package agent

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/agentwire"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fileStamp identifies one version of the CRL file.
type fileStamp struct {
	mod  time.Time
	size int64
}

func loadCAs(path string) (*x509.CertPool, []*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	var cas []*x509.Certificate
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("ca_file %s: %w", path, err)
		}
		pool.AddCert(c)
		cas = append(cas, c)
	}
	if len(cas) == 0 {
		return nil, nil, fmt.Errorf("ca_file %s: no PEM certificates", path)
	}
	return pool, cas, nil
}

func revokedKey(issuer, serial string) string { return issuer + "/" + serial }

func (p *Prober) revoked(issuer, serial string) bool {
	m := p.crl.Load()
	return m != nil && (*m)[revokedKey(issuer, serial)]
}

func (p *Prober) crlChanged() bool {
	fi, err := os.Stat(p.cfg.CRLFile)
	if err != nil {
		return false
	}
	st := p.crlStat.Load()
	return st == nil || !st.mod.Equal(fi.ModTime()) || st.size != fi.Size()
}

// reloadCRL reads crl_file. Every list in it must be signed by a CA in
// ca_file; an unsigned or foreign list is refused so nobody can revoke
// agents with their own list. A list whose Number is lower than the one
// loaded for the same issuer is refused too, so an older list from the
// same CA cannot be put back to un-revoke an agent.
func (p *Prober) reloadCRL() error {
	fi, err := os.Stat(p.cfg.CRLFile)
	if err != nil {
		return fmt.Errorf("crl_file: %w", err)
	}
	data, err := os.ReadFile(p.cfg.CRLFile)
	if err != nil {
		return fmt.Errorf("crl_file: %w", err)
	}
	revoked := map[string]bool{}
	numbers := map[string]*big.Int{}
	var next time.Time
	lists := 0
	for {
		var blk *pem.Block
		blk, data = pem.Decode(data)
		if blk == nil {
			break
		}
		if blk.Type != "X509 CRL" {
			continue
		}
		rl, err := x509.ParseRevocationList(blk.Bytes)
		if err != nil {
			return fmt.Errorf("crl_file %s: %w", p.cfg.CRLFile, err)
		}
		if !slices.ContainsFunc(p.cas, func(ca *x509.Certificate) bool { return rl.CheckSignatureFrom(ca) == nil }) {
			return fmt.Errorf("crl_file %s: not signed by a CA in ca_file", p.cfg.CRLFile)
		}
		issuer := string(rl.RawIssuer)
		if old := p.crlNumbers[issuer]; old != nil && (rl.Number == nil || rl.Number.Cmp(old) < 0) {
			return fmt.Errorf("crl_file %s: CRL number %v is lower than the loaded %v; refusing a rollback to an older list", p.cfg.CRLFile, rl.Number, old)
		}
		if rl.Number != nil && (numbers[issuer] == nil || rl.Number.Cmp(numbers[issuer]) > 0) {
			numbers[issuer] = rl.Number
		}
		if !rl.NextUpdate.IsZero() && (next.IsZero() || rl.NextUpdate.Before(next)) {
			next = rl.NextUpdate
		}
		for _, e := range rl.RevokedCertificateEntries {
			revoked[revokedKey(string(rl.RawIssuer), e.SerialNumber.Text(16))] = true
		}
		lists++
	}
	if lists == 0 {
		return fmt.Errorf("crl_file %s: no PEM X509 CRL", p.cfg.CRLFile)
	}
	// A file that leaves a CA out must not forget that CA's number, or an
	// older list from it would be accepted on a later reload.
	for issuer, n := range p.crlNumbers {
		if numbers[issuer] == nil {
			numbers[issuer] = n
		}
	}
	p.crlNumbers, p.crlNext, p.crlWarned = numbers, next, false
	p.crl.Store(&revoked)
	p.crlStat.Store(&fileStamp{mod: fi.ModTime(), size: fi.Size()})
	return nil
}

// authenticate maps the caller's certificate to an allowed agent. TLS
// already checked the chain; this checks the name and the revocation list
// on every request, so a revoked agent is refused on its open connection.
func (p *Prober) authenticate(w http.ResponseWriter, r *http.Request) (*agentState, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return nil, false
	}
	leaf := r.TLS.PeerCertificates[0]
	names := append([]string{leaf.Subject.CommonName}, leaf.DNSNames...)
	issuer, serial := string(leaf.RawIssuer), leaf.SerialNumber.Text(16)
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, n := range names {
		a, ok := p.agents[n]
		if !ok {
			continue
		}
		if p.revoked(issuer, serial) {
			p.log.Warn("probe agent refused: certificate revoked", "agent", n, "serial", serial)
			http.Error(w, "certificate revoked", http.StatusForbidden)
			return nil, false
		}
		a.issuer, a.serial = issuer, serial
		return a, true
	}
	http.Error(w, "agent not allowed", http.StatusForbidden)
	return nil, false
}

// servePoll declares the agent, then answers with work or, after
// poll_wait, with nothing. The call is the agent's heartbeat.
func (p *Prober) servePoll(w http.ResponseWriter, r *http.Request) {
	a, ok := p.authenticate(w, r)
	if !ok {
		return
	}
	var req agentwire.PollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, agentwire.MaxBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := checkPoll(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Site != a.spec.Site {
		// A certificate is good for its configured site only: an agent
		// that claims another one would get that site's tasks and feed
		// its decisions with measurements taken elsewhere.
		p.log.Warn("probe agent refused: site mismatch", "agent", a.spec.Name, "site", req.Site, "configured_site", a.spec.Site)
		http.Error(w, fmt.Sprintf("agent %s is configured for site %s", a.spec.Name, a.spec.Site), http.StatusForbidden)
		return
	}
	p.mu.Lock()
	if !a.up {
		p.log.Info("probe agent online", "agent", a.spec.Name, "site", req.Site, "providers", req.Providers)
	}
	a.providers, a.up = map[string]bool{}, true
	for _, n := range req.Providers {
		a.providers[n] = true
	}
	a.lastSeen = p.now()
	p.mu.Unlock()

	timer := time.NewTimer(p.cfg.PollWait)
	defer timer.Stop()
	for {
		if tasks := p.take(a, req.Free); len(tasks) > 0 {
			p.respond(w, a, agentwire.PollResponse{Tasks: tasks})
			return
		}
		select {
		case <-a.wake:
		case <-timer.C:
			p.respond(w, a, agentwire.PollResponse{})
			return
		case <-r.Context().Done():
			// The agent hung up: stop using it now, not after max_age.
			p.mu.Lock()
			a.lastSeen = time.Time{}
			p.mu.Unlock()
			return
		case <-p.stop:
			return
		}
	}
}

func checkPoll(req agentwire.PollRequest) error {
	if req.Free < 1 || req.Free > agentwire.MaxTasksPerPoll {
		return fmt.Errorf("free %d must be between 1 and %d", req.Free, agentwire.MaxTasksPerPoll)
	}
	if !agentwire.NameRE.MatchString(req.Site) {
		return fmt.Errorf("site %q is not a valid name", req.Site)
	}
	if len(req.Providers) == 0 || len(req.Providers) > agentwire.MaxProviders {
		return fmt.Errorf("declare between 1 and %d providers", agentwire.MaxProviders)
	}
	for _, n := range req.Providers {
		if !agentwire.NameRE.MatchString(n) {
			return fmt.Errorf("provider %q is not a valid name", n)
		}
	}
	return nil
}

// take moves up to n queued tasks to in-flight and returns them.
func (p *Prober) take(a *agentState, n int) []agentwire.Task {
	p.mu.Lock()
	defer p.mu.Unlock()
	n = min(n, len(a.queue))
	out := make([]agentwire.Task, 0, n)
	for _, t := range a.queue[:n] {
		a.inflight[t.wire.ID] = t
		out = append(out, t.wire)
	}
	a.queue = a.queue[n:]
	return out
}

func (p *Prober) respond(w http.ResponseWriter, a *agentState, resp agentwire.PollResponse) {
	p.mu.Lock()
	a.lastSeen = p.now()
	p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// serveResults completes the agent's own in-flight tasks. An id the agent
// was not given, or one already dropped, is ignored.
func (p *Prober) serveResults(w http.ResponseWriter, r *http.Request) {
	a, ok := p.authenticate(w, r)
	if !ok {
		return
	}
	var req agentwire.ResultsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, agentwire.MaxBody)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	a.lastSeen = p.now()
	for _, res := range req.Results {
		t, ok := a.inflight[res.ID]
		if !ok {
			continue
		}
		delete(a.inflight, res.ID)
		t.done <- convert(t, res)
	}
	w.WriteHeader(http.StatusNoContent)
}

// convert checks an agent's answer against the task and turns it into a
// probe result tagged with the agent and its site. An agent cannot report
// more packets than it was asked to send.
func convert(t *task, res agentwire.Result) outcome {
	switch {
	case res.Error != "" && res.SourceUnavailable:
		return outcome{err: fmt.Errorf("%w: agent %s: %s", plugin.ErrSourceUnavailable, t.agent, res.Error)}
	case res.Error != "":
		return outcome{err: fmt.Errorf("agent %s: %s", t.agent, res.Error)}
	case res.Sent < 1 || res.Sent > t.wire.Count || len(res.RTTsNS) > res.Sent:
		return outcome{err: fmt.Errorf("agent %s: sent %d with %d replies for a task of %d packets", t.agent, res.Sent, len(res.RTTsNS), t.wire.Count)}
	}
	out := plugin.ProbeResult{Sent: res.Sent, Site: t.site, Agent: t.agent}
	limit := time.Duration(t.wire.TimeoutMS) * time.Millisecond
	for _, ns := range res.RTTsNS {
		if ns < 0 || time.Duration(ns) > limit {
			return outcome{err: fmt.Errorf("agent %s: RTT %dns outside 0..%s", t.agent, ns, limit)}
		}
		out.RTTs = append(out.RTTs, time.Duration(ns))
	}
	return outcome{res: out}
}
