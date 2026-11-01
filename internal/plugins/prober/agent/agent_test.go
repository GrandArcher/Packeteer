package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentclient "github.com/GrandArcher/Packeteer/internal/agent"
	"github.com/GrandArcher/Packeteer/internal/agentwire"
	"github.com/GrandArcher/Packeteer/internal/agentwire/pkitest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeProber is the measurement side of a test agent: it records what it
// was asked and answers every packet.
type fakeProber struct {
	plugin.Base
	rtt   time.Duration
	block chan struct{} // when set, Probe waits for ctx or this channel
	in    chan struct{} // gets one value when Probe starts, if set

	mu   sync.Mutex
	reqs []plugin.ProbeRequest
}

func (f *fakeProber) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	if f.in != nil {
		f.in <- struct{}{}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return plugin.ProbeResult{}, ctx.Err()
		}
	}
	res := plugin.ProbeResult{Sent: req.Count}
	for range req.Count {
		res.RTTs = append(res.RTTs, f.rtt)
	}
	return res, nil
}

func (f *fakeProber) requests() []plugin.ProbeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]plugin.ProbeRequest(nil), f.reqs...)
}

type lab struct {
	t    *testing.T
	ca   *pkitest.CA
	hub  *Prober
	url  string
	crl  string
	logs *bytes.Buffer
}

// newLab starts a controller side that allows the named agents.
func newLab(t *testing.T, maxPPS int, names ...string) *lab {
	t.Helper()
	ca := pkitest.New(t)
	srv := ca.Issue(t, "controller")
	crl := filepath.Join(ca.Dir, "agents.crl")
	ca.WriteCRL(t, crl, 1)
	var agents strings.Builder
	for _, n := range names {
		fmt.Fprintf(&agents, "    - name: %s\n      max_pps: %d\n", n, maxPPS)
	}
	cfg, err := plugin.ConfigFromYAML(fmt.Sprintf(`
listen: 127.0.0.1:0
cert_file: %s
key_file: %s
ca_file: %s
crl_file: %s
poll_wait: 200ms
max_age: 600ms
agents:
%s`, srv.CertFile, srv.KeyFile, ca.CAFile, crl, agents.String()))
	if err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	pl, err := New(cfg, plugin.Env{Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := pl.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	hub := pl.(*Prober)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hub.Stop(ctx)
	})
	return &lab{t: t, ca: ca, hub: hub, url: "https://" + hub.Addr().String(), crl: crl, logs: logs}
}

// startAgent runs an agent client until the returned stop is called.
func (l *lab) startAgent(name, site string, p plugin.Prober, providers map[string]string) (stop func()) {
	l.t.Helper()
	return l.startAgentWith(l.ca.Issue(l.t, name), site, p, providers)
}

func (l *lab) startAgentWith(leaf pkitest.Leaf, site string, p plugin.Prober, providers map[string]string) (stop func()) {
	l.t.Helper()
	cfg := agentclient.Config{ControllerURL: l.url, ServerName: "controller", CertFile: leaf.CertFile, KeyFile: leaf.KeyFile,
		CAFile: l.ca.CAFile, Site: site}
	for n, src := range providers {
		cfg.Providers = append(cfg.Providers, agentclient.Provider{Name: n, SourceIP: src})
	}
	a, err := agentclient.New(cfg, p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		l.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
		}
	}
	l.t.Cleanup(stop)
	return stop
}

func req(provider, site string) plugin.ProbeRequest {
	return plugin.ProbeRequest{Provider: provider, Site: site, Target: netip.MustParseAddr("198.51.100.7"), Count: 3, Timeout: 100 * time.Millisecond}
}

func probe(t *testing.T, h *Prober, r plugin.ProbeRequest) (plugin.ProbeResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.Probe(ctx, r)
}

// probeWhenUp retries until an agent has registered, then returns the result.
func probeWhenUp(t *testing.T, h *Prober, r plugin.ProbeRequest) plugin.ProbeResult {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := probe(t, h, r)
		if err == nil {
			return res
		}
		if !errors.Is(err, plugin.ErrSourceUnavailable) || time.Now().After(deadline) {
			t.Fatalf("probe: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestProbesGoToTheSiteAndAreAttributed(t *testing.T) {
	l := newLab(t, 0, "agent-a", "agent-b")
	pa, pb := &fakeProber{rtt: 10 * time.Millisecond}, &fakeProber{rtt: 30 * time.Millisecond}
	l.startAgent("agent-a", "site-a", pa, map[string]string{"carrier-a": "192.0.2.11"})
	l.startAgent("agent-b", "site-b", pb, map[string]string{"carrier-b": "192.0.2.12"})

	ra := probeWhenUp(t, l.hub, req("carrier-a", "site-a"))
	rb := probeWhenUp(t, l.hub, req("carrier-b", "site-b"))
	if ra.Site != "site-a" || ra.Agent != "agent-a" || rb.Site != "site-b" || rb.Agent != "agent-b" {
		t.Fatalf("attribution: %+v %+v", ra, rb)
	}
	if ra.Sent != 3 || len(ra.RTTs) != 3 || ra.RTTs[0] != 10*time.Millisecond || rb.RTTs[0] != 30*time.Millisecond {
		t.Fatalf("results: %+v %+v", ra, rb)
	}
	if got := pa.requests(); len(got) != 1 || got[0].Source != netip.MustParseAddr("192.0.2.11") || got[0].Provider != "carrier-a" {
		t.Fatalf("agent-a asked %+v, want one probe from its own declared source", got)
	}
	if got := pb.requests(); len(got) != 1 || got[0].Source != netip.MustParseAddr("192.0.2.12") {
		t.Fatalf("agent-b asked %+v", got)
	}
	// A provider only the other site declares is not served by this one.
	if _, err := probe(t, l.hub, req("carrier-b", "site-a")); !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("carrier-b at site-a: %v, want ErrSourceUnavailable", err)
	}
}

func TestProbesSpreadAcrossAgentsOfASite(t *testing.T) {
	l := newLab(t, 0, "agent-a", "agent-b")
	pa, pb := &fakeProber{}, &fakeProber{}
	l.startAgent("agent-a", "site-a", pa, map[string]string{"carrier-a": "192.0.2.11"})
	l.startAgent("agent-b", "site-a", pb, map[string]string{"carrier-a": "192.0.2.21"})
	waitFor(t, "both agents online", func() bool {
		l.hub.mu.Lock()
		defer l.hub.mu.Unlock()
		return l.hub.agents["agent-a"].up && l.hub.agents["agent-b"].up
	})
	for range 20 {
		probeWhenUp(t, l.hub, req("carrier-a", "site-a"))
	}
	a, b := len(pa.requests()), len(pb.requests())
	if a+b != 20 || a < 9 || b < 9 {
		t.Fatalf("agent-a ran %d, agent-b ran %d of 20; want an even split", a, b)
	}
	// Each agent used its own source address for the same provider.
	if pa.requests()[0].Source == pb.requests()[0].Source {
		t.Fatal("both agents probed from the same source")
	}
}

func TestKilledAgentFailsItsProviderClosedAndRecovers(t *testing.T) {
	l := newLab(t, 0, "agent-a", "agent-b")
	prov := map[string]string{"carrier-a": "192.0.2.11"}
	stop := l.startAgent("agent-a", "site-a", &fakeProber{}, prov)
	l.startAgent("agent-b", "site-b", &fakeProber{}, map[string]string{"carrier-b": "192.0.2.12"})
	probeWhenUp(t, l.hub, req("carrier-a", "site-a"))
	probeWhenUp(t, l.hub, req("carrier-b", "site-b"))

	stop()
	waitFor(t, "agent-a unusable", func() bool {
		_, err := probe(t, l.hub, req("carrier-a", "site-a"))
		return errors.Is(err, plugin.ErrSourceUnavailable)
	})
	if _, err := probe(t, l.hub, req("carrier-b", "site-b")); err != nil {
		t.Fatalf("the other site must keep working: %v", err)
	}

	l.startAgent("agent-a", "site-a", &fakeProber{}, prov)
	if r := probeWhenUp(t, l.hub, req("carrier-a", "site-a")); r.Agent != "agent-a" {
		t.Fatalf("after restart: %+v", r)
	}
}

func TestProbeInFlightFailsWhenItsAgentDies(t *testing.T) {
	l := newLab(t, 0, "agent-a")
	p := &fakeProber{block: make(chan struct{}), in: make(chan struct{}, 1)}
	stop := l.startAgent("agent-a", "site-a", p, map[string]string{"carrier-a": "192.0.2.11"})
	waitFor(t, "agent online", func() bool {
		l.hub.mu.Lock()
		defer l.hub.mu.Unlock()
		return l.hub.agents["agent-a"].up
	})
	errc := make(chan error, 1)
	go func() {
		_, err := probe(t, l.hub, req("carrier-a", "site-a"))
		errc <- err
	}()
	<-p.in
	stop()
	select {
	case err := <-errc:
		if err == nil || errors.Is(err, plugin.ErrSourceUnavailable) {
			t.Fatalf("err = %v, want a plain error for the lost agent", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the probe kept waiting on a dead agent")
	}
}

func TestRevokedCertificateIsRefusedAtStart(t *testing.T) {
	l := newLab(t, 0, "agent-ok", "agent-bad")
	bad := l.ca.Issue(t, "agent-bad")
	l.ca.WriteCRL(t, l.crl, 2, bad)
	waitFor(t, "CRL loaded", func() bool { return l.hub.revoked(rawIssuer(t, bad), bad.Serial.Text(16)) })

	prov := map[string]string{"carrier-a": "192.0.2.11"}
	pOK, pBad := &fakeProber{}, &fakeProber{}
	l.startAgent("agent-ok", "site-a", pOK, prov)
	l.startAgentWith(bad, "site-a", pBad, prov)
	for range 10 {
		if r := probeWhenUp(t, l.hub, req("carrier-a", "site-a")); r.Agent != "agent-ok" {
			t.Fatalf("a revoked agent served a probe: %+v", r)
		}
	}
	if n := len(pBad.requests()); n != 0 {
		t.Fatalf("revoked agent ran %d probes", n)
	}
	if !strings.Contains(l.logs.String(), "certificate revoked") {
		t.Fatalf("no refusal logged: %s", l.logs.String())
	}
}

func TestRevokingARunningAgentStopsUsingIt(t *testing.T) {
	l := newLab(t, 0, "agent-a")
	leaf := l.ca.Issue(t, "agent-a")
	l.startAgentWith(leaf, "site-a", &fakeProber{}, map[string]string{"carrier-a": "192.0.2.11"})
	probeWhenUp(t, l.hub, req("carrier-a", "site-a"))
	l.ca.WriteCRL(t, l.crl, 2, leaf)
	waitFor(t, "agent-a unusable", func() bool {
		_, err := probe(t, l.hub, req("carrier-a", "site-a"))
		return errors.Is(err, plugin.ErrSourceUnavailable)
	})
}

// rawIssuer is the issuer of a leaf, in the form the CRL check keys on.
func rawIssuer(t *testing.T, l pkitest.Leaf) string {
	t.Helper()
	data, err := os.ReadFile(l.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return string(c.RawIssuer)
}

// postAs posts body to the controller with leaf's certificate and returns
// the status.
func postAs(t *testing.T, l *lab, leaf pkitest.Leaf, path string, body []byte) int {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(leaf.CertFile, leaf.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(l.ca.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "controller"}}}
	resp, err := c.Post(l.url+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestUnlistedAndForeignCertificatesAreRefused(t *testing.T) {
	l := newLab(t, 0, "agent-ok")
	prov := map[string]string{"carrier-a": "192.0.2.11"}
	pStranger, pForeign := &fakeProber{}, &fakeProber{}
	l.startAgent("stranger", "site-a", pStranger, prov) // valid certificate, not in agents
	foreign := pkitest.New(t)
	l.startAgentWith(foreign.Issue(t, "agent-ok"), "site-a", pForeign, prov) // right name, wrong CA
	l.startAgent("agent-ok", "site-a", &fakeProber{}, prov)
	for range 5 {
		if r := probeWhenUp(t, l.hub, req("carrier-a", "site-a")); r.Agent != "agent-ok" {
			t.Fatalf("served by %q", r.Agent)
		}
	}
	if len(pStranger.requests())+len(pForeign.requests()) != 0 {
		t.Fatal("a refused agent received work")
	}
}

func TestRateLimitIsPerAgent(t *testing.T) {
	l := newLab(t, 10, "agent-a", "agent-b")
	pa, pb := &fakeProber{}, &fakeProber{}
	l.startAgent("agent-a", "site-a", pa, map[string]string{"carrier-a": "192.0.2.11"})
	l.startAgent("agent-b", "site-a", pb, map[string]string{"carrier-a": "192.0.2.21"})
	waitFor(t, "both agents online", func() bool {
		l.hub.mu.Lock()
		defer l.hub.mu.Unlock()
		return l.hub.agents["agent-a"].up && l.hub.agents["agent-b"].up
	})
	big := req("carrier-a", "site-a")
	big.Count = 50
	// 10 pps with the minimum burst of 100 packets: each agent takes two
	// 50-packet probes at once, and the fifth has to wait 5s.
	for range 4 {
		probeWhenUp(t, l.hub, big)
	}
	if len(pa.requests()) != 2 || len(pb.requests()) != 2 {
		t.Fatalf("agent-a ran %d, agent-b ran %d, want 2 each", len(pa.requests()), len(pb.requests()))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := l.hub.Probe(ctx, big)
	if err == nil || errors.Is(err, plugin.ErrSourceUnavailable) || !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("err = %v, want a rate-limit error that does not fail the provider closed", err)
	}
	if len(pa.requests())+len(pb.requests()) != 4 {
		t.Fatal("a probe over the limit reached an agent")
	}
}

func TestAnotherAgentsAnswerIsIgnored(t *testing.T) {
	l := newLab(t, 0, "agent-a", "agent-b")
	pa := &fakeProber{block: make(chan struct{}), in: make(chan struct{}, 1)}
	l.startAgent("agent-a", "site-a", pa, map[string]string{"carrier-a": "192.0.2.11"})
	l.startAgent("agent-b", "site-b", &fakeProber{}, map[string]string{"carrier-b": "192.0.2.12"})
	waitFor(t, "both online", func() bool {
		l.hub.mu.Lock()
		defer l.hub.mu.Unlock()
		return l.hub.agents["agent-a"].up && l.hub.agents["agent-b"].up
	})
	errc := make(chan error, 1)
	go func() {
		_, err := probe(t, l.hub, req("carrier-a", "site-a"))
		errc <- err
	}()
	<-pa.in
	l.hub.mu.Lock()
	var id uint64
	for k := range l.hub.agents["agent-a"].inflight {
		id = k
	}
	l.hub.mu.Unlock()
	if id == 0 {
		t.Fatal("no task in flight")
	}
	// agent-b answers agent-a's task id with its own certificate.
	leaf := l.ca.Issue(t, "agent-b")
	body, _ := json.Marshal(agentwire.ResultsRequest{Results: []agentwire.Result{{ID: id, Sent: 3, RTTsNS: []int64{1000000, 1000000, 1000000}}}})
	resp := postAs(t, l, leaf, agentwire.ResultsPath, body)
	if resp != http.StatusNoContent {
		t.Fatalf("status %d", resp)
	}
	select {
	case err := <-errc:
		t.Fatalf("the probe finished on a forged answer: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	close(pa.block)
	if err := <-errc; err != nil {
		t.Fatalf("the real answer: %v", err)
	}
}

func TestProbeRejectsRequestsTheAgentsCannotRun(t *testing.T) {
	l := newLab(t, 0, "agent-a")
	for name, r := range map[string]plugin.ProbeRequest{
		"no site":      {Provider: "p", Target: netip.MustParseAddr("198.51.100.7"), Count: 3, Timeout: time.Second},
		"count":        {Provider: "p", Site: "s", Count: agentwire.MaxCount + 1, Timeout: time.Second},
		"zero timeout": {Provider: "p", Site: "s", Count: 1},
	} {
		if _, err := probe(t, l.hub, r); err == nil || errors.Is(err, plugin.ErrSourceUnavailable) {
			t.Errorf("%s: err = %v, want a plain error", name, err)
		}
	}
}

func TestConvertChecksTheAgentsAnswer(t *testing.T) {
	task := &task{agent: "agent-a", site: "site-a", wire: agentwire.Task{ID: 1, Count: 3, TimeoutMS: 100}}
	good := agentwire.Result{ID: 1, Sent: 3, RTTsNS: []int64{1e6, 2e6}}
	o := convert(task, good)
	if o.err != nil || o.res.Sent != 3 || len(o.res.RTTs) != 2 || o.res.Site != "site-a" || o.res.Agent != "agent-a" {
		t.Fatalf("good answer: %+v", o)
	}
	for name, r := range map[string]agentwire.Result{
		"more sent than asked":   {ID: 1, Sent: 4},
		"zero sent":              {ID: 1},
		"more replies than sent": {ID: 1, Sent: 1, RTTsNS: []int64{1e6, 1e6}},
		"rtt over the timeout":   {ID: 1, Sent: 3, RTTsNS: []int64{2e8}},
		"negative rtt":           {ID: 1, Sent: 3, RTTsNS: []int64{-5}},
		"agent error":            {ID: 1, Error: "boom"},
	} {
		if o := convert(task, r); o.err == nil || errors.Is(o.err, plugin.ErrSourceUnavailable) {
			t.Errorf("%s: err = %v, want a plain error", name, o.err)
		}
	}
	// An agent that cannot bind its declared source fails the provider closed.
	o = convert(task, agentwire.Result{ID: 1, Error: "no such address", SourceUnavailable: true})
	if !errors.Is(o.err, plugin.ErrSourceUnavailable) {
		t.Fatalf("source unavailable: %v", o.err)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	ca := pkitest.New(t)
	srv := ca.Issue(t, "controller")
	other := pkitest.New(t)
	badCRL := filepath.Join(ca.Dir, "bad.crl")
	other.WriteCRL(t, badCRL, 1)
	base := fmt.Sprintf("listen: 127.0.0.1:0\ncert_file: %s\nkey_file: %s\nca_file: %s\nagents:\n  - name: agent-a\n", srv.CertFile, srv.KeyFile, ca.CAFile)
	if _, err := New(mustCfg(t, base), plugin.Env{}); err != nil {
		t.Fatalf("base config: %v", err)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"no agents":     {strings.Replace(base, "agents:\n  - name: agent-a\n", "", 1), "agents"},
		"duplicate":     {base + "  - name: agent-a\n", "duplicate"},
		"bad name":      {strings.Replace(base, "agent-a", "bad name", 1), "name"},
		"max_pps":       {base + "    max_pps: 0\n  - name: b\n    max_pps: 1000000\n", "max_pps"},
		"listen":        {strings.Replace(base, "127.0.0.1:0", "nowhere", 1), "listen"},
		"poll_wait":     {base + "poll_wait: 1ms\n", "poll_wait"},
		"max_age":       {base + "poll_wait: 1s\nmax_age: 1s\n", "max_age"},
		"no tls":        {strings.Replace(base, "ca_file: "+ca.CAFile, "", 1), "mutual TLS"},
		"foreign crl":   {base + "crl_file: " + badCRL + "\n", "not signed by a CA"},
		"missing crl":   {base + "crl_file: /nonexistent.crl\n", "crl_file"},
		"unknown field": {base + "bogus: 1\n", "bogus"},
	} {
		if _, err := New(mustCfg(t, tc.yaml), plugin.Env{}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func mustCfg(t *testing.T, y string) plugin.Config {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPollRejectsBadFree(t *testing.T) {
	l := newLab(t, 0, "agent-a")
	leaf := l.ca.Issue(t, "agent-a")
	for _, free := range []int{-1, 0, agentwire.MaxTasksPerPoll + 1} {
		body, _ := json.Marshal(agentwire.PollRequest{Site: "site-a", Providers: []string{"carrier-a"}, Free: free})
		if got := postAs(t, l, leaf, agentwire.PollPath, body); got != http.StatusBadRequest {
			t.Errorf("free %d: status %d, want 400", free, got)
		}
	}
}
