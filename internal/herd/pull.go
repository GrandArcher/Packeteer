package herd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// overlap is how far before the last response a later pull starts, so a
// record stored just after that response is still fetched. Duplicates are
// ignored by (member, id).
const overlap = 5 * time.Minute

// PullerOptions wires the pull client.
type PullerOptions struct {
	Cfg   *config.Herd
	Node  *Node
	Store plugin.HerdStore
	// Origins are the origin ASNs to ask a query-only peer about.
	Origins func() []uint32
	Now     func() time.Time
	Log     *slog.Logger
	Trips   *Trips
	Event   func(string)
	// Active, when set, gates pulling: a standby HA node pulls nothing.
	Active func() bool
	// Jitter returns a number in [0, 1). Nil uses math/rand.
	Jitter func() float64
}

// PeerStatus is the state of one static peer for the status API.
type PeerStatus struct {
	URL         string    `json:"url"`
	KeyID       string    `json:"key_id"`
	ASN         uint32    `json:"asn,omitempty"`
	Country     string    `json:"country,omitempty"`
	Granularity string    `json:"granularity,omitempty"`
	Discovery   string    `json:"discovery,omitempty"`
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures"`
	RetryAt     time.Time `json:"retry_at,omitzero"`
	Pulled      uint64    `json:"records_pulled"`
	Rejected    uint64    `json:"records_rejected"`
}

type peer struct {
	url    string
	id     string
	pub    ed25519.PublicKey
	client *http.Client

	mu     sync.Mutex
	st     PeerStatus
	since  map[uint32]time.Time
	resume map[uint32]resume
	cursor int
}

// resume is where an unfinished sweep of one origin continues: the page
// cursor, and when the sweep's first page was generated. The cursor is a
// position in the store order for an unchanged from, so since stays put
// until the sweep completes.
type resume struct {
	cursor  string
	started time.Time
}

// Puller fetches the records of the static peers, in turn, within hard
// budgets: concurrent pulls, requests per interval (overall and per
// peer), bytes per response, records per response, per pull and in total
// per peer, and the pulled-data disk budget. A peer that fails or answers
// 429 backs off exponentially with jitter.
type Puller struct {
	o     PullerOptions
	lim   config.HerdLimits
	peers []*peer
	guard *guard

	offset atomic.Int64
}

// PinnedKeys returns the pinned public keys of the configured peers by key
// id.
func PinnedKeys(c *config.Herd) (map[string]ed25519.PublicKey, error) {
	keys := map[string]ed25519.PublicKey{}
	for _, p := range c.Peers {
		k, err := config.ParseHerdKey(p.Key)
		if err != nil {
			return nil, fmt.Errorf("herd peer %s: %w", p.URL, err)
		}
		keys[KeyID(k)] = k
	}
	return keys, nil
}

// NewPuller returns a Puller for the peers in o.Cfg.
func NewPuller(o PullerOptions) (*Puller, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Jitter == nil {
		o.Jitter = mrand.Float64
	}
	p := &Puller{o: o, lim: o.Cfg.Limits, guard: newGuard(o.Log, o.Event)}
	for _, cp := range o.Cfg.Peers {
		raw, err := config.ParseHerdKey(cp.Key)
		if err != nil {
			return nil, fmt.Errorf("herd peer %s: %w", cp.URL, err)
		}
		pub := ed25519.PublicKey(raw)
		id := KeyID(pub)
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{o.Node.cert},
				// The server's key is pinned, not chained to an issuer.
				InsecureSkipVerify:    true,
				VerifyPeerCertificate: pinned(map[string]ed25519.PublicKey{id: pub}),
			},
			// No proxy from the environment: peers are reached directly.
			MaxIdleConnsPerHost:   1,
			MaxConnsPerHost:       1,
			TLSHandshakeTimeout:   p.lim.PullTimeout,
			ResponseHeaderTimeout: p.lim.PullTimeout,
			IdleConnTimeout:       p.lim.IdleTimeout,
		}
		p.peers = append(p.peers, &peer{
			url: cp.URL, id: id, pub: pub, since: map[uint32]time.Time{}, resume: map[uint32]resume{},
			client: &http.Client{
				Transport:     tr,
				Timeout:       p.lim.PullTimeout,
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			},
			st: PeerStatus{URL: cp.URL, KeyID: id},
		})
	}
	return p, nil
}

// Peers returns the state of every peer, in config order.
func (p *Puller) Peers() []PeerStatus {
	out := make([]PeerStatus, len(p.peers))
	for i, pe := range p.peers {
		pe.mu.Lock()
		out[i] = pe.st
		pe.mu.Unlock()
	}
	return out
}

// Restarts is how many times the pull loop restarted after a panic.
func (p *Puller) Restarts() uint64 { return p.guard.restarts.Load() }

// Run pulls every PullInterval until ctx ends.
func (p *Puller) Run(ctx context.Context) {
	p.guard.run(ctx, "puller", func(ctx context.Context) {
		t := time.NewTicker(p.lim.PullInterval)
		defer t.Stop()
		for {
			if p.o.Active == nil || p.o.Active() {
				p.Round(ctx)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
}

// Close releases idle connections.
func (p *Puller) Close() {
	for _, pe := range p.peers {
		pe.client.CloseIdleConnections()
	}
}

// Round pulls each peer that is not backing off, at most MaxPulls at a
// time and PullRequests requests in all. The starting peer rotates each
// round, so a budget that runs out does not always starve the same peers.
func (p *Puller) Round(ctx context.Context) {
	if len(p.peers) == 0 {
		return
	}
	var budget atomic.Int64
	budget.Store(int64(p.lim.PullRequests))
	jobs := make(chan *peer)
	var wg sync.WaitGroup
	for range min(p.lim.MaxPulls, len(p.peers)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pe := range jobs {
				p.pullPeer(ctx, pe, &budget)
			}
		}()
	}
	start := int(p.offset.Add(1)-1) % len(p.peers)
	now := p.o.Now()
	for i := range p.peers {
		pe := p.peers[(start+i)%len(p.peers)]
		pe.mu.Lock()
		wait := now.Before(pe.st.RetryAt)
		pe.mu.Unlock()
		if wait {
			continue
		}
		select {
		case jobs <- pe:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
}

type retryError struct{ after time.Duration }

func (e retryError) Error() string { return "peer answered 429 (rate limited)" }

// pullPeer runs one peer's pull and records the outcome.
func (p *Puller) pullPeer(ctx context.Context, pe *peer, budget *atomic.Int64) {
	err := p.pull(ctx, pe, budget)
	pe.mu.Lock()
	defer pe.mu.Unlock()
	now := p.o.Now()
	if err == nil {
		pe.st.LastOK, pe.st.LastError, pe.st.Failures, pe.st.RetryAt = now, "", 0, time.Time{}
		return
	}
	if errors.Is(err, errBudget) || ctx.Err() != nil {
		return
	}
	pe.st.Failures++
	pe.st.LastError = err.Error()
	d := p.lim.BackoffMax
	if pe.st.Failures < 20 {
		d = min(d, 5*time.Second<<(pe.st.Failures-1))
	}
	d = time.Duration(float64(d) * (0.5 + 0.5*p.o.Jitter()))
	var re retryError
	if errors.As(err, &re) {
		d = max(d, min(re.after, p.lim.BackoffMax))
	}
	pe.st.RetryAt = now.Add(d)
	p.o.Log.Warn("herd pull failed", "peer", pe.url, "err", err, "retry_in", d.Round(time.Second))
}

var errBudget = errors.New("pull budget used")

func (p *Puller) pull(ctx context.Context, pe *peer, budget *atomic.Int64) error {
	left := p.lim.PeerRequests
	take := func() error {
		if left <= 0 {
			p.o.Trips.Add("peer_requests", pe.id)
			return errBudget
		}
		if budget.Add(-1) < 0 {
			p.o.Trips.Add("pull_requests", pe.id)
			return errBudget
		}
		left--
		return nil
	}
	if err := take(); err != nil {
		return err
	}
	st, err := p.fetchStatus(ctx, pe)
	if err != nil {
		return err
	}
	pe.mu.Lock()
	pe.st.ASN, pe.st.Country, pe.st.Granularity, pe.st.Discovery = st.ASN, st.Vantage, st.Granularity, st.Discovery
	pe.mu.Unlock()
	pulled := 0
	for _, a := range p.targets(pe, st) {
		n, err := p.pullQuery(ctx, pe, a, take, p.lim.PeerRecordsPerPull-pulled)
		pulled += n
		if err != nil {
			return err
		}
		if pulled >= p.lim.PeerRecordsPerPull {
			p.o.Trips.Add("peer_records_per_pull", pe.id)
			break
		}
	}
	return nil
}

// targets are the origin ASNs to query this pull. A listing peer is
// paged once, with no filter (0). A query-only peer is asked about the
// origins this node recorded, a rotating slice of them each pull.
func (p *Puller) targets(pe *peer, st Status) []uint32 {
	if st.Discovery == config.HerdListing {
		return []uint32{0}
	}
	var origins []uint32
	if p.o.Origins != nil {
		origins = p.o.Origins()
	}
	if len(origins) == 0 {
		return nil
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	n := min(len(origins), p.lim.PeerRequests-1)
	out := make([]uint32, 0, n)
	for i := range n {
		out = append(out, origins[(pe.cursor+i)%len(origins)])
	}
	pe.cursor = (pe.cursor + n) % len(origins)
	keep := map[uint32]bool{}
	for _, a := range origins {
		keep[a] = true
	}
	for a := range pe.since {
		if !keep[a] && a != 0 {
			delete(pe.since, a)
		}
	}
	for a := range pe.resume {
		if !keep[a] && a != 0 {
			delete(pe.resume, a)
		}
	}
	return out
}

func (p *Puller) fetchStatus(ctx context.Context, pe *peer) (Status, error) {
	var st Status
	raw, err := p.get(ctx, pe, PathStatus)
	if err != nil {
		return st, err
	}
	if err := verifyDocument(pe.pub, raw); err != nil {
		p.o.Trips.Add("bad_signature", pe.id)
		return st, fmt.Errorf("status: %w", err)
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, fmt.Errorf("status: %w", err)
	}
	switch {
	case st.Schema != Schema:
		return st, fmt.Errorf("status schema %q", st.Schema)
	case st.Member != pe.id:
		return st, errors.New("status is signed for another member")
	case st.RetentionDays < config.MinHerdRetentionDays || st.RetentionDays > config.MaxHerdRetentionDays:
		return st, fmt.Errorf("status retention_days %d", st.RetentionDays)
	case st.Granularity != config.HerdOriginASN && st.Granularity != config.HerdRoute:
		return st, fmt.Errorf("status granularity %q", st.Granularity)
	case st.Discovery != config.HerdQueryOnly && st.Discovery != config.HerdListing:
		return st, fmt.Errorf("status discovery %q", st.Discovery)
	}
	return st, nil
}

// get fetches one document, reading at most PullBytes of the body.
func (p *Puller) get(ctx context.Context, pe *peer, pathAndQuery string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pe.url+pathAndQuery, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := pe.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusTooManyRequests {
		secs, _ := strconv.Atoi(res.Header.Get("Retry-After"))
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return nil, retryError{after: time.Duration(secs) * time.Second}
	}
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("%s: %s", pathAndQuery, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, int64(p.lim.PullBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > p.lim.PullBytes {
		p.o.Trips.Add("pull_bytes", pe.id)
		return nil, fmt.Errorf("response larger than pull_bytes %d", p.lim.PullBytes)
	}
	return body, nil
}

func nonce() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pullQuery pages through one query (origin 0: no filter) and stores what
// validates. It returns how many records were stored. A sweep cut short by
// a budget continues on the next pull: from the page cursor, or, when a
// record budget cut a page, from just after the last record kept. since
// moves forward only when a sweep completes, to the time its first page was
// generated, so records stored while it ran are fetched next time.
func (p *Puller) pullQuery(ctx context.Context, pe *peer, origin uint32, take func() error, room int) (int, error) {
	pe.mu.Lock()
	since, rs := pe.since[origin], pe.resume[origin]
	pe.mu.Unlock()
	q := Query{OriginASN: origin, Limit: p.lim.PullRecords, Cursor: rs.cursor}
	if !since.IsZero() {
		q.From = since.UTC().Format(time.RFC3339Nano)
	}
	stored := 0
	complete := false
	var err error
	for {
		if err = take(); err != nil {
			break
		}
		q.Nonce = nonce()
		var raw []byte
		if raw, err = p.get(ctx, pe, PathRecords+"?"+q.Values()); err != nil {
			break
		}
		var env Envelope
		if env, err = p.openEnvelope(pe, raw, q); err != nil {
			break
		}
		var n, done int
		n, done, err = p.keep(ctx, pe, env, room-stored)
		stored += n
		if err != nil {
			break
		}
		if rs.started.IsZero() {
			rs.started = env.GeneratedAt
		}
		if done < len(env.Records) {
			if done > 0 {
				q.Cursor = recordCursor(env.Records[done-1])
			}
			break
		}
		if env.NextCursor == "" {
			complete = true
			break
		}
		q.Cursor = env.NextCursor
		if stored >= room {
			break
		}
	}
	pe.mu.Lock()
	if complete {
		pe.since[origin] = rs.started.Add(-overlap)
		delete(pe.resume, origin)
	} else if q.Cursor != "" {
		pe.resume[origin] = resume{cursor: q.Cursor, started: rs.started}
	}
	pe.mu.Unlock()
	return stored, err
}

// openEnvelope checks a records response: the size and record count
// caps, the signature, the member, the schema, and that it answers the
// query that was sent (the nonce makes a replayed response fail here).
func (p *Puller) openEnvelope(pe *peer, raw []byte, sent Query) (Envelope, error) {
	var env Envelope
	if err := verifyDocument(pe.pub, raw); err != nil {
		p.o.Trips.Add("bad_signature", pe.id)
		return env, fmt.Errorf("records: %w", err)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return env, fmt.Errorf("records: %w", err)
	}
	switch {
	case env.Schema != Schema:
		return env, fmt.Errorf("records schema %q", env.Schema)
	case env.Member != pe.id:
		return env, errors.New("records are signed for another member")
	case env.Granularity != config.HerdOriginASN && env.Granularity != config.HerdRoute:
		return env, fmt.Errorf("records granularity %q", env.Granularity)
	case len(env.Records) > p.lim.PullRecords:
		p.o.Trips.Add("pull_records", pe.id)
		return env, fmt.Errorf("response holds %d records, over pull_records %d", len(env.Records), p.lim.PullRecords)
	}
	echo := env.Query
	if !fromPlausible(echo.From, sent.From, env) {
		p.o.Trips.Add("replayed_response", pe.id)
		return env, errors.New("response answers another time window than the one asked for")
	}
	if echo.Nonce != sent.Nonce || echo.OriginASN != sent.OriginASN || echo.Cursor != sent.Cursor || echo.Prefix != sent.Prefix || echo.Match != sent.Match || echo.To != sent.To ||
		echo.ProviderASN != sent.ProviderASN || echo.Limit < 1 || echo.Limit > sent.Limit {
		p.o.Trips.Add("replayed_response", pe.id)
		return env, errors.New("response does not answer the query that was sent")
	}
	return env, nil
}

// fromPlausible bounds the echoed from. The server clips from to its
// retention, so it may differ from the one sent, but never lie before it,
// nor after the later of it and the retention floor at generated_at.
func fromPlausible(echoed, sent string, env Envelope) bool {
	got, err := time.Parse(time.RFC3339Nano, echoed)
	if err != nil {
		return false
	}
	latest := env.GeneratedAt.Add(-time.Duration(env.RetentionDays) * 24 * time.Hour)
	if s, err := time.Parse(time.RFC3339Nano, sent); err == nil {
		if got.Before(s) {
			return false
		}
		if s.After(latest) {
			latest = s
		}
	}
	return !got.After(latest.Add(time.Second))
}

// pulledBody is what a pulled record is stored as: the record as received
// and where it came from.
type pulledBody struct {
	Record      Record    `json:"record"`
	FetchedAt   time.Time `json:"fetched_at"`
	GeneratedAt time.Time `json:"generated_at"`
}

// recordCursor is the server's cursor for the position just after rec, a
// record it served from its own rows.
func recordCursor(rec Record) string {
	r := plugin.HerdRecord{ID: rec.ID, ProviderASN: rec.ProviderASN, Time: rec.Time}
	if rec.Prefix != "" {
		r.Prefix = netip.MustParsePrefix(rec.Prefix)
	}
	return cursorOf(&r)
}

// keep validates the records of env and stores up to room of them. A
// record is trusted only as an age relative to the envelope's generated_at,
// converted to the local clock, so clock skew cannot make old data look
// fresh; one dated after generated_at is dropped. It returns how many rows
// were new and how many leading records of env were dealt with: fewer than
// all when a record budget cut the page, so the caller can fetch the rest
// again instead of skipping them.
func (p *Puller) keep(ctx context.Context, pe *peer, env Envelope, room int) (int, int, error) {
	now := p.o.Now()
	floor := now.Add(-time.Duration(p.o.Cfg.RetentionDays) * 24 * time.Hour)
	var rows []plugin.HerdRecord
	// at is the index in env.Records of each row; bad, of each rejected record.
	var at, bad []int
	for i := range env.Records {
		rec := env.Records[i]
		if rec.Validate(env.Granularity) != nil || rec.Time.After(env.GeneratedAt) {
			bad = append(bad, i)
			continue
		}
		local := now.Add(-env.GeneratedAt.Sub(rec.Time))
		if local.Before(floor) {
			continue
		}
		body, _ := json.Marshal(pulledBody{Record: rec, FetchedAt: now, GeneratedAt: env.GeneratedAt})
		hr := plugin.HerdRecord{
			Member: pe.id, ID: rec.ID, Granularity: rec.Granularity, OriginASN: rec.OriginASN,
			ProviderASN: rec.ProviderASN, Time: local.UTC().Truncate(time.Millisecond), Body: body,
		}
		if rec.Prefix != "" {
			hr.Prefix = netip.MustParsePrefix(rec.Prefix)
		}
		rows = append(rows, hr)
		at = append(at, i)
	}
	stats, err := p.o.Store.HerdStats(ctx)
	if err != nil {
		return 0, 0, err
	}
	keepN := min(len(rows), max(room, 0))
	if left := p.lim.PeerRecordsTotal - stats.PerMember[pe.id]; keepN > left {
		p.o.Trips.Add("peer_records_total", pe.id)
		keepN = max(left, 0)
	}
	done := len(env.Records)
	if keepN < len(rows) {
		// Resume just after the last row kept. A rejected record between it
		// and the cut is fetched again, so it is counted only then.
		done = 0
		if keepN > 0 {
			done = at[keepN-1] + 1
		}
		rows = rows[:keepN]
	}
	rejected := 0
	for _, i := range bad {
		if i < done {
			rejected++
		}
	}
	pe.mu.Lock()
	pe.st.Rejected += uint64(rejected)
	pe.mu.Unlock()
	if len(rows) == 0 {
		return 0, done, nil
	}
	n, err := p.o.Store.PutHerdRecords(ctx, rows)
	if err != nil {
		return 0, 0, err
	}
	// The oldest pulled rows go first when the pulled-data budget is hit.
	if dropped, err := p.o.Store.TrimHerd(ctx, true, p.lim.PulledBytes); err != nil {
		return n, done, err
	} else if dropped > 0 {
		p.o.Trips.Add("pulled_bytes", "")
	}
	pe.mu.Lock()
	pe.st.Pulled += uint64(n)
	pe.mu.Unlock()
	return n, done, nil
}
