package herd

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// puller builds a Puller for m that pulls from other.
func (m *member) puller(other *member, origins ...uint32) *Puller {
	m.t.Helper()
	peerOf(m.cfg, other)
	p, err := NewPuller(PullerOptions{
		Cfg: m.cfg, Node: m.node, Store: m.store, Origins: func() []uint32 { return origins },
		Now: m.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: m.trips,
		Jitter: func() float64 { return 1 },
	})
	if err != nil {
		m.t.Fatal(err)
	}
	m.t.Cleanup(p.Close)
	return p
}

func pulledRows(t *testing.T, m *member, peer *Node) []plugin.HerdRecord {
	t.Helper()
	rows, err := m.store.HerdRecords(context.Background(), plugin.HerdQuery{Member: peer.ID(), Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestPullBetweenTwoMembers(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, func(h *config.Herd) { h.Vantage.Country = "DE" })
	a.serve(b.node)
	a.seedN(5, 64510)
	p := b.puller(a, 64510)

	p.Round(context.Background())

	rows := pulledRows(t, b, a.node)
	if len(rows) != 5 {
		t.Fatalf("pulled %d rows, want 5; peers %+v", len(rows), p.Peers())
	}
	var pb pulledBody
	if err := json.Unmarshal(rows[0].Body, &pb); err != nil {
		t.Fatal(err)
	}
	if pb.Record.Vantage != "US" || pb.GeneratedAt.IsZero() || pb.FetchedAt != t0 {
		t.Errorf("provenance = %+v", pb)
	}
	// Times are kept as ages against generated_at, on the local clock.
	b.setClock(t0.Add(time.Hour))
	st := p.Peers()[0]
	if st.ASN != 64501 || st.Country != "US" || st.Granularity != "origin_asn" || st.Pulled != 5 || st.LastOK.IsZero() || st.Failures != 0 {
		t.Errorf("peer status = %+v", st)
	}
	// What is pulled is never served on: b serves only its own rows.
	b.serve(a.node)
	code, _, body := get(t, client(a.node, b), b.url()+PathRecords+"?origin_asn=64510")
	if code != 200 || len(envelope(t, body).Records) != 0 {
		t.Errorf("b re-served pulled data: %d %s", code, body)
	}
	// A second pull stores nothing new: duplicates are ignored.
	p.Round(context.Background())
	if n := len(pulledRows(t, b, a.node)); n != 5 {
		t.Errorf("rows after a repeat pull = %d", n)
	}
}

func TestPullShiftsTimesByAge(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	a.serve(b.node)
	// a's clock is a day ahead of b's; the record is two minutes old on a.
	a.setClock(t0.Add(24 * time.Hour))
	a.seed(a.mkRecord("x1", 64510, 64501, "198.51.100.0/24", a.clock().Add(-2*time.Minute), 10, 11), route("198.51.100.0/24", 64501, 64510))
	p := b.puller(a, 64510)
	p.Round(context.Background())
	rows := pulledRows(t, b, a.node)
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	if want := t0.Add(-2 * time.Minute); !rows[0].Time.Equal(want) {
		t.Errorf("stored time %v, want %v (the age on the peer's clock applied to the local one)", rows[0].Time, want)
	}
}

func TestRetentionBoundsPulledData(t *testing.T) {
	a := newMember(t, 64501, func(h *config.Herd) { h.RetentionDays = 365 })
	b := newMember(t, 64502, func(h *config.Herd) { h.RetentionDays = 30 })
	a.serve(b.node)
	a.seed(a.mkRecord("old", 64510, 64501, "198.51.100.0/24", t0.Add(-40*24*time.Hour), 10), route("198.51.100.0/24", 64501, 64510))
	a.seed(a.mkRecord("new", 64510, 64501, "198.51.100.0/24", t0.Add(-time.Hour), 10), route("198.51.100.0/24", 64501, 64510))
	b.puller(a, 64510).Round(context.Background())
	rows := pulledRows(t, b, a.node)
	if len(rows) != 1 || rows[0].ID != "new" {
		t.Errorf("rows = %+v, want only the record inside b's 30 days", rows)
	}
}

func TestListingPeerIsPagedAndQueryOnlyPeerIsAskedByOrigin(t *testing.T) {
	a := newMember(t, 64501, func(h *config.Herd) { h.Share.Discovery = config.HerdListing; h.Limits.PageRecords = 4 })
	b := newMember(t, 64502, nil)
	a.serve(b.node)
	a.seedN(10, 64510)
	p := b.puller(a)
	p.Round(context.Background())
	if n := len(pulledRows(t, b, a.node)); n != 10 {
		t.Errorf("listing peer: pulled %d of 10 over several pages", n)
	}
	// 10 records at 4 per page, plus the status request.
	if got := len(a.auditLog()); got != 3 {
		t.Errorf("pages served = %d, want 3", got)
	}

	q := newMember(t, 64503, nil)
	c := newMember(t, 64504, nil)
	q.serve(c.node)
	q.seedN(3, 64510)
	q.seed(q.mkRecord("other", 64511, 64501, "198.51.100.0/24", t0, 10), route("198.51.100.0/24", 64501, 64511))
	c.puller(q, 64510).Round(context.Background())
	rows := pulledRows(t, c, q.node)
	if len(rows) != 3 {
		t.Errorf("query-only peer asked about origin 64510: %d rows, want 3", len(rows))
	}
	for _, r := range rows {
		if r.OriginASN != 64510 {
			t.Errorf("row for origin %d came back", r.OriginASN)
		}
	}
	// With no origins of its own to ask about, nothing but the status
	// document is requested.
	d := newMember(t, 64505, nil)
	before := len(q.auditLog())
	d.puller(q).Round(context.Background())
	if len(q.auditLog()) != before {
		t.Error("a node with no recorded origins queried a query-only peer")
	}
}

// fakePeer is a peer with its own key whose responses a test controls.
type fakePeer struct {
	node *Node
	ln   net.Listener
	reqs atomic.Int64

	mu    sync.Mutex
	serve func(w http.ResponseWriter, r *http.Request)
}

func newFakePeer(t *testing.T, client *Node) *fakePeer {
	t.Helper()
	f := &fakePeer{node: testNode(t)}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{f.node.cert},
		ClientAuth: tls.RequireAnyClientCert, VerifyPeerCertificate: pinned(map[string]ed25519.PublicKey{client.ID(): client.pub}),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.reqs.Add(1)
		f.mu.Lock()
		fn := f.serve
		f.mu.Unlock()
		fn(w, r)
	}), ErrorLog: slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil).WithAttrs(nil), slog.LevelDebug)}
	go srv.Serve(ln)
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakePeer) handle(fn func(w http.ResponseWriter, r *http.Request)) {
	f.mu.Lock()
	f.serve = fn
	f.mu.Unlock()
}

func (f *fakePeer) pin(c *config.Herd) {
	c.Peers = []config.HerdPeer{{URL: "https://" + f.ln.Addr().String(), Key: f.node.PublicKey()}}
}

// status writes a valid signed status document from the peer.
func (f *fakePeer) status(w http.ResponseWriter, discovery string) {
	st := Status{Schema: Schema, Member: f.node.ID(), ASN: 64599, GeneratedAt: t0, RetentionDays: 90,
		Granularity: "origin_asn", Classes: []string{"measurements"}, Discovery: discovery, Vantage: "NL"}
	st.Signature, _ = f.node.sign(st)
	b, _ := json.Marshal(st)
	_, _ = w.Write(b)
}

// envelopeFor answers q with records, signed by the peer.
func (f *fakePeer) envelopeFor(r *http.Request, recs []Record) Envelope {
	q, _ := ParseQuery(r.URL.RawQuery)
	if q.From == "" {
		q.From = t0.Add(-90 * 24 * time.Hour).Format(time.RFC3339Nano)
	}
	e := Envelope{Schema: Schema, Member: f.node.ID(), ASN: 64599, GeneratedAt: t0, RetentionDays: 90,
		Granularity: "origin_asn", Query: q, Records: recs}
	return e
}

func (f *fakePeer) sign(e Envelope) []byte {
	e.Signature, _ = f.node.sign(e)
	b, _ := json.Marshal(e)
	return b
}

func goodRecord(id string) Record {
	r := Record{Schema: Schema, ID: id, Granularity: "origin_asn", Routes: 1, OriginASN: 64510, ProviderASN: 64501,
		Vantage: "NL", Method: "icmp", Time: t0.Add(-time.Minute), Sent: 4,
		Samples: []Sample{{0, 10}, {0, 12}, {0, 11}}}
	r.setSummary()
	return r
}

func newPullFixture(t *testing.T, edit func(*config.Herd)) (*member, *fakePeer, *Puller) {
	t.Helper()
	m := newMember(t, 64502, edit)
	f := newFakePeer(t, m.node)
	f.pin(m.cfg)
	p, err := NewPuller(PullerOptions{
		Cfg: m.cfg, Node: m.node, Store: m.store, Origins: func() []uint32 { return []uint32{64510} },
		Now: m.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: m.trips,
		Jitter: func() float64 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return m, f, p
}

func TestPullRefusesTamperedReplayedAndWronglySignedResponses(t *testing.T) {
	cases := map[string]func(f *fakePeer, w http.ResponseWriter, r *http.Request){
		"tampered": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			b := f.sign(f.envelopeFor(r, []Record{goodRecord("a")}))
			_, _ = w.Write([]byte(strings.Replace(string(b), `"rtt_ms":10`, `"rtt_ms":99`, 1)))
		},
		"wrong key": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			other := testNode(t)
			e := f.envelopeFor(r, []Record{goodRecord("a")})
			e.Signature, _ = other.sign(e)
			b, _ := json.Marshal(e)
			_, _ = w.Write(b)
		},
		"replayed": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			// A genuine signed answer to a different query (another nonce).
			e := f.envelopeFor(r, []Record{goodRecord("a")})
			e.Query.Nonce = "an-earlier-nonce"
			_, _ = w.Write(f.sign(e))
		},
		"answer to another origin": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			e := f.envelopeFor(r, []Record{goodRecord("a")})
			e.Query.OriginASN = 64999
			_, _ = w.Write(f.sign(e))
		},
		"answer for a later window": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			e := f.envelopeFor(r, []Record{goodRecord("a")})
			e.Query.From = t0.Add(-time.Minute).Format(time.RFC3339Nano)
			_, _ = w.Write(f.sign(e))
		},
		"signed for another member": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			e := f.envelopeFor(r, []Record{goodRecord("a")})
			e.Member = strings.Repeat("0", 64)
			_, _ = w.Write(f.sign(e))
		},
		"unknown schema": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			e := f.envelopeFor(r, []Record{goodRecord("a")})
			e.Schema = "herd/v2"
			_, _ = w.Write(f.sign(e))
		},
		"unsigned": func(f *fakePeer, w http.ResponseWriter, r *http.Request) {
			b, _ := json.Marshal(f.envelopeFor(r, []Record{goodRecord("a")}))
			_, _ = w.Write(b)
		},
	}
	for name, respond := range cases {
		t.Run(name, func(t *testing.T) {
			m, f, p := newPullFixture(t, nil)
			f.handle(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == PathStatus {
					f.status(w, "query_only")
					return
				}
				respond(f, w, r)
			})
			p.Round(context.Background())
			if n := len(pulledRows(t, m, f.node)); n != 0 {
				t.Errorf("%d records stored from a %s response", n, name)
			}
			if st := p.Peers()[0]; st.Failures != 1 || st.LastError == "" {
				t.Errorf("peer status = %+v, want one failure", st)
			}
		})
	}
}

func TestPullDropsInvalidRecordsAndKeepsTheRest(t *testing.T) {
	m, f, p := newPullFixture(t, nil)
	bad := goodRecord("bad-loss")
	l := 50.0
	bad.LossPct = &l
	future := goodRecord("future")
	future.Time = t0.Add(time.Hour)
	noSamples := goodRecord("more-replies-than-sent")
	noSamples.Sent = 1
	order := goodRecord("out-of-order")
	order.Samples = []Sample{{0, 10}, {2, 11}}
	order.Sent = 4
	order.setSummary()
	oldSchema := goodRecord("old-schema")
	oldSchema.Schema = "herd/v0"
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f.status(w, "query_only")
			return
		}
		_, _ = w.Write(f.sign(f.envelopeFor(r, []Record{bad, future, noSamples, order, oldSchema, goodRecord("good")})))
	})
	p.Round(context.Background())
	rows := pulledRows(t, m, f.node)
	if len(rows) != 1 || rows[0].ID != "good" {
		t.Fatalf("stored %v, want only the valid record", ids(rows))
	}
	if st := p.Peers()[0]; st.Rejected != 5 {
		t.Errorf("rejected = %d, want 5", st.Rejected)
	}
}

func ids(rs []plugin.HerdRecord) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func TestOversizedAndEndlessResponsesAreCutAtTheCap(t *testing.T) {
	m, f, p := newPullFixture(t, func(h *config.Herd) { h.Limits.PullBytes = 4096; h.Limits.PullRecords = 3 })
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f.status(w, "query_only")
			return
		}
		// An endless body: far more than pull_bytes, never ending.
		w.Header().Set("Content-Type", "application/json")
		chunk := []byte(strings.Repeat("x", 1024))
		for range 100000 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	start := time.Now()
	p.Round(context.Background())
	if time.Since(start) > 5*time.Second {
		t.Error("the endless response was read to the end")
	}
	if tripCount(m.trips, "pull_bytes") != 1 {
		t.Errorf("trips = %+v", m.trips.Snapshot())
	}
	if len(pulledRows(t, m, f.node)) != 0 || p.Peers()[0].Failures != 1 {
		t.Errorf("peer = %+v", p.Peers()[0])
	}

	// Too many records in one response is a failure too.
	m2, f2, p2 := newPullFixture(t, func(h *config.Herd) { h.Limits.PullRecords = 3 })
	f2.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f2.status(w, "query_only")
			return
		}
		var recs []Record
		for i := range 4 {
			recs = append(recs, goodRecord(fmt.Sprint("r", i)))
		}
		_, _ = w.Write(f2.sign(f2.envelopeFor(r, recs)))
	})
	p2.Round(context.Background())
	if tripCount(m2.trips, "pull_records") != 1 || len(pulledRows(t, m2, f2.node)) != 0 {
		t.Errorf("trips = %+v rows %d", m2.trips.Snapshot(), len(pulledRows(t, m2, f2.node)))
	}
}

func TestBackoffGrowsAfterFailuresAnd429(t *testing.T) {
	m, f, p := newPullFixture(t, func(h *config.Herd) { h.Limits.BackoffMax = time.Hour })
	var mode atomic.Value
	mode.Store("fail")
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if mode.Load() == "429" {
			w.Header().Set("Retry-After", "600")
			http.Error(w, "slow down", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	ctx := context.Background()
	var gaps []time.Duration
	for range 3 {
		p.Round(ctx)
		st := p.Peers()[0]
		gaps = append(gaps, st.RetryAt.Sub(m.clock()))
		m.setClock(st.RetryAt)
	}
	if !(gaps[0] == 5*time.Second && gaps[1] == 10*time.Second && gaps[2] == 20*time.Second) {
		t.Errorf("backoff after 1, 2, 3 failures = %v, want 5s, 10s, 20s", gaps)
	}
	// While backing off the peer is not contacted at all.
	n := f.reqs.Load()
	m.setClock(m.clock().Add(-time.Second))
	p.Round(ctx)
	if f.reqs.Load() != n {
		t.Error("a peer in backoff was contacted")
	}
	m.setClock(p.Peers()[0].RetryAt)
	mode.Store("429")
	p.Round(ctx)
	st := p.Peers()[0]
	if got := st.RetryAt.Sub(m.clock()); got != 10*time.Minute || st.Failures != 4 {
		t.Errorf("after a 429 with Retry-After 600: wait %v failures %d, want 10m and 4", got, st.Failures)
	}
}

func TestPullBudgetsHold(t *testing.T) {
	// Three peers, a budget of 4 requests in all: a status request and
	// a query is two requests per peer, so two peers are pulled.
	m := newMember(t, 64502, func(h *config.Herd) {
		h.Limits.PullRequests = 4
		h.Limits.MaxPulls = 1
	})
	var peers []*fakePeer
	m.cfg.Peers = nil
	for range 3 {
		f := newFakePeer(t, m.node)
		f.handle(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == PathStatus {
				f.status(w, "query_only")
				return
			}
			_, _ = w.Write(f.sign(f.envelopeFor(r, nil)))
		})
		peers = append(peers, f)
		m.cfg.Peers = append(m.cfg.Peers, config.HerdPeer{URL: "https://" + f.ln.Addr().String(), Key: f.node.PublicKey()})
	}
	p, err := NewPuller(PullerOptions{Cfg: m.cfg, Node: m.node, Store: m.store, Origins: func() []uint32 { return []uint32{64510} },
		Now: m.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: m.trips})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.Round(context.Background())
	total := int64(0)
	for _, f := range peers {
		total += f.reqs.Load()
	}
	if total != 4 {
		t.Errorf("requests in one interval = %d, want the budget of 4", total)
	}
	if tripCount(m.trips, "pull_requests") == 0 {
		t.Errorf("trips = %+v", m.trips.Snapshot())
	}
	// The next round starts one peer later, so the third peer is reached.
	p.Round(context.Background())
	reached := 0
	for _, f := range peers {
		if f.reqs.Load() > 0 {
			reached++
		}
	}
	if reached != 3 {
		t.Errorf("peers reached after two rounds = %d, want all 3", reached)
	}
}

func TestPerPeerRequestBudgetAndConcurrency(t *testing.T) {
	m, f, p := newPullFixture(t, func(h *config.Herd) { h.Limits.PeerRequests = 2; h.Share.Discovery = config.HerdListing })
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f.status(w, "listing")
			return
		}
		e := f.envelopeFor(r, []Record{goodRecord(fmt.Sprint("r", f.reqs.Load()))})
		e.NextCursor = encodeCursor(cursorKey{ID: "next", TimeMS: 1})
		_, _ = w.Write(f.sign(e))
	})
	p.Round(context.Background())
	if f.reqs.Load() != 2 {
		t.Errorf("requests to one peer = %d, want its budget of 2", f.reqs.Load())
	}
	if tripCount(m.trips, "peer_requests") != 1 {
		t.Errorf("trips = %+v", m.trips.Snapshot())
	}

	// At most max_pulls peers are in flight at once.
	m2 := newMember(t, 64503, func(h *config.Herd) { h.Limits.MaxPulls = 2 })
	var cur, peak atomic.Int64
	m2.cfg.Peers = nil
	for range 5 {
		fp := newFakePeer(t, m2.node)
		fp.handle(func(w http.ResponseWriter, r *http.Request) {
			n := cur.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
			cur.Add(-1)
			http.Error(w, "no", http.StatusInternalServerError)
		})
		m2.cfg.Peers = append(m2.cfg.Peers, config.HerdPeer{URL: "https://" + fp.ln.Addr().String(), Key: fp.node.PublicKey()})
	}
	p2, _ := NewPuller(PullerOptions{Cfg: m2.cfg, Node: m2.node, Store: m2.store, Now: m2.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: m2.trips})
	t.Cleanup(p2.Close)
	p2.Round(context.Background())
	if peak.Load() != 2 {
		t.Errorf("peak concurrent pulls = %d, want max_pulls 2", peak.Load())
	}
}

func TestPerPeerRecordCaps(t *testing.T) {
	m, f, p := newPullFixture(t, func(h *config.Herd) { h.Limits.PeerRecordsTotal = 3; h.Limits.PeerRecordsPerPull = 2 })
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f.status(w, "query_only")
			return
		}
		var recs []Record
		for i := range 3 {
			recs = append(recs, goodRecord(fmt.Sprint("r", i)))
		}
		_, _ = w.Write(f.sign(f.envelopeFor(r, recs)))
	})
	p.Round(context.Background())
	if n := len(pulledRows(t, m, f.node)); n != 2 {
		t.Errorf("per-pull cap 2: stored %d", n)
	}
	// Later pulls bring distinct records until the peer's total cap.
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f.status(w, "query_only")
			return
		}
		var recs []Record
		for i := range 3 {
			recs = append(recs, goodRecord(fmt.Sprint("s", i)))
		}
		_, _ = w.Write(f.sign(f.envelopeFor(r, recs)))
	})
	p.Round(context.Background())
	if n := len(pulledRows(t, m, f.node)); n != 3 {
		t.Errorf("per-peer total cap 3: stored %d", n)
	}
	if tripCount(m.trips, "peer_records_total") == 0 || tripCount(m.trips, "peer_records_per_pull") == 0 {
		t.Errorf("trips = %+v", m.trips.Snapshot())
	}
}

func TestPulledDiskBudgetDropsOldestFirstAndLeavesOwnRecords(t *testing.T) {
	m, f, _ := newPullFixture(t, func(h *config.Herd) { h.Limits.PulledBytes = 1 << 20 })
	m.seedN(3, 64510)
	one := goodRecord("probe")
	body, _ := json.Marshal(pulledBody{Record: one})
	// Room for about six pulled rows.
	m.cfg.Limits.PulledBytes = int64(len(body)+400) * 6
	p, err := NewPuller(PullerOptions{Cfg: m.cfg, Node: m.node, Store: m.store, Origins: func() []uint32 { return []uint32{64510} },
		Now: m.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: m.trips})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	var wave atomic.Int64
	f.handle(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == PathStatus {
			f.status(w, "query_only")
			return
		}
		n := wave.Add(1)
		var recs []Record
		for i := range 5 {
			rec := goodRecord(fmt.Sprintf("w%d-%d", n, i))
			rec.Time = t0.Add(-time.Duration(100-int(n)*10-i) * time.Second)
			recs = append(recs, rec)
		}
		_, _ = w.Write(f.sign(f.envelopeFor(r, recs)))
	})
	for range 4 {
		p.Round(context.Background())
	}
	st, _ := m.store.HerdStats(context.Background())
	if st.PulledBytes > m.cfg.Limits.PulledBytes {
		t.Errorf("pulled bytes %d over the budget %d", st.PulledBytes, m.cfg.Limits.PulledBytes)
	}
	if st.LocalRecords != 3 {
		t.Errorf("own records = %d, a pulled-data flood must leave them alone", st.LocalRecords)
	}
	if tripCount(m.trips, "pulled_bytes") == 0 {
		t.Errorf("trips = %+v", m.trips.Snapshot())
	}
	rows := pulledRows(t, m, f.node)
	for _, r := range rows {
		if strings.HasPrefix(r.ID, "w1-") {
			t.Errorf("oldest wave survived the budget: %s", r.ID)
		}
	}
}

func TestFromPlausibleBoundsTheEchoedWindow(t *testing.T) {
	env := Envelope{GeneratedAt: t0, RetentionDays: 90}
	floor := t0.Add(-90 * 24 * time.Hour)
	f := func(tm time.Time) string { return tm.Format(time.RFC3339Nano) }
	sent := t0.Add(-time.Hour)
	for name, c := range map[string]struct {
		echoed, sent string
		want         bool
	}{
		"retention floor, none asked":      {f(floor), "", true},
		"as asked":                         {f(sent), f(sent), true},
		"clipped to a later floor":         {f(t0.Add(-30 * time.Minute)), f(floor), false},
		"before the one asked":             {f(sent.Add(-time.Hour)), f(sent), false},
		"after generated_at":               {f(t0.Add(time.Hour)), f(sent), false},
		"later than the floor, none asked": {f(t0.Add(-time.Hour)), "", false},
		"not a time":                       {"yesterday", "", false},
		"empty":                            {"", f(sent), false},
	} {
		if got := fromPlausible(c.echoed, c.sent, env); got != c.want {
			t.Errorf("%s: fromPlausible(%q, %q) = %v, want %v", name, c.echoed, c.sent, got, c.want)
		}
	}
}

// A peer holding more than one pull's worth is read to the end over
// several pulls: each pull continues where the budget cut the last one.
func TestPullContinuesABacklogLargerThanOnePull(t *testing.T) {
	a := newMember(t, 64501, func(h *config.Herd) { h.Share.Discovery = config.HerdListing })
	b := newMember(t, 64502, func(h *config.Herd) {
		h.Limits.PullRecords = 2
		h.Limits.PeerRequests = 4
	})
	a.serve(b.node)
	a.seedN(20, 64510)
	p := b.puller(a)

	var counts []int
	for range 5 {
		p.Round(context.Background())
		counts = append(counts, len(pulledRows(t, b, a.node)))
	}
	if want := []int{6, 12, 18, 20, 20}; !slices.Equal(counts, want) {
		t.Errorf("pulled rows after each pull = %v, want %v", counts, want)
	}

	// Once read to the end, only what is new is asked for.
	a.setClock(t0.Add(time.Minute))
	a.seed(a.mkRecord("late", 64510, 64501, "198.51.100.0/24", t0.Add(30*time.Second), 10), route("198.51.100.0/24", 64501, 64500, 64510))
	b.setClock(t0.Add(time.Minute))
	// The overlap re-reads the last five minutes, which is more than one pull.
	for range 3 {
		p.Round(context.Background())
	}
	if n := len(pulledRows(t, b, a.node)); n != 21 {
		t.Errorf("rows after a new record = %d, want 21", n)
	}
}
