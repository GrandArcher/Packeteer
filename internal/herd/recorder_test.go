package herd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeRIB struct {
	mu    sync.Mutex
	ready bool
	// paths holds the AS path learned through each provider for a prefix.
	paths map[netip.Prefix][]uint32
	// down is a provider with no learned paths.
	down string
	boom bool
}

func (f *fakeRIB) Ready() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ready
}
func (f *fakeRIB) Exact(p netip.Prefix) (rib.Route, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.boom {
		panic("rib exploded")
	}
	_, ok := f.paths[p]
	return rib.Route{}, ok
}
func (f *fakeRIB) ProviderPaths(p netip.Prefix, provider string) [][]uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if path, ok := f.paths[p]; ok && provider != f.down {
		return [][]uint32{path}
	}
	return nil
}

const secretProvider = "transit-secret-name"

// result is one probed round of prefix through secretProvider, listed by
// the named target sources, with replies of the given RTTs on one host.
func result(prefix string, sources []string, rtts ...time.Duration) probe.Result {
	return probe.Result{
		Provider: secretProvider, Prefix: netip.MustParsePrefix(prefix), Prober: "icmp-main",
		Target: netip.MustParseAddr("198.51.100.77"), Time: t0,
		Share: &probe.Share{Hosts: []probe.HostRaw{{Sent: len(rtts) + 1, RTTs: rtts}}, Sources: sources},
	}
}

type recFixture struct {
	rec   *Recorder
	store plugin.HerdStore
	rib   *fakeRIB
	srv   *Server
	cfg   *config.Herd
}

func newRecFixture(t *testing.T, edit func(*config.Herd), rules *Rules) *recFixture {
	t.Helper()
	cfg := testCfg(t, edit)
	store := testStore(t)
	node := testNode(t)
	if rules == nil {
		rules = defaultRules()
	}
	f := &recFixture{store: store, cfg: cfg, rib: &fakeRIB{ready: true, paths: map[netip.Prefix][]uint32{
		netip.MustParsePrefix("198.51.100.0/24"): {64501, 64502, 64510},
		netip.MustParsePrefix("203.0.113.0/24"):  {64501, 64503, 64510},
	}}}
	f.rec = NewRecorder(RecorderOptions{
		Cfg: cfg, Node: node, Store: store, RIB: f.rib, Rules: rules,
		Methods: map[string]string{"icmp-main": "icmp"}, FirstMethod: "icmp",
		SourceTypes: map[string]string{"main-static": "static", "main-flow": "flow"},
		Now:         func() time.Time { return t0 }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	f.srv = NewServer(ServerOptions{
		Cfg: cfg, ASN: 64496, Node: node, Store: store, RIB: f.rib, Rules: rules, Now: func() time.Time { return t0 },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: &Trips{},
	})
	return f
}

func (f *recFixture) record(t *testing.T, batch ...probe.Result) {
	t.Helper()
	f.rec.process(context.Background(), batch)
}

// served is the preview body for a query: the bytes a puller would get.
func (f *recFixture) served(t *testing.T, raw string) (Envelope, string) {
	t.Helper()
	code, body := f.srv.Preview(raw)
	if code != 200 {
		t.Fatalf("preview %q: %d %s", raw, code, body)
	}
	return envelope(t, body), string(body)
}

func ms(n ...int) []time.Duration {
	var out []time.Duration
	for _, v := range n {
		out = append(out, time.Duration(v)*time.Millisecond)
	}
	return out
}

func TestOriginLevelIsTheDefaultAndNamesNoPrefix(t *testing.T) {
	f := newRecFixture(t, func(c *config.Herd) { c.Share.Classes = []string{"measurements"} }, nil)
	f.record(t, result("198.51.100.0/24", []string{"main-static"}, ms(10, 12, 14)...))
	if f.cfg.Share.Granularity != config.HerdOriginASN {
		t.Fatalf("granularity = %q", f.cfg.Share.Granularity)
	}
	env, raw := f.served(t, "origin_asn=64510")
	if len(env.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(env.Records))
	}
	r := env.Records[0]
	if r.OriginASN != 64510 || r.Routes != 1 || r.ProviderASN != 64501 || r.Method != "icmp" || r.Sent != 4 || len(r.Samples) != 3 {
		t.Errorf("record = %+v", r)
	}
	if r.Prefix != "" || r.ASPath != nil || r.ASPaths != nil {
		t.Errorf("origin-level record without the paths class carries a prefix or path: %+v", r)
	}
	for _, leak := range []string{"198.51.100", "prefix", "as_path", secretProvider, "icmp-main", "main-static", "198.51.100.77"} {
		if strings.Contains(raw, leak) {
			t.Errorf("the response contains %q:\n%s", leak, raw)
		}
	}
	// A prefix query matches nothing at this level.
	if env, _ := f.served(t, "prefix=198.51.100.0/24"); len(env.Records) != 0 {
		t.Errorf("origin-level member answered a prefix query: %+v", env.Records)
	}
	if loss := *r.LossPct; loss != 25 {
		t.Errorf("loss = %v, want 25", loss)
	}
}

func TestRouteLevelNamesThePrefixAndPathsOnlyWithTheClass(t *testing.T) {
	for _, withPaths := range []bool{false, true} {
		f := newRecFixture(t, func(c *config.Herd) {
			c.Share.Granularity = config.HerdRoute
			c.Share.Classes = []string{"measurements"}
			if withPaths {
				c.Share.Classes = append(c.Share.Classes, "paths")
			}
		}, nil)
		f.record(t, result("198.51.100.0/24", []string{"main-static"}, ms(10, 12)...))
		env, raw := f.served(t, "prefix=198.51.100.0/24")
		if len(env.Records) != 1 || env.Records[0].Prefix != "198.51.100.0/24" {
			t.Fatalf("paths=%v: records = %+v", withPaths, env.Records)
		}
		got := env.Records[0].ASPath
		if withPaths {
			// Private-use ASNs would be stripped; documentation ASNs stay.
			if len(got) != 3 || got[0] != 64501 || got[2] != 64510 {
				t.Errorf("as_path = %v", got)
			}
		} else if got != nil || strings.Contains(raw, "as_path") {
			t.Errorf("as_path served without the paths class: %s", raw)
		}
		if strings.Contains(raw, secretProvider) || strings.Contains(raw, "198.51.100.77") {
			t.Errorf("provider name or probed host in the response: %s", raw)
		}
	}
}

func TestRecorderStoresNothingThatTheRulesRefuse(t *testing.T) {
	rules := &Rules{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/25")},
		ASNs:     map[uint32]bool{64502: true},
		Sources:  map[string]bool{"static": true},
	}
	f := newRecFixture(t, func(c *config.Herd) { c.Share.Granularity = config.HerdRoute }, rules)
	for p, path := range map[string][]uint32{
		"192.0.2.0/24":    {64501, 64510}, // not in the RIB view below
		"10.1.0.0/16":     {64501, 64510}, // private space
		"198.51.100.0/24": {64501, 64502, 64510},
		"203.0.113.0/24":  {64501, 64503, 64510},
	} {
		f.rib.paths[netip.MustParsePrefix(p)] = path
	}
	delete(f.rib.paths, netip.MustParsePrefix("192.0.2.0/24"))
	batch := []probe.Result{
		result("198.51.100.0/24", []string{"main-static"}, ms(10)...), // ASN 64502 in the path
		result("203.0.113.0/24", []string{"main-static"}, ms(10)...),  // covers an excluded prefix
		result("10.1.0.0/16", []string{"main-static"}, ms(10)...),
		result("192.0.2.0/24", []string{"main-static"}, ms(10)...),
	}
	f.record(t, batch...)
	if st, _ := f.store.HerdStats(context.Background()); st.LocalRecords != 0 {
		t.Fatalf("stored %d records, want none", st.LocalRecords)
	}

	// An allowed route from a source that is not opted in is not stored either.
	f.rib.paths[netip.MustParsePrefix("192.0.2.0/24")] = []uint32{64501, 64510}
	f.record(t, result("192.0.2.0/24", []string{"main-flow"}, ms(10)...))
	if st, _ := f.store.HerdStats(context.Background()); st.LocalRecords != 0 {
		t.Fatalf("a flow-only route was stored: %d records", st.LocalRecords)
	}
	f.record(t, result("192.0.2.0/24", []string{"main-flow", "main-static"}, ms(10)...))
	if st, _ := f.store.HerdStats(context.Background()); st.LocalRecords != 1 {
		t.Fatalf("a route listed by an opted-in source was not stored: %d records", st.LocalRecords)
	}
}

func TestRecorderSkipsWhatItCannotShare(t *testing.T) {
	f := newRecFixture(t, nil, nil)
	ind := result("198.51.100.0/24", []string{"main-static"}, ms(10)...)
	ind.Indirect = true
	sub := result("198.51.100.0/24", []string{"main-static"}, ms(10)...)
	sub.Subranges = []probe.SubrangeResult{{}}
	noShare := result("198.51.100.0/24", []string{"main-static"}, ms(10)...)
	noShare.Share = nil
	exec := result("198.51.100.0/24", []string{"main-static"}, ms(10)...)
	exec.Prober = "exec-thing"
	f.record(t, ind, sub, noShare, exec)
	f.rib.ready = false
	f.record(t, result("198.51.100.0/24", []string{"main-static"}, ms(10)...))
	if st, _ := f.store.HerdStats(context.Background()); st.LocalRecords != 0 {
		t.Fatalf("stored %d records, want none", st.LocalRecords)
	}
}

func TestFailedRoundIsARecordWithoutAMeasurement(t *testing.T) {
	f := newRecFixture(t, nil, nil)
	failed := result("198.51.100.0/24", []string{"main-static"})
	failed.Prober, failed.Err = "", "no reply"
	failed.Share.Hosts = nil
	f.record(t, failed)
	env, _ := f.served(t, "origin_asn=64510")
	if len(env.Records) != 1 || !env.Records[0].Failed || env.Records[0].Sent != 0 || env.Records[0].LossPct != nil {
		t.Fatalf("records = %+v", env.Records)
	}
	if err := env.Records[0].Validate(config.HerdOriginASN); err != nil {
		t.Errorf("a failed record does not validate: %v", err)
	}
}

func TestOriginRecordPoolsRoutesOfOneOriginAndValidates(t *testing.T) {
	f := newRecFixture(t, nil, nil)
	f.record(t,
		result("198.51.100.0/24", []string{"main-static"}, ms(10, 20)...),
		result("203.0.113.0/24", []string{"main-static"}, ms(30)...),
	)
	env, _ := f.served(t, "origin_asn=64510")
	if len(env.Records) != 1 {
		t.Fatalf("records = %d, want the two routes pooled into one", len(env.Records))
	}
	r := env.Records[0]
	if r.Routes != 2 || len(r.Samples) != 3 || r.Sent != 5 {
		t.Fatalf("pooled record = %+v", r)
	}
	if err := r.Validate(config.HerdOriginASN); err != nil {
		t.Errorf("recorded record does not validate: %v", err)
	}
	want := Summarize(5, r.Samples)
	if *r.RTTAvgMs != want.Avg || *r.RTTMinMs != 10 || *r.RTTMaxMs != 30 {
		t.Errorf("summary %v %v %v, want avg %v min 10 max 30", *r.RTTMinMs, *r.RTTAvgMs, *r.RTTMaxMs, want.Avg)
	}
}

func TestExcludeAppliesToDataStoredBeforeTheEntryWasAdded(t *testing.T) {
	f := newRecFixture(t, func(c *config.Herd) { c.Share.Granularity = config.HerdRoute }, nil)
	f.record(t, result("198.51.100.0/24", []string{"main-static"}, ms(10)...), result("203.0.113.0/24", []string{"main-static"}, ms(10)...))
	if env, _ := f.served(t, "origin_asn=64510"); len(env.Records) != 2 {
		t.Fatalf("records = %d, want 2", len(env.Records))
	}
	cases := []struct {
		name string
		edit func(*Rules)
		want string // the one prefix still served
	}{
		{"covering entry", func(r *Rules) { r.Prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.0.0/16")} }, "203.0.113.0/24"},
		{"equal entry", func(r *Rules) { r.Prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")} }, "203.0.113.0/24"},
		{"inside entry", func(r *Rules) { r.Prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.128/25")} }, "203.0.113.0/24"},
		{"origin asn", func(r *Rules) { r.ASNs[64510] = true }, ""},
		{"asn in the path", func(r *Rules) { r.ASNs[64502] = true }, "203.0.113.0/24"},
		{"source opt-out", func(r *Rules) { r.Sources = map[string]bool{"vip": true} }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rules := defaultRules()
			c.edit(rules)
			f.srv.o.Rules = rules
			env, raw := f.served(t, "origin_asn=64510")
			var got []string
			for _, r := range env.Records {
				got = append(got, r.Prefix)
			}
			if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || got[0] != c.want) {
				t.Errorf("served %v, want [%s]", got, c.want)
			}
			if c.want != "" && strings.Contains(raw, "198.51.100.0/24") {
				t.Errorf("an excluded prefix is in the response: %s", raw)
			}
		})
	}
}

func TestPooledRecordIsDroppedWholeWhenOneRouteIsExcluded(t *testing.T) {
	f := newRecFixture(t, nil, nil)
	f.record(t, result("198.51.100.0/24", []string{"main-static"}, ms(10)...), result("203.0.113.0/24", []string{"main-static"}, ms(10)...))
	rules := defaultRules()
	rules.Prefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	f.srv.o.Rules = rules
	if env, _ := f.served(t, "origin_asn=64510"); len(env.Records) != 0 {
		t.Fatalf("a pooled record with an excluded route was served: %+v", env.Records)
	}
}

func TestPreviewIsTheBytesAPullerReceives(t *testing.T) {
	srv := newMember(t, 64501, func(c *config.Herd) { c.Share.Granularity = config.HerdRoute })
	cli := testNode(t)
	srv.serve(cli)
	for i := range 5 {
		srv.seed(srv.mkRecord("r"+string(rune('a'+i)), 64510, 64501, "198.51.100.0/24", t0.Add(-time.Duration(i)*time.Minute), 10, 11),
			route("198.51.100.0/24", 64501, 64500, 64510))
	}
	srv.seed(srv.mkRecord("z", 64510, 64501, "198.51.100.0/25", t0, 10), route("198.51.100.0/25", 64501, 64500, 64510))
	c := client(cli, srv)
	for _, raw := range []string{
		"origin_asn=64510", "origin_asn=64510&limit=2", "prefix=198.51.100.0/24", "prefix=198.51.100.0/24&match=covered",
		"prefix=198.51.100.0/25&match=covering", "origin_asn=64510&provider_asn=64501", "origin_asn=64999",
		"origin_asn=64510&limit=2&cursor=garbage", "bogus=1", "origin_asn=0",
	} {
		pcode, pbody := srv.srv.Preview(raw + "&nonce=same")
		code, _, body := get(t, c, srv.url()+PathRecords+"?"+raw+"&nonce=same")
		if code != pcode || string(body) != string(pbody) {
			t.Errorf("%q: pull got %d %s\npreview was %d %s", raw, code, body, pcode, pbody)
		}
	}
	_, status := srv.srv.Status()
	code, _, body := get(t, c, srv.url()+PathStatus)
	var st Status
	if err := json.Unmarshal(body, &st); err != nil || code != 200 || !reflect.DeepEqual(st, status) {
		t.Errorf("status: pull %d %s, preview %+v", code, body, status)
	}
}

func TestOfferNeverBlocksAndCountsWhatItDrops(t *testing.T) {
	f := newRecFixture(t, func(c *config.Herd) { c.Limits.Queue = 2 }, nil)
	batch := []probe.Result{result("198.51.100.0/24", []string{"main-static"}, ms(10)...)}
	done := make(chan struct{})
	go func() {
		for range 1000 {
			f.rec.Offer(batch)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Offer blocked with nobody draining the queue")
	}
	if f.rec.Dropped() != 998 {
		t.Errorf("dropped = %d, want 998 (queue holds 2)", f.rec.Dropped())
	}
}

func TestRecorderSurvivesAPanicAndKeepsRecording(t *testing.T) {
	f := newRecFixture(t, nil, nil)
	f.rec.guard.backoff = 10 * time.Millisecond
	var mu sync.Mutex
	var events []string
	f.rec.guard.event = func(m string) { mu.Lock(); events = append(events, m); mu.Unlock() }
	f.rib.boom = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.rec.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	f.rec.Offer([]probe.Result{result("198.51.100.0/24", []string{"main-static"}, ms(10)...)})
	waitFor(t, func() bool { return f.rec.Restarts() == 1 })
	mu.Lock()
	if len(events) != 1 || !strings.Contains(events[0], "rib exploded") {
		t.Errorf("events = %v", events)
	}
	mu.Unlock()

	f.rib.boom = false
	f.rec.Offer([]probe.Result{result("198.51.100.0/24", []string{"main-static"}, ms(10)...)})
	waitFor(t, func() bool { return f.rec.Stored() == 1 })
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 400 {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

func TestRetentionDeletesOldRecordsAndTheLocalBudgetTrimsOldestFirst(t *testing.T) {
	f := newRecFixture(t, func(c *config.Herd) { c.RetentionDays = 30 }, nil)
	m := &member{t: t, cfg: f.cfg, store: f.store, rib: f.rib}
	rt := route("198.51.100.0/24", 64501, 64500, 64510)
	for i, age := range []time.Duration{40 * 24 * time.Hour, 31 * 24 * time.Hour, 29 * 24 * time.Hour, time.Hour} {
		m.seed(m.mkRecord("id"+string(rune('a'+i)), 64510, 64501, "198.51.100.0/24", t0.Add(-age), 10), rt)
	}
	f.rec.prune(context.Background())
	rows, _ := f.store.HerdRecords(context.Background(), plugin.HerdQuery{AnyMember: true, Limit: 10})
	if len(rows) != 2 {
		t.Fatalf("after retention %d rows remain, want the two inside 30 days", len(rows))
	}
	f.rec.o.Cfg.Limits.LocalBytes = int64(len(rows[1].Body)) + 1
	f.rec.prune(context.Background())
	left, _ := f.store.HerdRecords(context.Background(), plugin.HerdQuery{AnyMember: true, Limit: 10})
	if len(left) != 1 || left[0].ID != "idd" {
		t.Fatalf("after the budget trim: %+v, want only the newest", left)
	}
}

func TestOriginsAreRememberedAndBounded(t *testing.T) {
	f := newRecFixture(t, nil, nil)
	for i := range maxOrigins + 10 {
		f.rec.noteOrigin(uint32(1000+i), t0.Add(time.Duration(i)*time.Second))
	}
	got := f.rec.Origins()
	if len(got) != maxOrigins {
		t.Fatalf("origins = %d, want %d", len(got), maxOrigins)
	}
	if got[0] != 1010 {
		t.Errorf("oldest origin kept = %d, want 1010 (the 10 oldest are evicted)", got[0])
	}
}
