package birdseye

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// rsASN is a documentation-range route server ASN; members use 64497 and up.
const rsASN = 64496

// t0 is a real clock reading: View judges staleness against time.Now.
var t0 = time.Now()

// fakeBirdseye serves the four allowlisted endpoints from mutable state and
// records every request it gets.
type fakeBirdseye struct {
	mu        sync.Mutex
	srv       *httptest.Server
	requests  []string
	protocols map[string]map[string]any
	counts    map[string]int
	tagged    map[string][][3]uint64 // one entry per route: its large communities
	fail      int                    // HTTP status for every request when non-zero
	bigLC     bool
}

func newFake(t *testing.T) *fakeBirdseye {
	t.Helper()
	f := &fakeBirdseye{
		protocols: map[string]map[string]any{},
		counts:    map[string]int{},
		tagged:    map[string][][3]uint64{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeBirdseye) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if f.fail != 0 {
		http.Error(w, "down", f.fail)
		return
	}
	api := map[string]any{"version": "0.1.0", "max_routes": 1000}
	var body any
	switch p := r.URL.Path; {
	case p == "/api/status":
		body = map[string]any{"api": api, "status": map[string]any{
			"version": "2.0.8", "router_id": "192.0.2.1", "last_reconfig": "2026-01-02T03:04:05+00:00",
			"message": "Daemon is up and running"}}
	case p == "/api/protocols/bgp":
		if len(f.protocols) == 0 {
			body = map[string]any{"api": api, "protocols": []any{}}
		} else {
			body = map[string]any{"api": api, "protocols": f.protocols}
		}
	case strings.HasPrefix(p, "/api/routes/count/protocol/"):
		name := strings.TrimPrefix(p, "/api/routes/count/protocol/")
		body = map[string]any{"api": api, "count": map[string]any{"routes": f.counts[name]}}
	case strings.HasPrefix(p, "/api/routes/lc-zwild/protocol/"):
		parts := strings.Split(strings.TrimPrefix(p, "/api/routes/lc-zwild/protocol/"), "/")
		routes := []any{}
		if len(parts) == 3 && parts[1] == fmt.Sprint(rsASN) && parts[2] == "1101" {
			for _, lc := range f.tagged[parts[0]] {
				routes = append(routes, map[string]any{"network": "198.51.100.0/24",
					"bgp": map[string]any{"large_communities": [][3]uint64{{64511, 1, 2}, lc}}})
			}
		}
		if f.bigLC {
			routes = append(routes, map[string]any{"pad": strings.Repeat("x", 4096)})
		}
		body = map[string]any{"api": api, "routes": routes}
	default:
		http.NotFound(w, r)
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeBirdseye) setSession(name string, asn uint32, addr, bgpState string, importLimit int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.protocols[name] = map[string]any{
		"protocol": name, "bird_protocol": "BGP", "state": "up", "connection": bgpState,
		"bgp_state": bgpState, "neighbor_address": addr, "neighbor_as": asn,
		"description": "Doc member " + name, "import_limit": importLimit,
	}
}

func (f *fakeBirdseye) get() (reqs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

type capture struct {
	mu     sync.Mutex
	events []plugin.Event
}

func (c *capture) sink(e plugin.Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *capture) kinds() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, e := range c.events {
		out = append(out, e.Kind+" "+e.Fields["session"])
	}
	return out
}

func (c *capture) reset() {
	c.mu.Lock()
	c.events = nil
	c.mu.Unlock()
}

func cfgNode(t *testing.T, v any) plugin.Config {
	t.Helper()
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		t.Fatal(err)
	}
	return plugin.NewConfig(&n)
}

func newWatch(t *testing.T, f *fakeBirdseye, extra map[string]any) (*Watch, *capture) {
	t.Helper()
	c := map[string]any{"servers": []map[string]any{{"name": "rs1", "url": f.srv.URL, "asn": rsASN}}}
	for k, v := range extra {
		c[k] = v
	}
	p, err := New(cfgNode(t, c), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	cap := &capture{}
	p.SetEventSink(cap.sink)
	return p.(*Watch), cap
}

func members() plugin.MemberView {
	return plugin.MemberView{Configured: true, Members: []plugin.IXPMember{{
		ASN: 64497, Name: "Doc Member One",
		Connections: []plugin.IXPConnection{{Addresses: []plugin.IXPAddress{
			{Family: "ipv4", Address: "192.0.2.10", RouteServer: true, MaxPrefix: 100},
		}}},
	}}}
}

func session(v plugin.RouteServerView, name string) plugin.RouteServerSession {
	for _, s := range v.Sessions {
		if s.Session == name {
			return s
		}
	}
	return plugin.RouteServerSession{}
}

func TestPollCountsReasonsAndAlerts(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_0001_as64497", 64497, "192.0.2.10", "Established", 5000)
	f.setSession("pb_0002_as64498", 64498, "192.0.2.11", "Active", 0)
	f.counts["pb_0001_as64497"] = 100
	// 60 routes tagged: 40 with reason 3, 20 with reasons 3 and 7.
	for i := 0; i < 40; i++ {
		f.tagged["pb_0001_as64497"] = append(f.tagged["pb_0001_as64497"], [3]uint64{rsASN, 1101, 3})
	}
	for i := 0; i < 20; i++ {
		f.tagged["pb_0001_as64497"] = append(f.tagged["pb_0001_as64497"], [3]uint64{rsASN, 1101, 7})
	}
	w, ev := newWatch(t, f, nil)
	w.SetMembers(members)
	w.round(context.Background(), t0)

	v := w.View()
	if !v.Configured || len(v.Servers) != 1 || !v.Servers[0].Up || v.Servers[0].Version != "2.0.8" ||
		v.Servers[0].RouterID != "192.0.2.1" || v.Servers[0].Sessions != 2 {
		t.Fatalf("servers %+v", v.Servers)
	}
	s := session(v, "pb_0001_as64497")
	if !s.Established || !s.Counted || s.Received != 100 || s.Filtered != 60 || s.Accepted != 40 || s.Name != "Doc Member One" || s.ASN != 64497 {
		t.Fatalf("session %+v", s)
	}
	if want := []plugin.RouteServerReason{{Reason: 3, Count: 40}, {Reason: 7, Count: 20}}; !slices.Equal(s.Reasons, want) {
		t.Fatalf("reasons %v", s.Reasons)
	}
	// The IX-F max_prefix (100) wins over Birdseye's import limit (5000).
	if s.MaxPrefix != 100 || s.UsedPct != 40 {
		t.Fatalf("max_prefix %d used %.1f", s.MaxPrefix, s.UsedPct)
	}
	d := session(v, "pb_0002_as64498")
	if d.Established || d.State != "Active" || !d.Counted || d.Received != 0 {
		t.Fatalf("down session %+v", d)
	}
	got := ev.kinds()
	slices.Sort(got)
	want := []string{"ixp.rs_filtered pb_0001_as64497", "ixp.rs_session_down pb_0002_as64498"}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v", got)
	}
	// A down session is not asked for counts.
	for _, r := range f.get() {
		if strings.Contains(r, "pb_0002_as64498") {
			t.Fatalf("requested %s", r)
		}
	}
}

func TestOnlyAllowlistedGETs(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_0001_as64497", 64497, "192.0.2.10", "Established", 0)
	f.counts["pb_0001_as64497"] = 3
	w, _ := newWatch(t, f, nil)
	w.round(context.Background(), t0)
	want := []string{
		"GET /api/status",
		"GET /api/protocols/bgp",
		"GET /api/routes/count/protocol/pb_0001_as64497",
		"GET /api/routes/lc-zwild/protocol/pb_0001_as64497/64496/1101",
	}
	if got := f.get(); !slices.Equal(got, want) {
		t.Fatalf("requests %v", got)
	}
}

func TestMaxPrefixAndTransitions(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 100)
	f.counts["pb_a"] = 95
	w, ev := newWatch(t, f, nil)
	now := t0
	w.round(context.Background(), now)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_max_prefix pb_a"}) {
		t.Fatalf("first round %v", got)
	}
	e := ev.events[0]
	if e.Severity != plugin.SeverityWarning || e.Fields["accepted"] != "95" || e.Fields["max_prefix"] != "100" || e.Fields["asn"] != "64497" {
		t.Fatalf("event %+v", e)
	}

	// Nothing changes: nothing is repeated.
	ev.reset()
	w.round(context.Background(), now.Add(time.Minute))
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("repeated %v", got)
	}

	// Back under the share, then the session drops, then it returns.
	f.counts["pb_a"] = 10
	w.round(context.Background(), now.Add(2*time.Minute))
	f.setSession("pb_a", 64497, "192.0.2.10", "Idle", 100)
	w.round(context.Background(), now.Add(3*time.Minute))
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 100)
	w.round(context.Background(), now.Add(4*time.Minute))
	want := []string{"ixp.rs_max_prefix_cleared pb_a", "ixp.rs_session_down pb_a", "ixp.rs_session_up pb_a"}
	if got := ev.kinds(); !slices.Equal(got, want) {
		t.Fatalf("events %v", got)
	}
	if ev.events[1].DedupKey() != ev.events[2].DedupKey() || !ev.events[2].Resolves() {
		t.Fatalf("down %q up %q", ev.events[1].DedupKey(), ev.events[2].DedupKey())
	}
}

func TestRemovedSessionClosesItsAlerts(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Active", 0)
	f.setSession("pb_b", 64498, "192.0.2.11", "Established", 10)
	f.counts["pb_b"] = 10
	w, ev := newWatch(t, f, nil)
	w.round(context.Background(), t0)
	ev.reset()
	f.mu.Lock()
	delete(f.protocols, "pb_a")
	delete(f.protocols, "pb_b")
	f.protocols["pb_c"] = map[string]any{"protocol": "pb_c", "bgp_state": "Established", "neighbor_as": 64499}
	f.mu.Unlock()
	w.round(context.Background(), t0.Add(time.Minute))
	got := ev.kinds()
	slices.Sort(got)
	want := []string{"ixp.rs_max_prefix_cleared pb_b", "ixp.rs_session_up pb_a"}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v", got)
	}
	if v := w.View(); len(v.Sessions) != 1 || v.Sessions[0].Session != "pb_c" {
		t.Fatalf("sessions %+v", v.Sessions)
	}
}

func TestServerFailureAndRecovery(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 0)
	f.counts["pb_a"] = 5
	w, ev := newWatch(t, f, nil)
	now := time.Now()
	w.round(context.Background(), now)

	f.mu.Lock()
	f.fail = http.StatusInternalServerError
	f.mu.Unlock()
	w.round(context.Background(), now.Add(time.Minute))
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("one failure alerted: %v", got)
	}
	v := w.View()
	if v.Servers[0].Up || v.Servers[0].Error != "HTTP 500" || len(v.Sessions) != 1 {
		t.Fatalf("after one failure %+v sessions %d", v.Servers[0], len(v.Sessions))
	}
	w.round(context.Background(), now.Add(2*time.Minute))
	w.round(context.Background(), now.Add(3*time.Minute))
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_unreachable "}) {
		t.Fatalf("events %v", got)
	}

	f.mu.Lock()
	f.fail = 0
	f.mu.Unlock()
	w.round(context.Background(), now.Add(4*time.Minute))
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_unreachable ", "ixp.rs_reachable "}) {
		t.Fatalf("events %v", got)
	}
	if ev.events[0].DedupKey() != ev.events[1].DedupKey() || !w.View().Servers[0].Up {
		t.Fatalf("dedup %q %q", ev.events[0].DedupKey(), ev.events[1].DedupKey())
	}
}

func TestStaleServerShowsNoSessions(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 0)
	f.counts["pb_a"] = 5
	w, _ := newWatch(t, f, nil)
	// The last good poll is older than three intervals.
	w.round(context.Background(), time.Now().Add(-time.Hour))
	f.mu.Lock()
	f.fail = http.StatusServiceUnavailable
	f.mu.Unlock()
	w.round(context.Background(), time.Now())
	v := w.View()
	if !v.Servers[0].Stale || v.Servers[0].Up || len(v.Sessions) != 0 || v.Servers[0].Sessions != 0 {
		t.Fatalf("%+v sessions %d", v.Servers[0], len(v.Sessions))
	}
	if h, ok := w.History("rs1", "pb_a"); !ok || len(h) != 1 {
		t.Fatalf("history kept? %v %v", h, ok)
	}
}

func TestHistoryIsBounded(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 0)
	f.counts["pb_a"] = 7
	f.tagged["pb_a"] = [][3]uint64{{rsASN, 1101, 5}, {rsASN, 1101, 5}}
	w, _ := newWatch(t, f, nil)
	now := time.Unix(10_000, 0)
	for i := 0; i < maxSamples+20; i++ {
		f.counts["pb_a"] = i
		w.round(context.Background(), now.Add(time.Duration(i)*time.Minute))
	}
	h, ok := w.History("rs1", "pb_a")
	if !ok || len(h) != maxSamples {
		t.Fatalf("len %d ok %v", len(h), ok)
	}
	last := h[len(h)-1]
	if last.Received != maxSamples+19 || last.Filtered != 2 || last.Accepted != maxSamples+17 ||
		!last.Established || !last.Counted || len(last.Reasons) != 1 || last.Reasons[0] != (plugin.RouteServerReason{Reason: 5, Count: 2}) {
		t.Fatalf("last %+v", last)
	}
	if h[0].Received != 20 || !h[0].At.Before(last.At) {
		t.Fatalf("first %+v", h[0])
	}
	if _, ok := w.History("rs1", "nope"); ok {
		t.Fatal("unknown session has history")
	}
	if _, ok := w.History("other", "pb_a"); ok {
		t.Fatal("unknown server has history")
	}
}

func TestHistoryOfGoneSessionAgesOut(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 0)
	w, _ := newWatch(t, f, nil)
	now := time.Unix(10_000, 0)
	w.round(context.Background(), now)
	f.mu.Lock()
	delete(f.protocols, "pb_a")
	f.mu.Unlock()
	w.round(context.Background(), now.Add(time.Hour))
	if _, ok := w.History("rs1", "pb_a"); !ok {
		t.Fatal("history dropped before the window")
	}
	w.round(context.Background(), now.Add(maxSamples*w.interval+time.Minute))
	if _, ok := w.History("rs1", "pb_a"); ok {
		t.Fatal("history kept past the window")
	}
}

func TestUnreadableCountsAreNotZero(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 0)
	f.counts["pb_a"] = 5
	f.bigLC = true
	w, ev := newWatch(t, f, map[string]any{"max_bytes": 2048})
	w.round(context.Background(), t0)
	s := session(w.View(), "pb_a")
	if s.Counted || s.Received != 0 || !strings.Contains(s.Error, "larger than 2048") {
		t.Fatalf("%+v", s)
	}
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("events %v", got)
	}
	h, _ := w.History("rs1", "pb_a")
	if len(h) != 1 || h[0].Counted {
		t.Fatalf("history %+v", h)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was requested: %s", r.URL)
	}))
	defer other.Close()
	front := httptest.NewServer(http.RedirectHandler(other.URL, http.StatusFound))
	defer front.Close()
	f := &fakeBirdseye{srv: front}
	w, ev := newWatch(t, f, nil)
	w.round(context.Background(), time.Now())
	w.round(context.Background(), time.Now())
	v := w.View()
	if v.Servers[0].Up || !strings.Contains(v.Servers[0].Error, "redirects") {
		t.Fatalf("%+v", v.Servers[0])
	}
	if got := ev.kinds(); len(got) != 1 {
		t.Fatalf("events %v", got)
	}
}

func TestStartPollsAndStopLeaves(t *testing.T) {
	f := newFake(t)
	f.setSession("pb_a", 64497, "192.0.2.10", "Established", 0)
	f.counts["pb_a"] = 1
	w, _ := newWatch(t, f, nil)
	if err := w.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(w.View().Sessions) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := w.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(w.View().Sessions) != 1 {
		t.Fatalf("no poll: %+v", w.View())
	}
}

func TestConfigValidation(t *testing.T) {
	good := map[string]any{"name": "rs1", "url": "https://rs1.example.invalid/birdseye/", "asn": 64496}
	cases := []struct {
		name string
		cfg  map[string]any
		want string
	}{
		{"no servers", map[string]any{}, "servers is required"},
		{"bad name", map[string]any{"servers": []map[string]any{{"name": "-x", "url": "http://192.0.2.1", "asn": 1}}}, "name is invalid"},
		{"duplicate", map[string]any{"servers": []map[string]any{good, good}}, "duplicated"},
		{"no asn", map[string]any{"servers": []map[string]any{{"name": "a", "url": "http://192.0.2.1"}}}, "asn is required"},
		{"userinfo", map[string]any{"servers": []map[string]any{{"name": "a", "url": "http://u:p@192.0.2.1", "asn": 1}}}, "no userinfo"},
		{"query", map[string]any{"servers": []map[string]any{{"name": "a", "url": "http://192.0.2.1/?apikey=x", "asn": 1}}}, "no userinfo, query"},
		{"scheme", map[string]any{"servers": []map[string]any{{"name": "a", "url": "ftp://192.0.2.1", "asn": 1}}}, "http or https"},
		{"interval", map[string]any{"servers": []map[string]any{good}, "interval": "10s"}, "interval"},
		{"timeout", map[string]any{"servers": []map[string]any{good}, "timeout": "10m"}, "timeout"},
		{"workers", map[string]any{"servers": []map[string]any{good}, "workers": 99}, "workers"},
		{"max bytes", map[string]any{"servers": []map[string]any{good}, "max_bytes": 5}, "max_bytes"},
		{"prefix pct", map[string]any{"servers": []map[string]any{good}, "max_prefix_warn_pct": 101}, "max_prefix_warn_pct"},
		{"filtered pct", map[string]any{"servers": []map[string]any{good}, "filtered_warn_pct": 101}, "filtered_warn_pct"},
		{"unknown key", map[string]any{"servers": []map[string]any{good}, "apikey": "x"}, "apikey"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(cfgNode(t, tc.cfg), plugin.Env{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
	p, err := New(cfgNode(t, map[string]any{"servers": []map[string]any{good}}), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	w := p.(*Watch)
	if w.servers[0].base != "https://rs1.example.invalid/birdseye" || w.interval != DefaultInterval ||
		w.prefPct != DefaultMaxPrefixWarnPct || w.filtPct != DefaultFilteredWarnPct {
		t.Fatalf("defaults %+v", w)
	}
}

func TestRegistered(t *testing.T) {
	if _, err := plugin.RouteServerWatches.New(TypeName, cfgNode(t, map[string]any{
		"servers": []map[string]any{{"name": "rs1", "url": "http://192.0.2.1", "asn": rsASN}},
	}), plugin.Env{}); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeProtocolsEmptyArray(t *testing.T) {
	ps, err := decodeProtocols(json.RawMessage(`[]`))
	if err != nil || len(ps) != 0 {
		t.Fatalf("%v %v", ps, err)
	}
	ps, err = decodeProtocols(json.RawMessage(`{"b":{"bgp_state":"Established"},"a":{"connection":"Active   Socket: No route to host"}}`))
	if err != nil || len(ps) != 2 || ps[0].Name != "a" || ps[0].established() || ps[0].stateText() != "Active" || !ps[1].established() {
		t.Fatalf("%+v %v", ps, err)
	}
}
