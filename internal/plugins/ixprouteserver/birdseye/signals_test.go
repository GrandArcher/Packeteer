package birdseye

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	sessA = "pb_0001_as64497"
	sessB = "pb_0002_as64498"
)

// signalFake has two Established members, A (AS64497) and B (AS64498).
func signalFake(t *testing.T) *fakeBirdseye {
	t.Helper()
	f := newFake(t)
	f.setSession(sessA, 64497, "192.0.2.10", "Established", 0)
	f.setSession(sessB, 64498, "192.0.2.11", "Established", 0)
	return f
}

// setRoutes replaces a session's listing and its route count.
func (f *fakeBirdseye) setRoutes(session string, routes ...fakeRoute) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[session] = routes
	f.counts[session] = len(routes)
}

func route(network string, path ...string) fakeRoute {
	return fakeRoute{network: network, path: path}
}

func tick(w *Watch, i int) {
	w.round(context.Background(), t0.Add(time.Duration(i)*time.Minute))
}

func TestFilterSpikeOpensAndCloses(t *testing.T) {
	f := signalFake(t)
	f.counts[sessA] = 500
	w, ev := newWatch(t, f, nil)
	tag := func(reason uint64, n int) [][3]uint64 {
		var out [][3]uint64
		for i := 0; i < n; i++ {
			out = append(out, [3]uint64{rsASN, 1101, reason})
		}
		return out
	}

	// First sighting has no baseline: 30 RPKI-invalid routes say nothing.
	f.tagged[sessA] = tag(13, 30)
	tick(w, 0)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("first poll %v", got)
	}

	// Up by 9 is under spike_min (10); up by 10 and 2x opens the alert.
	f.tagged[sessA] = tag(13, 39)
	tick(w, 1)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("under spike_min %v", got)
	}
	f.tagged[sessA] = append(tag(13, 60), tag(3, 80)...)
	tick(w, 2)
	// Reason 3 (a bogon) is not watched, and 60 is under 2x the level of 39.
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("under factor %v", got)
	}
	f.tagged[sessA] = tag(13, 130)
	tick(w, 3)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_filter_spike " + sessA}) {
		t.Fatalf("spike %v", got)
	}
	e := ev.events[0]
	if e.Severity != plugin.SeverityWarning || e.Fields["reason"] != "13" || e.Fields["count"] != "130" ||
		e.Fields["baseline"] != "60" || e.Fields["asn"] != "64497" || e.Fields["server"] != "rs1" {
		t.Fatalf("event %+v", e)
	}

	// Still high: not repeated. The level is the one before the spike, so
	// the alert closes at the same threshold it opened at.
	ev.reset()
	tick(w, 4)
	tick(w, 5)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("repeated %v", got)
	}
	f.tagged[sessA] = tag(13, 125)
	tick(w, 6)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("closed too early %v", got)
	}
	f.tagged[sessA] = tag(13, 100)
	tick(w, 7)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_filter_spike_cleared " + sessA}) {
		t.Fatalf("clear %v", got)
	}
	if ev.events[0].DedupKey() != e.DedupKey() || !ev.events[0].Resolves() {
		t.Fatalf("dedup %q vs %q", ev.events[0].DedupKey(), e.DedupKey())
	}
}

func TestFilterSpikeKnobsAndReasons(t *testing.T) {
	f := signalFake(t)
	f.counts[sessA] = 100
	w, ev := newWatch(t, f, map[string]any{"spike_min": 3, "spike_factor": 1})
	tick(w, 0)
	for _, reason := range []uint64{9, 10, 14} {
		f.tagged[sessA] = [][3]uint64{{rsASN, 1101, reason}, {rsASN, 1101, reason}, {rsASN, 1101, reason}}
		ev.reset()
		tick(w, int(reason))
		got := ev.kinds()
		if len(got) != 1 || ev.events[0].Fields["reason"] != itoa(reason) {
			t.Fatalf("reason %d: %v", reason, got)
		}
		f.tagged[sessA] = nil
		tick(w, int(reason)+100)
	}
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func TestNoRouteListingUnlessEnabled(t *testing.T) {
	f := signalFake(t)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	w, _ := newWatch(t, f, nil)
	tick(w, 0)
	for _, r := range f.get() {
		if strings.Contains(r, "/api/routes/protocol/") {
			t.Fatalf("listing requested: %s", r)
		}
	}
	s := session(w.View(), sessA)
	if s.Scanned || s.Blackhole != 0 {
		t.Fatalf("session %+v", s)
	}
}

func TestOnlyAllowlistedGETsWithRouteSignals(t *testing.T) {
	f := signalFake(t)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.counts[sessB] = 0
	w, _ := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	want := []string{
		"GET /api/status",
		"GET /api/protocols/bgp",
		"GET /api/routes/count/protocol/" + sessA,
		"GET /api/routes/count/protocol/" + sessB,
		"GET /api/routes/lc-zwild/protocol/" + sessA + "/64496/1101",
		"GET /api/routes/protocol/" + sessA,
		"GET /api/routes/protocol/" + sessB,
	}
	got := f.get()
	slices.Sort(got[2:])
	slices.Sort(want[2:])
	if !slices.Equal(got, want) {
		t.Fatalf("requests\n got %v\nwant %v", got, want)
	}
}

func TestBlackholeRoutesAreCountedPerMember(t *testing.T) {
	f := signalFake(t)
	bh := fakeRoute{network: "192.0.2.77/32", path: []string{"64498"}, comm: [][2]uint64{{65535, 666}, {64496, 1}}}
	other := fakeRoute{network: "192.0.2.78/32", path: []string{"64498"}, comm: [][2]uint64{{65535, 667}}}
	filteredBH := fakeRoute{network: "192.0.2.79/32", path: []string{"64498"}, comm: [][2]uint64{{65535, 666}},
		large: [][3]uint64{{rsASN, 1101, 4}}}
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.setRoutes(sessB, bh, other, filteredBH)
	w, ev := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	f.setRoutes(sessB, bh, other)
	tick(w, 1)

	v := w.View()
	if a := session(v, sessA); !a.Scanned || a.Blackhole != 0 {
		t.Fatalf("A %+v", a)
	}
	if b := session(v, sessB); !b.Scanned || b.Blackhole != 1 || b.ScanError != "" {
		t.Fatalf("B %+v", b)
	}
	h, ok := w.History("rs1", sessB)
	if !ok || len(h) != 2 || h[0].Blackhole != 2 || h[1].Blackhole != 1 || !h[0].Scanned || !h[1].Scanned {
		t.Fatalf("history %+v", h)
	}
	// A /32 blackhole inside A's /24, with another origin, is expected.
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("events %v", got)
	}
}

func TestOriginChangeAgainstAnotherMember(t *testing.T) {
	f := signalFake(t)
	a := []fakeRoute{route("192.0.2.0/24", "64497"), route("203.0.113.0/24", "64500", "64497")}
	b := []fakeRoute{route("198.51.100.0/24", "64498")}
	f.setRoutes(sessA, a...)
	f.setRoutes(sessB, b...)
	w, ev := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("baseline %v", got)
	}

	// B announces A's 203.0.113.0/24 with A's own origin (a customer behind
	// two members): not a change. It also announces 192.0.2.0/24 with its
	// own origin: a change. A tagged route of B with a new origin is
	// filtered, so it is ignored.
	filtered := fakeRoute{network: "2001:db8::/32", path: []string{"64498"}, large: [][3]uint64{{rsASN, 1101, 13}}}
	f.setRoutes(sessA, append(a, route("2001:db8::/32", "64497"))...)
	tick(w, 1)
	ev.reset()
	f.setRoutes(sessB, append(b, route("203.0.113.0/24", "64501", "64497"), route("192.0.2.0/24", "64498"), filtered)...)
	tick(w, 2)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_origin_change " + sessB}) {
		t.Fatalf("events %v", got)
	}
	e := ev.events[0]
	if e.Fields["count"] != "1" || e.Fields["prefix"] != "192.0.2.0/24" || e.Fields["origin"] != "64498" || e.Severity != plugin.SeverityWarning {
		t.Fatalf("event %+v", e)
	}

	// Held while the route stays; closed when it leaves.
	ev.reset()
	tick(w, 3)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("repeated %v", got)
	}
	f.setRoutes(sessB, append(b, route("203.0.113.0/24", "64501", "64497"))...)
	tick(w, 4)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_origin_change_cleared " + sessB}) {
		t.Fatalf("clear %v", got)
	}
	if ev.events[0].DedupKey() != e.DedupKey() || !ev.events[0].Resolves() {
		t.Fatalf("dedup")
	}
}

func TestOriginChangeBaselineAndNewSession(t *testing.T) {
	f := signalFake(t)
	// The conflict is there at the first poll: that is the baseline.
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.setRoutes(sessB, route("192.0.2.0/24", "64498"))
	w, ev := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	tick(w, 1)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("baseline %v", got)
	}

	// A session that joins later is judged from its first listing.
	f.setSession("pb_0003_as64499", 64499, "192.0.2.12", "Established", 0)
	f.setRoutes("pb_0003_as64499", route("198.51.100.0/24", "64499"), route("192.0.2.0/24", "64497"))
	tick(w, 2)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("same origin joined %v", got)
	}
	f.setSession("pb_0004_as64500", 64500, "192.0.2.13", "Established", 0)
	f.setRoutes("pb_0004_as64500", route("198.51.100.0/24", "64500"))
	tick(w, 3)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_origin_change pb_0004_as64500"}) {
		t.Fatalf("new session %v", got)
	}
}

func TestOriginOfSameMemberTwoSessionsIsNotAChange(t *testing.T) {
	f := signalFake(t)
	f.setSession("pb_0005_as64497_v6", 64497, "192.0.2.14", "Established", 0)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.setRoutes("pb_0005_as64497_v6", route("198.51.100.0/24", "64497"))
	w, ev := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	f.setRoutes("pb_0005_as64497_v6", route("198.51.100.0/24", "64497"), route("192.0.2.0/24", "64510"))
	tick(w, 1)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("own prefix via a second session: %v", got)
	}
}

func TestMoreSpecificBurst(t *testing.T) {
	f := signalFake(t)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"), route("2001:db8::/32", "64497"))
	f.setRoutes(sessB, route("198.51.100.0/24", "64498"))
	w, ev := newWatch(t, f, map[string]any{"route_signals": true, "burst_min": 3})
	tick(w, 0)

	b := []fakeRoute{route("198.51.100.0/24", "64498")}
	// Two more-specifics are under burst_min; one has A's origin, so it
	// does not count either.
	b1 := append(slices.Clone(b), route("192.0.2.0/25", "64498"), route("192.0.2.128/25", "64498"), route("192.0.2.64/26", "64500", "64497"))
	f.setRoutes(sessB, b1...)
	tick(w, 1)
	if got := ev.kinds(); len(got) != 0 {
		t.Fatalf("small %v", got)
	}

	// Three new ones, one of them IPv6, in one poll are a burst.
	b2 := append(slices.Clone(b1), route("192.0.2.32/27", "64498"), route("192.0.2.96/27", "64498"), route("2001:db8:1::/48", "64498"))
	f.setRoutes(sessB, b2...)
	tick(w, 2)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_morespecific_burst " + sessB}) {
		t.Fatalf("burst %v", got)
	}
	e := ev.events[0]
	if e.Fields["count"] != "3" || e.Severity != plugin.SeverityWarning {
		t.Fatalf("event %+v", e)
	}
	if e.Fields["prefix"] != "192.0.2.32/27" {
		t.Fatalf("example is not the lowest prefix: %v", e.Fields["prefix"])
	}

	// The alert closes only when all three are gone.
	ev.reset()
	f.setRoutes(sessB, b1...)
	tick(w, 3)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_morespecific_burst_cleared " + sessB}) {
		t.Fatalf("clear %v", got)
	}
	if ev.events[0].DedupKey() != e.DedupKey() || !ev.events[0].Resolves() {
		t.Fatalf("dedup")
	}
}

func TestRemovedSessionClosesSignalAlerts(t *testing.T) {
	f := signalFake(t)
	f.counts[sessB] = 100
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	w, ev := newWatch(t, f, map[string]any{"route_signals": true, "spike_min": 2})
	f.setRoutes(sessB, route("198.51.100.0/24", "64498"))
	tick(w, 0)
	f.setRoutes(sessB, route("198.51.100.0/24", "64498"), route("192.0.2.0/24", "64498"))
	f.tagged[sessB] = [][3]uint64{{rsASN, 1101, 13}, {rsASN, 1101, 13}}
	tick(w, 1)
	got := ev.kinds()
	slices.Sort(got)
	if want := []string{"ixp.rs_filter_spike " + sessB, "ixp.rs_filtered " + sessB, "ixp.rs_origin_change " + sessB}; !slices.Equal(got, want) {
		t.Fatalf("open %v", got)
	}
	ev.reset()
	f.mu.Lock()
	delete(f.protocols, sessB)
	f.mu.Unlock()
	tick(w, 2)
	got = ev.kinds()
	slices.Sort(got)
	want := []string{"ixp.rs_filter_spike_cleared " + sessB, "ixp.rs_filtered_cleared " + sessB, "ixp.rs_origin_change_cleared " + sessB}
	if !slices.Equal(got, want) {
		t.Fatalf("close %v", got)
	}
}

// A down session's routes are gone from the route server, so its table
// leaves the comparison and its origin alert closes. On return the routes
// are judged afresh, so the alert opens again.
func TestDownSessionDropsItsRoutes(t *testing.T) {
	f := signalFake(t)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.setRoutes(sessB, route("198.51.100.0/24", "64498"))
	w, ev := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	f.setRoutes(sessB, route("192.0.2.0/24", "64498"))
	tick(w, 1)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_origin_change " + sessB}) {
		t.Fatalf("open events %v", got)
	}
	ev.reset()
	f.setSession(sessB, 64498, "192.0.2.11", "Idle", 0)
	tick(w, 2)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_origin_change_cleared " + sessB, "ixp.rs_session_down " + sessB}) {
		t.Fatalf("down events %v", got)
	}
	ev.reset()
	f.setSession(sessB, 64498, "192.0.2.11", "Established", 0)
	tick(w, 3)
	want := []string{"ixp.rs_session_up " + sessB, "ixp.rs_origin_change " + sessB}
	if got := ev.kinds(); !slices.Equal(got, want) {
		t.Fatalf("up events %v", got)
	}
}

// Sessions with an unknown ASN (0) are separate members, so each one's
// origin is judged against the other's route.
func TestUnknownASNSessionsAreSeparateMembers(t *testing.T) {
	f := newFake(t)
	f.setSession(sessA, 0, "192.0.2.10", "Established", 0)
	f.setSession(sessB, 0, "192.0.2.11", "Established", 0)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.setRoutes(sessB, route("203.0.113.0/24", "64498"))
	w, ev := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	f.setRoutes(sessB, route("203.0.113.0/24", "64498"), route("192.0.2.0/24", "64498"))
	tick(w, 1)
	if got := ev.kinds(); !slices.Equal(got, []string{"ixp.rs_origin_change " + sessB}) {
		t.Fatalf("events %v", got)
	}
}

func TestListingFailureKeepsCounts(t *testing.T) {
	f := signalFake(t)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"))
	f.listFail = http.StatusForbidden
	w, _ := newWatch(t, f, map[string]any{"route_signals": true})
	tick(w, 0)
	s := session(w.View(), sessA)
	if !s.Counted || s.Received != 1 || s.Scanned || s.ScanError != "HTTP 403" || s.Error != "" {
		t.Fatalf("session %+v", s)
	}

	// A session over Birdseye's max_routes is not listed at all.
	f.listFail = 0
	f.maxRoutes = 1
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"), route("198.51.100.0/24", "64497"))
	before := len(f.get())
	tick(w, 1)
	for _, r := range f.get()[before:] {
		if r == "GET /api/routes/protocol/"+sessA {
			t.Fatalf("listing requested: %s", r)
		}
	}
	s = session(w.View(), sessA)
	if s.Scanned || !strings.Contains(s.ScanError, "api.max_routes (1)") {
		t.Fatalf("session %+v", s)
	}
}

func TestTrackedRoutesAreBounded(t *testing.T) {
	f := signalFake(t)
	f.setRoutes(sessA, route("192.0.2.0/24", "64497"), route("198.51.100.0/24", "64497"))
	f.setRoutes(sessB, route("203.0.113.0/24", "64498"), route("2001:db8::/32", "64498"))
	w, _ := newWatch(t, f, map[string]any{"route_signals": true})
	w.maxTracked = 3
	tick(w, 0)
	v := w.View()
	a, b := session(v, sessA), session(v, sessB)
	if !a.Scanned || b.Scanned || !strings.Contains(b.ScanError, "more than 3") || !b.Counted {
		t.Fatalf("A %+v B %+v", a, b)
	}
}

func TestOriginAS(t *testing.T) {
	cases := []struct {
		path []string
		want uint32
		ok   bool
	}{
		{[]string{"64500", "64497"}, 64497, true},
		{[]string{"64497"}, 64497, true},
		{[]string{"64500", "{64497,64498}"}, 0, false},
		{[]string{}, 0, false},
		{[]string{"0"}, 0, false},
		{[]string{"x"}, 0, false},
	}
	for _, c := range cases {
		got, ok := originAS(c.path)
		if got != c.want || ok != c.ok {
			t.Errorf("%v: %d %v", c.path, got, ok)
		}
	}
}
