package icmp

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeProber struct {
	plugin.Base
	mu      sync.Mutex
	reqs    []plugin.ProbeRequest
	err     error
	res     plugin.ProbeResult
	block   chan struct{}
	entered chan struct{}
	once    sync.Once
	onDone  func(n int)
}

func (f *fakeProber) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, req)
	n := len(f.reqs)
	err, res, block := f.err, f.res, f.block
	f.mu.Unlock()
	if f.entered != nil {
		f.once.Do(func() { close(f.entered) })
	}
	if f.onDone != nil {
		f.onDone(n)
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return plugin.ProbeResult{}, ctx.Err()
		}
	}
	if err != nil {
		return plugin.ProbeResult{}, err
	}
	if res.Sent == 0 && res.RTTs == nil {
		res = plugin.ProbeResult{Sent: 5, RTTs: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}}
	}
	return res, nil
}

func (f *fakeProber) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func (f *fakeProber) requests() []plugin.ProbeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]plugin.ProbeRequest(nil), f.reqs...)
}

type allowWait struct{}

func (allowWait) WaitN(context.Context, int) error { return nil }

type fnWait struct {
	fn func(context.Context, int) error
}

func (f fnWait) WaitN(ctx context.Context, n int) error { return f.fn(ctx, n) }

// seqWait lets the first calls through and blocks the call numbered blockOn.
type seqWait struct {
	mu      sync.Mutex
	calls   int
	ns      []int
	blockOn int
	hold    chan struct{}
	hit     chan struct{}
}

func (s *seqWait) WaitN(ctx context.Context, n int) error {
	s.mu.Lock()
	s.calls++
	c := s.calls
	s.ns = append(s.ns, n)
	s.mu.Unlock()
	if c == s.blockOn {
		close(s.hit)
		select {
		case <-s.hold:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func testRunner(fp *fakeProber) *runner {
	return &runner{
		log:        slog.New(slog.DiscardHandler),
		prober:     fp,
		interval:   time.Minute,
		timeout:    time.Second,
		packets:    5,
		workers:    4,
		memberPPS:  1,
		global:     allowWait{},
		memberWait: func(uint32) waiter { return allowWait{} },
		http: &http.Client{
			Timeout:       time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return errNoRedirect },
		},
		view:      plugin.FabricView{Configured: true, Vantages: []plugin.FabricVantageStatus{}, Samples: []plugin.FabricSample{}},
		memberLim: map[uint32]*rate.Limiter{},
		now:       func() time.Time { return time.Unix(100, 0).UTC() },
	}
}

func v4(ip string) plugin.IXPAddress {
	return plugin.IXPAddress{Family: "ipv4", Address: ip, VLANID: 10}
}

func v6(ip string) plugin.IXPAddress {
	return plugin.IXPAddress{Family: "ipv6", Address: ip, VLANID: 10}
}

func boolPtr(v bool) *bool { return &v }

func memberView(members []plugin.IXPMember) plugin.MemberView {
	fetched := time.Unix(50, 0).UTC()
	return plugin.MemberView{
		Configured: true,
		Fetched:    &fetched,
		IXPs: []plugin.IXPSite{{
			ID:    1,
			VLANs: []plugin.IXPVLAN{{ID: 10, IPv4: "192.0.2.0/24", IPv6: "2001:db8::/64"}},
		}},
		Members: members,
	}
}

func oneMember(asn uint32, name string, addrs ...plugin.IXPAddress) plugin.IXPMember {
	return plugin.IXPMember{ASN: asn, Name: name, Connections: []plugin.IXPConnection{{
		IXPID:      1,
		State:      "active",
		Interfaces: []plugin.IXPInterface{{SwitchID: 7, Switch: "sw1", Colo: "cab-a"}},
		Addresses:  addrs,
	}}}
}

func vantage(name, ip string) plugin.FabricVantage {
	return plugin.FabricVantage{Name: name, VLANID: 10, Address: netip.MustParseAddr(ip)}
}

func TestManagerCanPingGate(t *testing.T) {
	addr := v4("192.0.2.20")
	busy := v4("192.0.2.21")
	missing := v4("192.0.2.31")
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", addr, busy, missing)})
	view.Manager = true
	vantages := []plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")}

	targets, opt, _ := selectTargets(view, vantages, nil)
	if len(targets) != 0 || opt != 3 {
		t.Fatalf("no list: targets %d opt %d", len(targets), opt)
	}
	targets, opt, _ = selectTargets(view, vantages, map[string]map[string]nagiosHost{"ipv4/10": {}})
	if len(targets) != 0 || opt != 3 {
		t.Fatalf("empty list: targets %d opt %d", len(targets), opt)
	}

	parts := map[string]map[string]nagiosHost{
		"ipv4/10": {
			"192.0.2.20": {canPing: true},
			"192.0.2.21": {canPing: true, busy: true},
		},
	}
	targets, opt, _ = selectTargets(view, vantages, parts)
	if opt != 1 || len(targets) != 2 {
		t.Fatalf("list: targets %d opt %d", len(targets), opt)
	}
	got := map[string]target{}
	for _, tg := range targets {
		got[tg.addr.String()] = tg
	}
	if got["192.0.2.20"].busy || got["192.0.2.20"].tol != tolNormal {
		t.Fatalf("normal %+v", got["192.0.2.20"])
	}
	if !got["192.0.2.21"].busy || got["192.0.2.21"].tol != tolBusy {
		t.Fatalf("busy %+v", got["192.0.2.21"])
	}
	if _, ok := got["192.0.2.31"]; ok {
		t.Fatal("address missing from the customers document was probed")
	}

	addr.CanPing = boolPtr(false)
	view.Members[0].Connections[0].Addresses[0] = addr
	targets, opt, _ = selectTargets(view, vantages, parts)
	if len(targets) != 1 || opt != 2 || targets[0].addr.String() != "192.0.2.21" {
		t.Fatalf("ix-f opt-out: %+v opt %d", targets, opt)
	}
}

func TestSelectAndMeasure(t *testing.T) {
	off := v4("192.0.2.30")
	off.CanPing = boolPtr(false)
	busy := v4("192.0.2.21")
	busy.BusyHost = true
	rs := v4("192.0.2.22")
	rs.RouteServer = true
	outside := v4("198.51.100.9")
	otherVLAN := v4("192.0.2.23")
	otherVLAN.VLANID = 11
	self := v4("192.0.2.8")
	down := oneMember(64496, "Down", v4("192.0.2.40"))
	down.Connections[0].State = ""
	view := memberView([]plugin.IXPMember{
		oneMember(64500, "Later", v4("192.0.2.20")),
		oneMember(64496, "Member A", v4("192.0.2.20"), busy, rs, outside, otherVLAN, self, off, v6("2001:db8::20")),
		down,
	})
	// The lower ASN owns 192.0.2.20 even though it is listed second.
	view.Members[1].Connections[0].State = "connected"
	vantages := []plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8"), vantage("lan1-v6", "2001:db8::8")}
	targets, opt, statuses := selectTargets(view, vantages, nil)
	if opt != 1 {
		t.Fatalf("opt out %d", opt)
	}
	if len(statuses) != 2 || statuses[0].Error != "" || statuses[1].Error != "" {
		t.Fatalf("statuses %+v", statuses)
	}
	got := map[string]target{}
	for _, tg := range targets {
		got[tg.vantage+"/"+tg.addr.String()] = tg
	}
	if len(got) != 4 {
		t.Fatalf("targets %d %+v", len(got), targets)
	}
	a := got["lan1-v4/192.0.2.20"]
	if a.asn != 64496 || a.name != "Member A" || a.busy || a.source.String() != "192.0.2.8" {
		t.Fatalf("owner %+v", a)
	}
	if len(a.switches) != 1 || a.switches[0].ID != 7 || a.switches[0].Name != "sw1" || a.switches[0].Colo != "cab-a" {
		t.Fatalf("switches %+v", a.switches)
	}
	if !got["lan1-v4/192.0.2.21"].busy || got["lan1-v4/192.0.2.21"].tol != tolBusy {
		t.Fatalf("busy %+v", got["lan1-v4/192.0.2.21"])
	}
	if _, ok := got["lan1-v4/192.0.2.22"]; !ok {
		t.Fatal("route server was not a target")
	}
	if got["lan1-v6/2001:db8::20"].source.String() != "2001:db8::8" || got["lan1-v6/2001:db8::20"].family != "ipv6" {
		t.Fatalf("v6 %+v", got["lan1-v6/2001:db8::20"])
	}
	for _, absent := range []string{"lan1-v4/192.0.2.30", "lan1-v4/192.0.2.8", "lan1-v4/198.51.100.9", "lan1-v4/192.0.2.23", "lan1-v4/192.0.2.40"} {
		if _, ok := got[absent]; ok {
			t.Fatalf("probed %s", absent)
		}
	}

	now := time.Unix(100, 0).UTC()
	res := plugin.ProbeResult{Sent: 5, RTTs: []time.Duration{10 * time.Millisecond, 12 * time.Millisecond, 11 * time.Millisecond, 15 * time.Millisecond}}
	sample := a.measured(now, res)
	if sample.LossPct != 20 || sample.RTTMs != 12 || sample.JitterMs != float64(7*time.Millisecond/3)/float64(time.Millisecond) || !sample.PastTolerance {
		t.Fatalf("stats %+v", sample)
	}
	bad := a.errored(now, "bind failed")
	if bad.PastTolerance || bad.Sent != 0 || bad.Error != "bind failed" {
		t.Fatalf("error sample %+v", bad)
	}
}

func TestToleranceBounds(t *testing.T) {
	now := time.Unix(1, 0).UTC()
	normal := target{tol: tolNormal}
	busy := target{tol: tolBusy}
	cases := []struct {
		name string
		tg   target
		res  plugin.ProbeResult
		past bool
	}{
		{"normal 50% loss", normal, plugin.ProbeResult{Sent: 2, RTTs: []time.Duration{time.Millisecond}}, true},
		{"normal 400ms", normal, plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{400 * time.Millisecond}}, true},
		{"normal exact 20%", normal, plugin.ProbeResult{Sent: 5, RTTs: []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond, time.Millisecond}}, true},
		{"normal 250ms", normal, plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{250 * time.Millisecond}}, true},
		{"normal inside", normal, plugin.ProbeResult{Sent: 5, RTTs: []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}}, false},
		{"busy 50% and 400ms", busy, plugin.ProbeResult{Sent: 2, RTTs: []time.Duration{400 * time.Millisecond}}, false},
		{"busy 999ms", busy, plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{999 * time.Millisecond}}, false},
		{"busy 85%", busy, plugin.ProbeResult{Sent: 20, RTTs: makeRTTs(3, time.Millisecond)}, true},
		{"busy 1000ms", busy, plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{1000 * time.Millisecond}}, true},
		{"busy 100% loss", busy, plugin.ProbeResult{Sent: 5}, true},
		{"sent 0", normal, plugin.ProbeResult{}, false},
	}
	for _, tc := range cases {
		s := tc.tg.measured(now, tc.res)
		if s.PastTolerance != tc.past {
			t.Errorf("%s past=%v loss=%v rtt=%v", tc.name, s.PastTolerance, s.LossPct, s.RTTMs)
		}
	}
	custom := target{tol: tolerance{warnRTT: 100 * time.Millisecond, warnLoss: 10, critRTT: 1500 * time.Millisecond}}
	if custom.measured(now, plugin.ProbeResult{Sent: 1, RTTs: []time.Duration{50 * time.Millisecond}}).PastTolerance {
		t.Fatal("custom inside was past")
	}
	if !custom.measured(now, plugin.ProbeResult{Sent: 10, RTTs: makeRTTs(9, time.Millisecond)}).PastTolerance {
		t.Fatal("custom 10% loss was not past")
	}
}

func makeRTTs(n int, d time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func TestVantageSelectionFailsClosed(t *testing.T) {
	view := memberView([]plugin.IXPMember{oneMember(64496, "Member A", v4("192.0.2.20"))})
	_, _, st := selectTargets(view, []plugin.FabricVantage{vantage("lan1-v4", "198.51.100.8")}, nil)
	if len(st) != 1 || st[0].Error != "vantage address is not on the peering LAN" || st[0].Up {
		t.Fatalf("%+v", st)
	}
	_, _, st = selectTargets(view, []plugin.FabricVantage{{Name: "lan1-v4", VLANID: 99, Address: netip.MustParseAddr("192.0.2.8")}}, nil)
	if st[0].Error != "vlan_id is not in the member list" {
		t.Fatalf("%+v", st)
	}
	two := view
	two.IXPs = append(two.IXPs, plugin.IXPSite{ID: 2, VLANs: []plugin.IXPVLAN{{ID: 10, IPv4: "192.0.2.0/24"}}})
	_, _, st = selectTargets(two, []plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")}, nil)
	if st[0].Error != "vlan_id is on more than one ixp; set ixp_id" {
		t.Fatalf("%+v", st)
	}
	picked := vantage("lan1-v4", "192.0.2.8")
	picked.IXPID = 1
	targets, _, st := selectTargets(two, []plugin.FabricVantage{picked}, nil)
	if st[0].Error != "" || len(targets) != 1 || targets[0].ixp != 1 {
		t.Fatalf("targets %d status %+v", len(targets), st)
	}

	for _, state := range []string{"active", "connected", "operational"} {
		m := oneMember(64496, "Member A", v4("192.0.2.20"))
		m.Connections[0].State = state
		targets, _, _ := selectTargets(memberView([]plugin.IXPMember{m}), []plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")}, nil)
		if len(targets) != 1 {
			t.Fatalf("state %s targets %d", state, len(targets))
		}
	}
	for _, state := range []string{"", "down", "disabled"} {
		m := oneMember(64496, "Member A", v4("192.0.2.20"))
		m.Connections[0].State = state
		targets, _, _ := selectTargets(memberView([]plugin.IXPMember{m}), []plugin.FabricVantage{vantage("lan1-v4", "192.0.2.8")}, nil)
		if len(targets) != 0 {
			t.Fatalf("state %q was probed", state)
		}
	}
}
