package main

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func TestTableIndexInvertsPrefix(t *testing.T) {
	for _, n := range []int{v4Count + 2, 70000} {
		tbl := newTable(n)
		for i := range n {
			if got, ok := tbl.index(tbl.prefix(i)); !ok || got != i {
				t.Fatalf("n=%d: index(prefix(%d) = %s) = %d, %v", n, i, tbl.prefix(i), got, ok)
			}
		}
		for _, s := range []string{"192.0.2.0/23", "192.0.3.0/24", "10.0.0.0/8", "2001:db8::/31", "2001:db9::/48", "2001:db8:ffff:ffff::/64"} {
			if i, ok := tbl.index(netip.MustParsePrefix(s)); ok {
				t.Fatalf("n=%d: %s is entry %d", n, s, i)
			}
		}
	}
	// An entry past the table's end is not in it.
	small, big := newTable(v4Count+100), newTable(v4Count+5000)
	if _, ok := small.index(big.prefix(v4Count + 4000)); ok {
		t.Fatal("prefix of a larger table found in a smaller one")
	}
}

// fakeSpeaker plays Packeteer's side of one session.
type fakeSpeaker struct {
	c   net.Conn
	mu  sync.Mutex
	in  []bgp.BGPMessage
	eor int // End-of-RIB markers seen
	end chan struct{}
}

func dialRouter(t *testing.T, rt *router) *fakeSpeaker {
	t.Helper()
	s, err := tryDial(rt)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// tryDial is dialRouter for goroutines, which may not call t.Fatal.
func tryDial(rt *router) (*fakeSpeaker, error) {
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(peerAddr)}, Timeout: 5 * time.Second}
	c, err := d.Dial("tcp", rt.ln.Addr().String())
	if err != nil {
		return nil, err
	}
	caps := []bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC), bgp.NewCapMultiProtocol(bgp.RF_IPv6_UC)}
	if err := writeMsg(c, bgp.NewBGPOpenMessage(labASN, 90, "192.0.2.10", []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})); err != nil {
		c.Close()
		return nil, err
	}
	for _, want := range []uint8{bgp.BGP_MSG_OPEN, bgp.BGP_MSG_KEEPALIVE} {
		m, err := readMsg(c)
		if err != nil || m.Header.Type != want {
			c.Close()
			return nil, fmt.Errorf("handshake: %v %v", m, err)
		}
	}
	if err := writeMsg(c, bgp.NewBGPKeepAliveMessage()); err != nil {
		c.Close()
		return nil, err
	}
	s := &fakeSpeaker{c: c, end: make(chan struct{})}
	go func() {
		defer close(s.end)
		for {
			m, err := readMsg(c)
			if err != nil {
				return
			}
			s.mu.Lock()
			if m.Header.Type == bgp.BGP_MSG_UPDATE {
				if isEoR(m.Body.(*bgp.BGPUpdate)) {
					s.eor++
				} else {
					s.in = append(s.in, *m)
				}
			}
			s.mu.Unlock()
		}
	}()
	return s, nil
}

func isEoR(u *bgp.BGPUpdate) bool {
	if len(u.WithdrawnRoutes) == 0 && len(u.NLRI) == 0 && len(u.PathAttributes) == 0 {
		return true
	}
	if len(u.PathAttributes) == 1 {
		if mp, ok := u.PathAttributes[0].(*bgp.PathAttributeMpUnreachNLRI); ok && len(mp.Value) == 0 {
			return true
		}
	}
	return false
}

// routes is the prefixes the speaker has been sent, announced minus
// withdrawn, in arrival order.
func (s *fakeSpeaker) routes() (announced, withdrawn []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.in {
		u := m.Body.(*bgp.BGPUpdate)
		for _, n := range u.WithdrawnRoutes {
			withdrawn = append(withdrawn, nlriPrefix(n))
		}
		for _, n := range u.NLRI {
			announced = append(announced, nlriPrefix(n))
		}
		for _, a := range u.PathAttributes {
			switch v := a.(type) {
			case *bgp.PathAttributeMpReachNLRI:
				for _, n := range v.Value {
					announced = append(announced, nlriPrefix(n))
				}
			case *bgp.PathAttributeMpUnreachNLRI:
				for _, n := range v.Value {
					withdrawn = append(withdrawn, nlriPrefix(n))
				}
			}
		}
	}
	return announced, withdrawn
}

func (s *fakeSpeaker) reset() {
	s.mu.Lock()
	s.in, s.eor = nil, 0
	s.mu.Unlock()
}

func (s *fakeSpeaker) eors() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eor
}

// injected is the UPDATE Packeteer sends for one of its routes.
func injected(p netip.Prefix, comms ...uint32) *bgp.BGPMessage {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath(nil),
		bgp.NewPathAttributeLocalPref(250),
		bgp.NewPathAttributeCommunities(comms),
	}
	if p.Addr().Is4() {
		attrs = append(attrs, bgp.NewPathAttributeNextHop("192.0.2.2"))
		return bgp.NewBGPUpdateMessage(nil, attrs, []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(uint8(p.Bits()), p.Addr().String())})
	}
	nlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(uint8(p.Bits()), p.Addr().String())}
	return bgp.NewBGPUpdateMessage(nil, append(attrs, bgp.NewPathAttributeMpReachNLRI("2001:db8:ffff::2", nlri)), nil)
}

func withdrawal(p netip.Prefix) *bgp.BGPMessage {
	if p.Addr().Is4() {
		return bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(uint8(p.Bits()), p.Addr().String())}, nil, nil)
	}
	nlri := []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(uint8(p.Bits()), p.Addr().String())}
	return bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{bgp.NewPathAttributeMpUnreachNLRI(nlri)}, nil)
}

const ownComms = packeteerComm

var goodComms = []uint32{ownComms, uint32(bgp.COMMUNITY_NO_EXPORT)}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	if !waitFor(context.Background(), 5*time.Second, cond) {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func newTestRouter(t *testing.T, ctx context.Context, id int, tbl table, adv *advertised) *router {
	t.Helper()
	rt, err := startRouter(ctx, id, 0, tbl, adv)
	if err != nil {
		t.Skipf("loopback %s not usable: %v", routerAddrs[id], err)
	}
	t.Cleanup(rt.stop)
	return rt
}

// acceptFake opens a session between rt and a fake Packeteer.
func acceptFake(t *testing.T, rt *router) *fakeSpeaker {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- rt.accept() }()
	s := dialRouter(t, rt)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	return s
}

// A router sends its whole table and End-of-RIB on every session, leaves
// out what the fleet has withdrawn when it sends the table again after a
// flap, and counts only a drop it did not cause.
func TestRouterFlapResendsTableWithoutWithdrawn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tbl := newTable(v4Count + 3000)
	f := &fleet{adv: newAdvertised()}
	rt := newTestRouter(t, ctx, 1, tbl, f.adv)
	f.routers = []*router{rt}

	s := acceptFake(t, rt)
	go rt.serve(ctx, make(chan struct{}))
	eventually(t, "table and End-of-RIB", func() bool { return s.eors() == 2 })
	ann, _ := s.routes()
	if len(ann) != tbl.n {
		t.Fatalf("first table: %d prefixes, want %d", len(ann), tbl.n)
	}
	for i, p := range ann {
		if p != tbl.prefix(i) {
			t.Fatalf("entry %d sent as %s, want %s", i, p, tbl.prefix(i))
		}
	}

	s.reset()
	f.withdraw(10, 20)
	f.withdraw(v4Count+5, v4Count+7)
	eventually(t, "withdrawals", func() bool { _, w := s.routes(); return len(w) == 12 })

	if !rt.flap() || rt.established() {
		t.Fatal("flap did not close the session")
	}
	<-s.end
	if rt.drops.Load() != 0 {
		t.Fatal("a flap counted as a drop")
	}
	s = dialRouter(t, rt)
	eventually(t, "table after the flap", func() bool { return s.eors() == 2 })
	ann, _ = s.routes()
	if len(ann) != tbl.n-12 {
		t.Fatalf("table after the flap: %d prefixes, want %d", len(ann), tbl.n-12)
	}
	for _, i := range []int{10, 19, v4Count + 5, v4Count + 6} {
		if slices.Contains(ann, tbl.prefix(i)) {
			t.Fatalf("withdrawn entry %d sent again after the flap", i)
		}
	}

	s.reset()
	f.announce(10, 20)
	eventually(t, "announce", func() bool { a, _ := s.routes(); return len(a) == 10 })

	_ = s.c.Close()
	eventually(t, "the drop counted", func() bool { return rt.drops.Load() == 1 && !rt.established() })
}

// Every route Packeteer sends is checked as it arrives.
func TestAdjOutChecksPacketeerRoutes(t *testing.T) {
	tbl := newTable(v4Count + 3000)
	a := newAdjOut()
	feed := func(m *bgp.BGPMessage) {
		b, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		pm, err := bgp.ParseBGPMessage(b)
		if err != nil {
			t.Fatal(err)
		}
		a.apply(pm.Body.(*bgp.BGPUpdate), time.Now(), tbl, 3)
	}
	v4, v6 := tbl.prefix(5), tbl.prefix(v4Count+1)
	feed(injected(v4, goodComms...))
	feed(injected(v6, goodComms...))
	if a.nbad != 0 || len(a.held) != 2 {
		t.Fatalf("good routes: %d faults %v, held %d", a.nbad, a.bad, len(a.held))
	}
	feed(injected(tbl.prefix(6), ownComms))
	feed(injected(netip.MustParsePrefix("192.0.2.0/23"), goodComms...))
	if a.nbad != 3 || !strings.Contains(a.bad[0], "NO_EXPORT") || !strings.Contains(a.bad[1], "192.0.2.0/23 is not a prefix") ||
		!strings.Contains(a.bad[2], "more than max_improvements 3") {
		t.Fatalf("faults %d %q", a.nbad, a.bad)
	}
	before := time.Now()
	feed(withdrawal(v4))
	if _, ok := a.since(v4); ok || a.withdrawnAt(v4).Before(before) {
		t.Fatal("withdraw not recorded")
	}
	if a.peak != 4 {
		t.Fatalf("peak %d, want 4", a.peak)
	}
	a.end()
	if a.atClose != 3 || len(a.snapshot()) != 0 {
		t.Fatalf("at close %d, held after %d", a.atClose, len(a.snapshot()))
	}
}

// The withdraw check times Packeteer's withdraw on each session and puts
// the prefix back; a fast session that keeps the route fails the run.
func TestTimeWithdrawMeasuresEachSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tbl := newTable(v4Count + 100)
	f := &fleet{adv: newAdvertised()}
	fast := newTestRouter(t, ctx, 2, tbl, f.adv)
	slow := newTestRouter(t, ctx, 3, tbl, f.adv)
	f.routers = []*router{fast, slow}
	const i = 7
	p := tbl.prefix(i)
	// Packeteer's side: withdraw its route a while after the router
	// withdraws the prefix, or never.
	replyAfter := func(s *fakeSpeaker, d time.Duration) {
		go func() {
			for !waitFor(ctx, time.Second, func() bool { _, w := s.routes(); return slices.Contains(w, p) }) {
				if ctx.Err() != nil {
					return
				}
			}
			time.Sleep(d)
			_ = writeMsg(s.c, withdrawal(p))
		}()
	}
	sf, ss := acceptFake(t, fast), acceptFake(t, slow)
	for _, s := range []*fakeSpeaker{sf, ss} {
		if err := writeMsg(s.c, injected(p, goodComms...)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "routes held", func() bool {
		_, a := fast.out.since(p)
		_, b := slow.out.since(p)
		return a && b
	})
	replyAfter(sf, 30*time.Millisecond)
	replyAfter(ss, 150*time.Millisecond)
	var lat latencies
	var fails []string
	fail := func(format string, a ...any) { fails = append(fails, fmt.Sprintf(format, a...)) }
	timeWithdraw(f, p, i, slow.id, 5*time.Second, &lat, fail)
	if len(fails) != 0 || lat.checks != 1 || len(lat.fast) != 1 || len(lat.slow) != 1 {
		t.Fatalf("fails %v, checks %d, fast %v, slow %v", fails, lat.checks, lat.fast, lat.slow)
	}
	if lat.fast[0] < 30 || lat.fast[0] > 2000 || lat.slow[0] < 150 {
		t.Fatalf("fast %.1fms, slow %.1fms", lat.fast[0], lat.slow[0])
	}
	if f.adv.withdrawn(i) {
		t.Fatal("prefix not announced again")
	}
	eventually(t, "announced again", func() bool { a, _ := sf.routes(); return slices.Contains(a, p) })

	// A fast session that never withdraws fails; a slow one is counted.
	for _, s := range []*fakeSpeaker{sf, ss} {
		if err := writeMsg(s.c, injected(p, goodComms...)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "routes held again", func() bool {
		_, a := fast.out.since(p)
		_, b := slow.out.since(p)
		return a && b
	})
	lat = latencies{}
	timeWithdraw(f, p, i, slow.id, 300*time.Millisecond, &lat, fail)
	if len(fails) != 1 || !strings.Contains(fails[0], "session 2 still had") || lat.slowLate != 1 {
		t.Fatalf("fails %v, slow late %d", fails, lat.slowLate)
	}
}

// pickInjected picks only IPv4 entries every fast session has held long
// enough, and falls back to the slow session when no fast one is up.
func TestPickInjectedNeedsAgeOnEveryFastSession(t *testing.T) {
	tbl := newTable(v4Count + 100)
	f := &fleet{adv: newAdvertised()}
	for id := range 3 {
		f.routers = append(f.routers, &router{id: id, out: newAdjOut()})
	}
	now := time.Now()
	old, young := now.Add(-time.Minute), now.Add(-time.Second)
	hold := func(id int, i int, at time.Time) { f.routers[id].out.held[tbl.prefix(i)] = at }
	// Entry 1 is old on both fast sessions; 2 is young on one; 3 is
	// missing on one; v4Count+1 is IPv6 (churned); 4 is withdrawn.
	for _, id := range []int{0, 1} {
		hold(id, 1, old)
		hold(id, v4Count+1, old)
		hold(id, 4, old)
	}
	hold(0, 2, old)
	hold(1, 2, young)
	hold(0, 3, old)
	hold(2, 9, old)
	f.adv.mark(4, 5, true)
	rng := rand.New(rand.NewPCG(1, 1))
	for _, r := range f.routers {
		r.up.Store(true)
	}
	for range 50 {
		if i, ok := pickInjected(f, tbl, 2, rng, now); !ok || i != 1 {
			t.Fatalf("picked %d %v, want entry 1", i, ok)
		}
	}
	f.routers[0].up.Store(false)
	f.routers[1].up.Store(false)
	if i, ok := pickInjected(f, tbl, 2, rng, now); !ok || i != 9 {
		t.Fatalf("slow only: picked %d %v, want entry 9", i, ok)
	}
	f.routers[2].up.Store(false)
	if _, ok := pickInjected(f, tbl, 2, rng, now); ok {
		t.Fatal("picked with no session up")
	}
}

// The flapper takes turns over the fast sessions, never the slow one, and
// waits for each to come back.
func TestFlapperSkipsSlowSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tbl := newTable(v4Count + 100)
	f := &fleet{adv: newAdvertised()}
	var mu sync.Mutex
	opened := map[int]int{}
	redialErr := make(chan error, 3)
	for id := range 3 {
		rt := newTestRouter(t, ctx, id, tbl, f.adv)
		f.routers = append(f.routers, rt)
		s := acceptFake(t, rt)
		opened[id]++
		go rt.serve(ctx, make(chan struct{}))
		// Packeteer reconnects after each flap.
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-s.end:
				}
				if ctx.Err() != nil {
					return
				}
				ns, err := tryDial(rt)
				if err != nil {
					redialErr <- err
					return
				}
				s = ns
				mu.Lock()
				opened[rt.id]++
				mu.Unlock()
			}
		}()
	}
	var st flapStats
	var fails []string
	fctx, stop := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer stop()
	flapper(fctx, f, 200*time.Millisecond, 2, &st, func(format string, a ...any) { fails = append(fails, fmt.Sprintf(format, a...)) })
	select {
	case err := <-redialErr:
		t.Fatalf("reconnect: %v", err)
	default:
	}
	mu.Lock()
	defer mu.Unlock()
	if len(fails) != 0 || st.flaps < 2 || opened[0] < 2 || opened[1] < 2 || opened[2] != 1 {
		t.Fatalf("fails %v, flaps %d, sessions opened %v", fails, st.flaps, opened)
	}
	if f.drops() != 0 {
		t.Fatalf("%d drops", f.drops())
	}
}

func TestSameRoutesComparesFastSessions(t *testing.T) {
	f := &fleet{}
	for id := range 3 {
		r := &router{id: id, out: newAdjOut()}
		r.up.Store(true)
		f.routers = append(f.routers, r)
	}
	now := time.Now()
	a, b := netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.2/32")
	f.routers[0].out.held[a] = now
	f.routers[1].out.held[a] = now.Add(time.Second)
	f.routers[2].out.held[b] = now // the slow session may lag
	if n, err := sameRoutes(context.Background(), f, 2, 200*time.Millisecond); err != nil || n != 1 {
		t.Fatalf("%d %v", n, err)
	}
	f.routers[1].out.held[b] = now
	if _, err := sameRoutes(context.Background(), f, 2, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "session 0 holds 1") {
		t.Fatalf("differing sessions: %v", err)
	}
}

func TestLoopWatchGapsAndLockWait(t *testing.T) {
	var w loopWatch
	t0 := time.Now()
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	w.sample(at(0), 10, 1, at(-2))
	w.sample(at(10), 20, 2, at(9))
	w.sample(at(20), 20, 2.5, at(19))
	w.sample(at(30), 20, 2.5, at(5)) // decide stuck since t=5
	w.sample(at(40), 30, 7, at(39))
	if w.probeGap != 30 {
		t.Fatalf("probe gap %v, want 30 (no new commit from t=10 to t=40)", w.probeGap)
	}
	if w.decideGap != 25 {
		t.Fatalf("decide gap %v, want 25", w.decideGap)
	}
	if got := w.waitRate(); got != 6.0/40 {
		t.Fatalf("lock wait %v", got)
	}
	if w.waitMax != 0.45 {
		t.Fatalf("worst lock wait %v, want 0.45 (4.5s over 10s)", w.waitMax)
	}
}

func TestThrottleReadsAtRate(t *testing.T) {
	src := bytes.NewReader(make([]byte, 4096))
	th := &throttle{r: src, bps: 8192}
	t0 := time.Now()
	buf := make([]byte, 4096)
	n := 0
	for n < len(buf) {
		k, err := th.Read(buf[n:])
		if err != nil {
			t.Fatal(err)
		}
		if k > 8192/4 {
			t.Fatalf("read %d bytes at once", k)
		}
		n += k
	}
	if d := time.Since(t0); d < 200*time.Millisecond {
		t.Fatalf("4096 bytes at 8192 B/s took %s", d)
	}
}

func TestMultiProfilesGenerateInjectConfig(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sessions int
	}{{"multi-smoke", 2}, {"multi2", 2}, {"multi4", 4}} {
		p, err := loadProfile("budgets.yaml", tc.name)
		if err != nil {
			t.Fatal(err)
		}
		if p.Sessions != tc.sessions || p.Inject == 0 || p.FlapEvery == 0 || p.SlowPeerBPS == 0 || p.VIPTargets == 0 || p.OutageTargets == 0 ||
			p.Budgets.LoopGapSecs != 3*probeInterval.Seconds() {
			t.Fatalf("%s: %+v", tc.name, p)
		}
		if tc.name != "multi-smoke" && p.Prefixes != 1000000 {
			t.Fatalf("%s: %d prefixes, want 1M per session", tc.name, p.Prefixes)
		}
		text := packeteerConfig(p, ports{BGP: 11179, Flow: 12055, HTTP: 18081}, "/var/lib/packeteer")
		cfg, err := config.Parse([]byte(text))
		if err != nil {
			t.Fatalf("%s: %v\n%s", tc.name, err, text)
		}
		if cfg.Mode != config.ModeInject || cfg.MaxImprovements == nil || *cfg.MaxImprovements != p.Inject || len(cfg.BGP.Neighbors) != tc.sessions {
			t.Fatalf("%s: mode %s, cap %v, %d neighbors", tc.name, cfg.Mode, cfg.MaxImprovements, len(cfg.BGP.Neighbors))
		}
		seen := map[string]bool{}
		for _, n := range cfg.BGP.Neighbors {
			if seen[n.Address] {
				t.Fatalf("%s: neighbor %s twice", tc.name, n.Address)
			}
			seen[n.Address] = true
		}
		if allow := cfg.Allowlist.Prefixes; !slices.Equal(allow, []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"}) {
			t.Fatalf("%s: allowlist %v", tc.name, allow)
		}
		types := map[string]bool{}
		for _, s := range cfg.Sources {
			types[s.Type] = true
		}
		if !types["vip"] || !types["outage"] || !types["static"] || !types["flow"] {
			t.Fatalf("%s: sources %v", tc.name, types)
		}
		if got := strings.Count(text, "loss_pct: 100"); got != p.OutageTargets {
			t.Fatalf("%s: %d lossy paths, want %d", tc.name, got, p.OutageTargets)
		}
		tbl := newTable(p.Prefixes)
		v4 := 0
		for _, i := range staticTargets(p, tbl) {
			if i < v4Count {
				v4++
			}
		}
		if v4 < v4Targets {
			t.Fatalf("%s: %d IPv4 static targets, want at least %d for the withdraw check", tc.name, v4, v4Targets)
		}
	}
	// Observe profiles keep their single session and no inject block.
	p, err := loadProfile("budgets.yaml", "pr")
	if err != nil {
		t.Fatal(err)
	}
	text := packeteerConfig(p, ports{BGP: 11179, Flow: 12055, HTTP: 18081}, "/var/lib/packeteer")
	if strings.Count(text, "- address:") != 1 || strings.Contains(text, "announcer:") || strings.Contains(text, "local_pref") ||
		strings.Contains(text, "type: vip") || strings.Contains(text, "type: outage") {
		t.Fatalf("pr config changed:\n%s", text)
	}
}

func TestMultiProfileValidation(t *testing.T) {
	base, err := loadProfile("budgets.yaml", "multi-smoke")
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*Profile){
		"five sessions":             func(p *Profile) { p.Sessions = 5 },
		"flap on one session":       func(p *Profile) { p.Sessions, p.SlowPeerBPS = 1, 0 },
		"slow peer on one session":  func(p *Profile) { p.Sessions, p.FlapEvery = 1, 0 },
		"slow peer too slow":        func(p *Profile) { p.SlowPeerBPS = 100 },
		"cap over max_improvements": func(p *Profile) { p.Inject = 10001 },
		"outage over static":        func(p *Profile) { p.OutageTargets = p.StaticTargets + 1 },
		"outage under min_prefixes": func(p *Profile) { p.OutageTargets = 2 },
		"negative flap":             func(p *Profile) { p.FlapEvery = -time.Second },
	} {
		p := base
		mod(&p)
		if p.validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := base.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestReportShowsInjectRowsAndLoopGap(t *testing.T) {
	r := Result{Profile: "multi-smoke", Prefixes: 20000, Mode: "inject", Sessions: 2, Failures: []string{},
		DecideMaxGapSecs: 120, ProbeMaxGapSecs: 4, WithdrawP99Ms: 45.7, SlowWithdrawMaxMs: 7187}
	text, ok := report(r, Budgets{LoopGapSecs: 90})
	if ok {
		t.Fatal("a decide loop gap over the budget passed")
	}
	for _, want := range []string{"on 2 session(s)", "Inject mode", "| decide loop, longest gap | 120 s |", "**OVER**",
		"| probe loop, longest gap | 4 s |", "| withdraw latency p99, fast sessions | 45.7 ms |", "slow session | 7187 ms |", "Withdraw checks"} {
		if !strings.Contains(text, want) {
			t.Fatalf("report lacks %q:\n%s", want, text)
		}
	}
	obs, ok := report(Result{Profile: "pr", Prefixes: 1250000, Failures: []string{}}, Budgets{})
	if !ok || strings.Contains(obs, "withdraw latency") || strings.Contains(obs, "flap") || !strings.Contains(obs, "Observe mode") {
		t.Fatalf("observe report:\n%s", obs)
	}
}

// Every pull request runs the short multi-session profile; the 1M
// profiles run weekly, multi4 only on a configured large runner.
func TestMultiWorkflows(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile("../../.github/workflows/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	ci, lm, soak := read("ci.yml"), read("load-multi.yml"), read("soak.yml")
	if !strings.Contains(ci, "bash lab/soak.sh packeteer:ci multi-smoke\n") || strings.Contains(ci, "multi2") || strings.Contains(ci, "multi4") {
		t.Fatal("ci.yml must run multi-smoke and not the 1M multi-session profiles")
	}
	if !strings.Contains(lm, "bash lab/soak.sh packeteer:multi multi2\n") || !strings.Contains(lm, "bash lab/soak.sh packeteer:multi multi4\n") ||
		!strings.Contains(lm, "vars.LARGE_RUNNER") || strings.Contains(lm, "pull_request") {
		t.Fatal("load-multi.yml must run multi2, and multi4 on a configured runner, and not on pull requests")
	}
	if strings.Contains(soak, "multi") {
		t.Fatal("soak.yml names a multi-session profile")
	}
}
