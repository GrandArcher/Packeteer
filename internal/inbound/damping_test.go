package inbound

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var damped = Damping{Confirm: 2 * time.Minute, Backoff: 2, MaxHold: 40 * time.Minute}

func threeProviders(mode string, d Damping) Config {
	cfg := baseConfig(mode)
	cfg.Providers = []string{"transit-a", "transit-b", "transit-c"}
	cfg.TTL = 0
	cfg.Damping = d
	return cfg
}

// commitNetwork is a simulated network whose inbound traffic moves when
// Packeteer steers: steering away from transit-a shifts 200 Mbps of its
// inbound traffic to transit-b and transit-c. Every commit is 450 Mbps.
type commitNetwork struct{ demandA float64 }

func (n commitNetwork) usage(now time.Time, steered map[string]bool) []plugin.Usage {
	a, b, c := n.demandA, 300.0, 200.0
	if steered["transit-a"] {
		a, b, c = a-200, b+100, c+100
	}
	var out []plugin.Usage
	for p, in := range map[string]float64{"transit-a": a, "transit-b": b, "transit-c": c} {
		out = append(out, plugin.Usage{Provider: p, CommitMbps: 450, Samples: 10, InMbps95: in, Updated: now})
	}
	return out
}

func steeredSet(c *Controller) map[string]bool {
	out := map[string]bool{}
	for _, s := range c.Status().Steers {
		out[s.Provider] = true
	}
	return out
}

// simulateCommit runs one decision a minute for a day, lowering transit-a's
// demand at noon so that it fits its commit even unsteered. It returns the
// steer/release transitions and whether transit-a is steered at the end.
func simulateCommit(t *testing.T, d Damping) (int, bool) {
	t.Helper()
	ann := newFakeAnn("transit-a", "transit-b", "transit-c")
	c := mustNew(t, threeProviders(config.ModeInject, d), ann, readyRIB())
	net := commitNetwork{demandA: 500}
	transitions := 0
	for i := 0; i < 24*60; i++ {
		now := start.Add(time.Duration(i) * time.Minute)
		if i == 12*60 {
			net.demandA = 350
		}
		transitions += len(c.Evaluate(now, net.usage(now, steeredSet(c))))
		if err := c.Sync(context.Background()); err != nil {
			t.Fatal(err)
		}
		if on := len(ann.routes) > 0; on != steeredSet(c)["transit-a"] {
			t.Fatalf("minute %d: steer set and wire disagree: %v %v", i, steeredSet(c), ann.routes)
		}
	}
	return transitions, steeredSet(c)["transit-a"]
}

// Steering transit-a brings it under release_pct, releasing brings it back
// over commit. Without damping Packeteer flips the edge every
// hold_time + cooldown all day. Damping learns how much traffic came back
// on the first release and keeps the steer until demand really drops.
func TestDampingPreventsCommitOscillation(t *testing.T) {
	undamped, _ := simulateCommit(t, Damping{Disabled: true})
	if undamped < 100 {
		t.Fatalf("undamped simulation made %d transitions; the model does not oscillate", undamped)
	}
	n, steeredAtEnd := simulateCommit(t, damped)
	// Steer, release, steer again (flap: inertia learned), release at noon.
	if n != 4 {
		t.Fatalf("damped simulation made %d transitions, want 4 (undamped %d)", n, undamped)
	}
	if steeredAtEnd {
		t.Fatal("transit-a still steered after its demand fell under commit")
	}
}

func TestDampingInertiaDetails(t *testing.T) {
	ann := newFakeAnn("transit-a", "transit-b", "transit-c")
	c := mustNew(t, threeProviders(config.ModeInject, damped), ann, readyRIB())
	net := commitNetwork{demandA: 500}
	step := func(now time.Time) []Change { return c.Evaluate(now, net.usage(now, steeredSet(c))) }

	if ch := step(start); len(ch) != 0 {
		t.Fatalf("steered before confirm: %+v", ch)
	}
	if st := c.Status(); len(st.Blocked) != 1 || !strings.Contains(st.Blocked[0].Reason, "confirming") {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
	now := start.Add(2 * time.Minute)
	ch := step(now)
	if len(ch) != 1 || ch[0].Steer.Trigger != TriggerCommit || ch[0].Steer.Hold != 5*time.Minute || ch[0].Steer.Flaps != 0 {
		t.Fatalf("first steer = %+v", ch)
	}
	now = now.Add(5 * time.Minute)
	if ch := step(now); len(ch) != 1 || ch[0].Action != ActionRelease {
		t.Fatalf("release = %+v", ch)
	}
	// Back over commit; confirm runs during the 5m cooldown.
	now = now.Add(time.Minute)
	step(now)
	now = now.Add(4 * time.Minute)
	ch = step(now)
	if len(ch) != 1 || ch[0].Steer.Flaps != 1 || ch[0].Steer.Hold != 10*time.Minute || ch[0].Steer.Shift != 200 {
		t.Fatalf("second steer = %+v", ch)
	}
	now = now.Add(30 * time.Minute)
	if ch := step(now); len(ch) != 0 {
		t.Fatalf("inertia did not hold the steer: %+v", ch)
	}
	st := c.Status()
	if len(st.Steers) != 1 || st.Steers[0].Shift != 200 || len(st.Blocked) != 1 || !strings.Contains(st.Blocked[0].Reason, "inertia") {
		t.Fatalf("status = %+v", st)
	}
}

func TestDampingBackoffCapsAtMaxHold(t *testing.T) {
	c := mustNew(t, perfConfig(config.ModeObserve, Damping{Backoff: 2, MaxHold: 12 * time.Minute}), nil, nil)
	bad := map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": 150}
	good := map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": 30}
	now := start
	var holds []time.Duration
	for i := 0; i < 4; i++ {
		ch := c.Plan(now, Input{Paths: paths(now, bad, nil)})
		if len(ch) != 1 || ch[0].Action != ActionSteer {
			t.Fatalf("round %d steer = %+v", i, ch)
		}
		holds = append(holds, ch[0].Steer.Hold)
		now = now.Add(ch[0].Steer.Hold)
		if ch := c.Plan(now, Input{Paths: paths(now, good, nil)}); len(ch) != 1 {
			t.Fatalf("round %d release = %+v", i, ch)
		}
		now = now.Add(ch[0].Steer.Hold)
	}
	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 12 * time.Minute, 12 * time.Minute}
	if fmt.Sprint(holds) != fmt.Sprint(want) {
		t.Fatalf("holds = %v, want %v", holds, want)
	}
	// Quiet for longer than the flap window: back to hold_time.
	now = now.Add(time.Hour)
	ch := c.Plan(now, Input{Paths: paths(now, bad, nil)})
	if len(ch) != 1 || ch[0].Steer.Hold != 5*time.Minute || ch[0].Steer.Flaps != 0 {
		t.Fatalf("after quiet period = %+v", ch)
	}
}

func perfConfig(mode string, d Damping) Config {
	cfg := threeProviders(mode, d)
	cfg.Performance = &PerfConfig{LossPct: 5, LatencyMs: 50, MinPrefixes: 3, ReleasePct: 50}
	cfg.PerfMaxAge = 5 * time.Minute
	return cfg
}

var targets = []netip.Prefix{
	netip.MustParsePrefix("198.51.100.0/25"),
	netip.MustParsePrefix("198.51.100.128/25"),
	netip.MustParsePrefix("192.0.2.0/25"),
	netip.MustParsePrefix("192.0.2.128/25"),
}

// paths is every provider measured toward every target, with the given
// RTT and loss per provider.
func paths(now time.Time, rttMs map[string]float64, loss map[string]float64) []Path {
	var out []Path
	for p, rtt := range rttMs {
		for _, t := range targets {
			out = append(out, Path{Provider: p, Prefix: t, RTT: time.Duration(rtt * float64(time.Millisecond)), LossPct: loss[p], Time: now})
		}
	}
	return out
}

func TestPerformanceSteersWorstProvider(t *testing.T) {
	ann := newFakeAnn("transit-a", "transit-b", "transit-c")
	c := mustNew(t, perfConfig(config.ModeInject, Damping{Disabled: true}), ann, readyRIB())
	ctx := context.Background()
	good := map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": 30}
	bad := map[string]float64{"transit-a": 20, "transit-b": 90, "transit-c": 150}

	if ch := c.Plan(start, Input{Paths: paths(start, good, nil)}); len(ch) != 0 {
		t.Fatalf("steered with no gap: %+v", ch)
	}
	// Two providers are over the threshold; only the worst is steered.
	ch := c.Plan(start, Input{Paths: paths(start, bad, nil)})
	if len(ch) != 1 || ch[0].Steer.Provider != "transit-c" || ch[0].Steer.Trigger != TriggerPerformance {
		t.Fatalf("steer = %+v", ch)
	}
	if g := ch[0].Steer.Perf; g == nil || g.RTTGapMs != 130 || g.Prefixes != len(targets) {
		t.Fatalf("gap = %+v", ch[0].Steer.Perf)
	}
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 1 || strings.Join(ann.routes[own].Away, ",") != "transit-c" {
		t.Fatalf("announce: %v %+v", err, ann.routes)
	}
	now := start.Add(time.Minute)
	if ch := c.Plan(now, Input{Paths: paths(now, bad, nil)}); len(ch) != 0 {
		t.Fatalf("second performance steer: %+v", ch)
	}
	// Gap 40 ms is under the 50 ms threshold but over 50% of it: held.
	now = start.Add(10 * time.Minute)
	if ch := c.Plan(now, Input{Paths: paths(now, map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": 60}, nil)}); len(ch) != 0 {
		t.Fatalf("released above release_pct: %+v", ch)
	}
	now = now.Add(time.Minute)
	if ch := c.Plan(now, Input{Paths: paths(now, good, nil)}); len(ch) != 1 || ch[0].Action != ActionRelease {
		t.Fatalf("release = %+v", ch)
	}
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 {
		t.Fatalf("withdraw: %v %+v", err, ann.routes)
	}
}

func TestPerformanceLossAndFailClosed(t *testing.T) {
	c := mustNew(t, perfConfig(config.ModeSuggest, Damping{Disabled: true}), nil, nil)
	rtt := map[string]float64{"transit-a": 20, "transit-b": 20, "transit-c": 20}
	ch := c.Plan(start, Input{Paths: paths(start, rtt, map[string]float64{"transit-b": 100})})
	if len(ch) != 1 || ch[0].Steer.Provider != "transit-b" || ch[0].Steer.Perf.LossGap != 100 {
		t.Fatalf("steer on total loss = %+v", ch)
	}
	// transit-b's probe source goes down: no fresh result, release at once.
	now := start.Add(time.Minute)
	var ps []Path
	for _, p := range paths(now, rtt, nil) {
		if p.Provider != "transit-b" {
			ps = append(ps, p)
		}
	}
	ch = c.Plan(now, Input{Paths: ps})
	if len(ch) != 1 || ch[0].Action != ActionRelease || !strings.Contains(ch[0].Reason, "stale") {
		t.Fatalf("release on missing results = %+v", ch)
	}
	// Stale results and too few common prefixes compare nothing.
	c2 := mustNew(t, perfConfig(config.ModeSuggest, Damping{Disabled: true}), nil, nil)
	bad := map[string]float64{"transit-a": 20, "transit-b": 20, "transit-c": 200}
	if ch := c2.Plan(start.Add(time.Hour), Input{Paths: paths(start, bad, nil)}); len(ch) != 0 {
		t.Fatalf("stale results steered: %+v", ch)
	}
	if ch := c2.Plan(start, Input{Paths: paths(start, bad, nil)[:3]}); len(ch) != 0 {
		t.Fatalf("under min_prefixes steered: %+v", ch)
	}
}

func TestPerformanceNeverEveryProvider(t *testing.T) {
	cfg := perfConfig(config.ModeSuggest, Damping{Disabled: true})
	cfg.Providers = []string{"transit-a", "transit-b"}
	c := mustNew(t, cfg, nil, nil)
	// transit-a is over commit and steered; transit-b is the worst
	// performer but steering it too would cover every provider.
	u := usage(start, map[string]float64{"transit-a": 150, "transit-b": 20})
	ch := c.Plan(start, Input{Usage: u, Paths: paths(start, map[string]float64{"transit-a": 20, "transit-b": 200}, nil)})
	if len(ch) != 1 || ch[0].Steer.Provider != "transit-a" {
		t.Fatalf("changes = %+v", ch)
	}
	if st := c.Status(); len(st.Blocked) != 1 || !strings.Contains(st.Blocked[0].Reason, "every provider") {
		t.Fatalf("blocked = %+v", st.Blocked)
	}
}

// simulatePerf feeds a day of RTT that flips transit-c between good and
// bad every period and returns the transitions.
func simulatePerf(t *testing.T, d Damping, period time.Duration) int {
	t.Helper()
	c := mustNew(t, perfConfig(config.ModeObserve, d), nil, nil)
	transitions := 0
	for i := 0; i < 24*60; i++ {
		now := start.Add(time.Duration(i) * time.Minute)
		rttC := 30.0
		if (time.Duration(i)*time.Minute/period)%2 == 0 {
			rttC = 150
		}
		rtt := map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": rttC}
		transitions += len(c.Plan(now, Input{Paths: paths(now, rtt, nil)}))
	}
	return transitions
}

func TestDampingPreventsPerformanceFlap(t *testing.T) {
	// Noise: bad one minute, good the next. Confirm never lets it steer.
	if undamped := simulatePerf(t, Damping{Disabled: true}, time.Minute); undamped < 100 {
		t.Fatalf("undamped noise made %d transitions", undamped)
	}
	if n := simulatePerf(t, damped, time.Minute); n != 0 {
		t.Fatalf("damped noise made %d transitions, want 0", n)
	}
	// Slower flapping gets through confirm; backoff stretches the hold
	// toward max_hold so the edge changes far less often.
	undamped := simulatePerf(t, Damping{Disabled: true}, 6*time.Minute)
	n := simulatePerf(t, damped, 6*time.Minute)
	if n*3 > undamped || n > 80 {
		t.Fatalf("damped flapping made %d transitions, undamped %d", n, undamped)
	}
}

func TestModeratedTriggerIsNotAnnounced(t *testing.T) {
	ann := newFakeAnn("transit-a", "transit-b", "transit-c")
	cfg := perfConfig(config.ModeInject, Damping{Disabled: true})
	cfg.Moderated = map[string]bool{TriggerPerformance: true}
	c := mustNew(t, cfg, ann, readyRIB())
	ctx := context.Background()

	ch := c.Plan(start, Input{Paths: paths(start, map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": 150}, nil)})
	if len(ch) != 1 || !ch[0].Steer.Moderated {
		t.Fatalf("moderated steer = %+v", ch)
	}
	if err := c.Sync(ctx); err != nil || len(ann.routes) != 0 || ann.calls != 0 {
		t.Fatalf("moderated steer announced: %v %+v", err, ann.routes)
	}
	if st := c.Status(); len(st.Steers) != 1 || !st.Steers[0].Moderated || len(st.Announced) != 0 {
		t.Fatalf("status = %+v", st)
	}
	// A commit steer is automated: it is announced, away from transit-a only.
	now := start.Add(time.Minute)
	c.Plan(now, Input{Usage: usage(now, map[string]float64{"transit-a": 150}),
		Paths: paths(now, map[string]float64{"transit-a": 20, "transit-b": 25, "transit-c": 150}, nil)})
	if err := c.Sync(ctx); err != nil || strings.Join(ann.routes[own].Away, ",") != "transit-a" {
		t.Fatalf("automated steer: %v %+v", err, ann.routes)
	}
	if err := c.WithdrawAll(ctx); err != nil || len(ann.routes) != 0 {
		t.Fatalf("withdraw all: %v %+v", err, ann.routes)
	}
}
