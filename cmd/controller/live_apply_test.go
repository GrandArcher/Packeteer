package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// liveApplyConfig has outbound, inbound, and mitigation configured. The
// three modes, hold_time, and improvement_ttl are the knobs the tests turn.
func liveApplyConfig(port int, mode, hold, ttl string) string {
	return fmt.Sprintf(`mode: %[2]s
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: %[3]s
improvement_ttl: %[4]s
thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}
http: {listen: ""}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["203.0.113.0/24"]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %[1]d, local_address: 127.0.0.2}
announcer: {type: gobgp}
inbound:
  mode: %[2]s
  prefixes: [203.0.113.0/24]
  performance: {}
  damping: {disabled: true}
  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - {provider: transit-a, communities: ["64512:1102"]}
        - {provider: transit-b, communities: ["64512:1202"]}
mitigation:
  mode: %[2]s
  allowlist: [198.51.100.0/24]
  max_rules: 2
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole: {next_hop: 192.0.2.66}
`, port, mode, hold, ttl)
}

// Observe to inject to observe to inject with inbound and mitigation
// configured (#233), against a simulated edge. Entering inject binds both
// announcers on the running speaker, leaving it withdraws both, and
// hold_time and improvement_ttl reach the inbound controller without a
// restart.
func TestReloadInboundMitigationLiveApply(t *testing.T) {
	edge, port := edgeRouter(t)
	ctx := context.Background()
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: "198.51.100.0", PrefixLen: 24})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	if _, err := edge.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(mode, hold, ttl string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(liveApplyConfig(port, mode, hold, ttl)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("observe", "5m", "1h")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	mit, err := newMitigation(cfg, plugins, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := setMitigationRIB(mit, view); err != nil {
		t.Fatal(err)
	}
	var ctl *announce.Controller
	inb, err := newInbound(cfg, plugins, view, func() int { return ctl.Active() }, mit, func(netip.Prefix) bool { return false }, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err = newController(cfg, plugins, view, inb, mit, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = view.Stop(context.Background()) })
	ctl.RememberSpeaker(view.Server())
	for _, p := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		waitFor(t, p+" learned", func() bool { _, ok := view.Exact(netip.MustParsePrefix(p)); return ok })
	}

	rl := &reloader{
		path: path, getenv: noEnv, log: log, cur: cfg, view: view, rib: view, ctl: ctl,
		decider: decider, plugins: plugins, inb: inb, mit: mit,
		opts: pluginhost.Options{Logger: log, Getenv: noEnv},
	}
	reload := func(want ...string) {
		t.Helper()
		applied, refused, fatal := rl.reload(ctx)
		if refused != nil || fatal != nil {
			t.Fatalf("reload: refused %v fatal %v", refused, fatal)
		}
		for _, k := range want {
			if !slices.Contains(applied, k) {
				t.Fatalf("applied = %v, want %s", applied, k)
			}
		}
	}

	victim := netip.MustParsePrefix("198.51.100.0/24")
	now := time.Now()
	round := func(at time.Time, usageIn float64) {
		t.Helper()
		in := []plugin.Usage{
			{Provider: "transit-a", CommitMbps: 100, Samples: 10, InMbps95: usageIn, OutMbps95: 10, Updated: at},
			{Provider: "transit-b", CommitMbps: 100, Samples: 10, InMbps95: 20, OutMbps95: 10, Updated: at},
		}
		inb.Evaluate(at, in)
		if err := inb.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		if err := mit.Sync(ctx, at); err != nil {
			t.Fatal(err)
		}
	}
	steerOnEdge := func() bool { return steerFromPacketeer(t, edge) != nil }
	blackholeOnEdge := func() bool { _, _, ok := packeteerPath(t, edge, victim.String()); return ok }
	never := func(what string, f func() bool) {
		t.Helper()
		time.Sleep(300 * time.Millisecond)
		if f() {
			t.Fatalf("%s reached the edge", what)
		}
	}

	// observe: a steer is planned and a rule is held, and neither is sent.
	if _, err := mit.Add(mitigation.Request{Prefix: victim, Action: plugin.MitigationBlackhole}, now); err != nil {
		t.Fatal(err)
	}
	round(now, 150)
	if st := inb.Status(); len(st.Steers) != 1 || st.Steers[0].Hold != 5*time.Minute {
		t.Fatalf("observe steers = %+v", st.Steers)
	}
	never("an observe steer", steerOnEdge)
	never("an observe rule", blackholeOnEdge)

	// observe -> inject, with a shorter hold_time in the same file. The
	// dry-run rule is dropped, not promoted; the planned steer goes out.
	write("inject", "2m", "1h")
	reload("mode", "inbound.mode", "mitigation.mode", "hold_time")
	if st := mit.Status(); st.Mode != config.ModeInject || len(st.Rules) != 0 {
		t.Fatalf("mitigation after entering inject: %+v", st)
	}
	round(now.Add(time.Second), 150)
	waitFor(t, "steer on the edge", steerOnEdge)
	comms := steerFromPacketeer(t, edge)
	for _, c := range []uint32{64512<<16 | 666, 64512<<16 | 667, 64512<<16 | 1102, 0xFFFFFF01} {
		if !comms[c] {
			t.Fatalf("steer communities = %v, missing %d", comms, c)
		}
	}
	never("a dry-run rule", blackholeOnEdge)
	if _, err := mit.Add(mitigation.Request{Prefix: victim, Action: plugin.MitigationBlackhole}, now); err != nil {
		t.Fatal(err)
	}
	round(now.Add(2*time.Second), 150)
	waitFor(t, "blackhole on the edge", blackholeOnEdge)
	if nhop, _, _ := packeteerPath(t, edge, victim.String()); nhop != "192.0.2.66" {
		t.Fatalf("blackhole next hop = %s", nhop)
	}
	if inb.Active() != 1 || mit.Active() != 1 {
		t.Fatalf("on the wire: inbound %d mitigation %d", inb.Active(), mit.Active())
	}

	// A shorter improvement_ttl retires the running steer; the next steer
	// takes the new hold_time. Neither needs a restart.
	write("inject", "30s", "1m")
	reload("hold_time", "improvement_ttl")
	later := now.Add(3 * time.Minute)
	round(later, 150)
	waitFor(t, "steer retired by the new ttl", func() bool { return !steerOnEdge() })
	round(later.Add(time.Second), 150)
	waitFor(t, "steer again", steerOnEdge)
	if st := inb.Status(); len(st.Steers) != 1 || st.Steers[0].Hold != 30*time.Second {
		t.Fatalf("steer after the hold_time reload = %+v", st.Steers)
	}

	// inject -> observe withdraws both under their locks. Nothing is
	// announced again while observing.
	write("observe", "30s", "1m")
	reload("mode", "inbound.mode", "mitigation.mode")
	waitFor(t, "steer withdrawn", func() bool { return !steerOnEdge() })
	waitFor(t, "blackhole withdrawn", func() bool { return !blackholeOnEdge() })
	if inb.Active() != 0 || mit.Active() != 0 || ctl.Active() != 0 {
		t.Fatalf("after leaving inject: inbound %d mitigation %d outbound %d", inb.Active(), mit.Active(), ctl.Active())
	}
	round(later.Add(2*time.Second), 150)
	never("a steer in observe", steerOnEdge)
	never("a rule in observe", blackholeOnEdge)

	// And in again: the announcers are already bound, which must not fail.
	write("inject", "30s", "1m")
	reload("mode", "inbound.mode", "mitigation.mode")
	round(later.Add(3*time.Second), 150)
	waitFor(t, "steer after re-entering inject", steerOnEdge)
	if _, err := mit.Add(mitigation.Request{Prefix: victim, Action: plugin.MitigationBlackhole}, later); err != nil {
		t.Fatal(err)
	}
	round(later.Add(4*time.Second), 150)
	waitFor(t, "blackhole after re-entering inject", blackholeOnEdge)

	// A shutdown still withdraws everything.
	if err := errors.Join(mit.WithdrawAll(ctx), inb.WithdrawAll(ctx), ctl.WithdrawAll(ctx)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "steer and blackhole withdrawn", func() bool { return !steerOnEdge() && !blackholeOnEdge() })
}

// inbound.mode and mitigation.mode apply online; any other change to either
// block, or the block appearing or disappearing, stays a restart.
func TestClassifyInboundMitigationMode(t *testing.T) {
	base := liveApplyConfig(179, "observe", "5m", "1h")
	cur := mustParse(t, base)
	swap := func(pairs ...string) *config.Config {
		t.Helper()
		y := base
		for i := 0; i < len(pairs); i += 2 {
			if !strings.Contains(y, pairs[i]) {
				t.Fatalf("no %q in the test config", pairs[i])
			}
			y = strings.Replace(y, pairs[i], pairs[i+1], 1)
		}
		return mustParse(t, y)
	}
	cases := []struct {
		name        string
		next        *config.Config
		restart, on []string
	}{
		{"same", cur, nil, nil},
		{"inbound mode", swap("inbound:\n  mode: observe", "inbound:\n  mode: suggest"), nil, []string{"inbound.mode"}},
		{"mitigation mode", swap("mode: observe\nasn", "mode: inject\nasn", "mitigation:\n  mode: observe", "mitigation:\n  mode: inject"), nil, []string{"mitigation.mode", "mode"}},
		{"inbound prefixes", swap("prefixes: [203.0.113.0/24]", "prefixes: [203.0.113.0/25]"), []string{"inbound"}, nil},
		{"mitigation allowlist", swap("allowlist: [198.51.100.0/24]", "allowlist: [198.51.100.0/25]"), []string{"mitigation"}, nil},
		{"mitigation cap with mode", swap("max_rules: 2", "max_rules: 3"), []string{"mitigation"}, nil},
		{"hold_time", swap("hold_time: 5m", "hold_time: 1m"), nil, []string{"hold_time"}},
	}
	for _, tc := range cases {
		restart, online := classify(cur, tc.next)
		if !slices.Equal(restart, tc.restart) || !slices.Equal(online, tc.on) {
			t.Errorf("%s: restart %v online %v, want %v %v", tc.name, restart, online, tc.restart, tc.on)
		}
	}
	// A mode change next to another block change is refused whole.
	both := swap("mode: observe\nasn", "mode: inject\nasn", "mitigation:\n  mode: observe", "mitigation:\n  mode: inject", "max_rules: 2", "max_rules: 3")
	if restart, _ := classify(cur, both); !slices.Equal(restart, []string{"mitigation"}) {
		t.Errorf("mode with a cap change: restart %v", restart)
	}
	// The block cannot appear or go away online.
	noInbound := mustParse(t, base[:strings.Index(base, "inbound:\n")])
	if restart, _ := classify(noInbound, cur); !slices.Contains(restart, "inbound") || !slices.Contains(restart, "mitigation") {
		t.Errorf("blocks added: restart %v", restart)
	}
	if restart, _ := classify(cur, noInbound); !slices.Contains(restart, "inbound") || !slices.Contains(restart, "mitigation") {
		t.Errorf("blocks removed: restart %v", restart)
	}
}

// The sessions negotiate FlowSpec only at start, so mitigation cannot
// start injecting a FlowSpec catalog online. Without an iBGP session it
// cannot bind at all. Both are refused before any mode changes.
func TestReloadMitigationInjectRefusals(t *testing.T) {
	observe := strings.Replace(liveApplyConfig(179, "observe", "5m", "1h"),
		"blackhole: {next_hop: 192.0.2.66}",
		"blackhole: {next_hop: 192.0.2.66}\n      flowspec:\n        redirect:\n          - {name: scrub-vrf, route_target: \"64512:777\"}", 1)
	cur := mustParse(t, observe)
	next := mustParse(t, strings.NewReplacer("mode: observe", "mode: inject").Replace(observe))
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugins, err := pluginhost.Build(cur, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	mit, err := newMitigation(cur, plugins, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := mit.SetRIB(ribGate{}); err != nil {
		t.Fatal(err)
	}
	pc, err := policyConfig(next)
	if err != nil {
		t.Fatal(err)
	}
	online := []string{"mitigation.mode"}
	rl := &reloader{cur: cur, plugins: plugins, mit: mit}
	if err := rl.prepareSteering(next, pc, online); err == nil || !strings.Contains(err.Error(), "restart required") {
		t.Fatalf("flowspec catalog, sessions without it: %v", err)
	}
	rl.flowSpecUp = true
	if err := rl.prepareSteering(next, pc, online); err == nil || !strings.Contains(err.Error(), "iBGP session") {
		t.Fatalf("no speaker: %v", err)
	}
	if mit.Status().Mode != config.ModeObserve {
		t.Fatal("a refused prepare changed the mode")
	}
}

func TestRunStepsPartialApplyIsFatal(t *testing.T) {
	boom := errors.New("withdraw failed")
	var ran []int
	step := func(n int, err error) func() error {
		return func() error { ran = append(ran, n); return err }
	}
	err := runSteps([]func() error{step(0, boom), step(1, nil)})
	if !errors.Is(err, boom) || errors.Is(err, errPartialApply) || !slices.Equal(ran, []int{0}) {
		t.Fatalf("first step failed: err %v ran %v", err, ran)
	}
	ran = nil
	err = runSteps([]func() error{step(0, nil), step(1, boom), step(2, nil)})
	if !errors.Is(err, boom) || !errors.Is(err, errPartialApply) || !slices.Equal(ran, []int{0, 1}) {
		t.Fatalf("later step failed: err %v ran %v", err, ran)
	}
	if err := runSteps([]func() error{step(0, nil)}); err != nil {
		t.Fatal(err)
	}
}
