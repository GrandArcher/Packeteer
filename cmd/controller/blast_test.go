package main

import (
	"bytes"
	"context"
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

	"github.com/GrandArcher/Packeteer/internal/blast"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

func blastConfig(port int, mode, allow string) string {
	return fmt.Sprintf(`mode: %s
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 5m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 10}
http: {listen: ""}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: [%s]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
`, mode, allow, port)
}

// The preview of an observe-mode controller names exactly the routes that
// reach a simulated edge after the switch to inject, and announces nothing
// before it (#227).
func TestBlastPreviewMatchesInject(t *testing.T) {
	edge, port := edgeRouter(t)
	ctx := context.Background()
	other := netip.MustParsePrefix("198.51.100.0/24")
	target := netip.MustParsePrefix("203.0.113.0/24")
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: "198.51.100.0", PrefixLen: 24})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	if _, err := edge.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(mode, allow string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(blastConfig(port, mode, allow)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("observe", `"203.0.113.0/24"`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := newController(cfg, plugins, view, nil, nil, nil, log)
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
	for _, p := range []netip.Prefix{target, other} {
		waitFor(t, p.String()+" learned", func() bool { _, ok := view.Exact(p); return ok })
	}

	live := &liveConfig{cfg: cfg}
	src := blastSource{live: live, decider: decider, ctl: ctl, view: view, plugins: plugins,
		check: candidateChecker(cfg, noEnv, "")}
	if _, err := src.Preview(nil); err != blast.ErrNoRound {
		t.Fatalf("preview before any round: %v, want ErrNoRound", err)
	}

	now := time.Now()
	round := func(at time.Time) policy.Input {
		var res []probe.Result
		for _, p := range []netip.Prefix{target, other} {
			for prov, rtt := range map[string]time.Duration{"transit-a": 80 * time.Millisecond, "transit-b": 20 * time.Millisecond} {
				res = append(res, probe.Result{Provider: prov, Prefix: p, Time: at,
					Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: rtt}})
			}
		}
		return policy.Input{Results: res, ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
			RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{target: "transit-a", other: "transit-a"}}
	}
	in := round(now)
	if _, err := runDecision(now, decider, in, ctl, log, "observe", nil); err != nil {
		t.Fatal(err)
	}
	if got := len(decider.Improvements()); got != 2 {
		t.Fatalf("observe improvements = %d, want 2 (the allowlist applies in inject only)", got)
	}

	rep, err := src.Preview(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Announces || len(rep.Add) != 1 || rep.Add[0].Prefix != target || rep.Add[0].From != "transit-a" || rep.Add[0].To != "transit-b" {
		t.Fatalf("preview add = %+v, want only %s transit-a -> transit-b", rep.Add, target)
	}
	if len(rep.Move)+len(rep.Withdraw) != 0 {
		t.Fatalf("preview move %+v withdraw %+v on an empty wire", rep.Move, rep.Withdraw)
	}
	var outside *blast.Warning
	for i, w := range rep.Warnings {
		if w.Code == blast.WarnAllowlist {
			outside = &rep.Warnings[i]
		}
	}
	if outside == nil || outside.Prefixes[0] != other.String() {
		t.Fatalf("warnings = %+v, want the allowlist warning for %s", rep.Warnings, other)
	}

	// Previewing announced nothing and changed no state.
	if _, _, ok := packeteerPath(t, edge, target.String()); ok || ctl.Active() != 0 || len(decider.Improvements()) != 2 {
		t.Fatalf("the preview changed state: on edge %v, active %d", ok, ctl.Active())
	}

	// A candidate: observe withdraws nothing from an empty wire; a wider
	// allowlist adds the second prefix.
	cand, err := src.Preview([]byte(blastConfig(port, "inject", `"203.0.113.0/24", "198.51.100.0/24"`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cand.Add) != 2 || cand.Add[0].Prefix != other || cand.Add[1].Prefix != target {
		t.Fatalf("candidate add = %+v, want both prefixes", cand.Add)
	}

	// Switch to inject for real and decide the same round again.
	write("inject", `"203.0.113.0/24"`)
	rl := &reloader{path: path, getenv: noEnv, log: log, cur: cfg, view: view, rib: view, ctl: ctl, decider: decider, plugins: plugins,
		live: live, preview: src.PreviewConfig, opts: pluginhost.Options{Logger: log, Getenv: noEnv}}
	applied, refused, fatal := rl.reload(ctx)
	if refused != nil || fatal != nil || !slices.Contains(applied, "mode") {
		t.Fatalf("reload: applied %v refused %v fatal %v", applied, refused, fatal)
	}
	if !strings.Contains(logs.String(), "blast radius") || !strings.Contains(logs.String(), "add=1") {
		t.Fatalf("the reload did not log the preview: %s", logs.String())
	}
	if _, err := runDecision(now.Add(time.Second), decider, in, ctl, log, "inject", nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "route on the edge", func() bool { _, _, ok := packeteerPath(t, edge, target.String()); return ok })
	if nhop, comms, _ := packeteerPath(t, edge, target.String()); nhop != "192.0.2.2" || !comms[64512<<16|666] {
		t.Fatalf("announced next hop %s communities %v, want transit-b and the Packeteer community", nhop, comms)
	}
	if _, _, ok := packeteerPath(t, edge, other.String()); ok || ctl.Injected(other) || !ctl.Injected(target) {
		t.Fatalf("announced set differs from the preview: %s injected %v, %s injected %v", target, ctl.Injected(target), other, ctl.Injected(other))
	}

	// Now on the wire: the preview of the running config has nothing to
	// change, and a candidate back to observe withdraws it.
	again, err := src.Preview(nil)
	if err != nil {
		t.Fatal(err)
	}
	if again.Changes || again.Keep != 1 {
		t.Fatalf("preview after the switch = %+v, want one kept route and no change", again)
	}
	off, err := src.Preview([]byte(blastConfig(port, "observe", `"203.0.113.0/24"`)))
	if err != nil {
		t.Fatal(err)
	}
	if off.Announces || len(off.Withdraw) != 1 || off.Withdraw[0].Prefix != target || off.Withdraw[0].To != "transit-a" {
		t.Fatalf("observe candidate = %+v, want %s withdrawn to transit-a", off, target)
	}
	if err := ctl.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBlastRefusalReasons(t *testing.T) {
	held := netip.MustParsePrefix("198.51.100.0/24")
	reserved := netip.MustParsePrefix("203.0.113.0/24")
	src := blastSource{
		held:     func(p netip.Prefix) bool { return p == held },
		reserved: func(p netip.Prefix) bool { return p == reserved },
	}
	for _, tc := range []struct {
		p    netip.Prefix
		want string
	}{
		{held, "leak watch"},
		{reserved, "inbound steering or threat mitigation"},
		{netip.MustParsePrefix("192.0.2.0/24"), "not in the learned RIB"},
	} {
		if got := src.refusal(tc.p); !strings.Contains(got, tc.want) {
			t.Errorf("refusal(%s) = %q, want %q", tc.p, got, tc.want)
		}
	}
}
