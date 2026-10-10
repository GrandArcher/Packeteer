package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const inboundCapBase = reloadBase + `bgp:
  neighbors:
    - {address: 192.0.2.251, description: edge-a}
inbound:
  mode: inject
  max_improvements: 5
  performance: {}
  prefixes: [198.51.100.0/24]
  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - {provider: transit-a, communities: ["64512:1102"]}
        - {provider: transit-b, communities: ["64512:1202"]}
`

// The inbound controller shares max_improvements and reads it once, at
// start. With inbound configured, a cap change must be refused by name,
// whichever way it goes, so outbound and inbound never run on two caps.
func TestReloadRefusesCapChangeWithInbound(t *testing.T) {
	withCap := func(n string) string { return inboundCapBase + "max_improvements: " + n + "\n" }
	cur := mustParse(t, withCap("50"))
	for _, next := range []string{"10", "5", "200"} {
		_, err := planReload(cur, mustParse(t, withCap(next)), nil)
		if err == nil || !strings.Contains(err.Error(), "max_improvements (shared with inbound)") {
			t.Fatalf("cap 50 -> %s: err = %v", next, err)
		}
	}
	// Other online keys still apply, and an unchanged cap is no change.
	other := strings.Replace(withCap("50"), "min_rtt_delta_ms: 15", "min_rtt_delta_ms: 10", 1)
	plan, err := planReload(cur, mustParse(t, other), nil)
	if err != nil || !slices.Equal(plan.online, []string{"thresholds"}) {
		t.Fatalf("thresholds with inbound: %+v %v", plan, err)
	}
	// Without inbound the cap is still online.
	plain := mustParse(t, reloadBase+"bgp:\n  neighbors:\n    - {address: 192.0.2.251, description: edge-a}\n")
	lowered := mustParse(t, reloadBase+"bgp:\n  neighbors:\n    - {address: 192.0.2.251, description: edge-a}\nmax_improvements: 10\n")
	if plan, err := planReload(plain, lowered, nil); err != nil || !slices.Equal(plan.online, []string{"max_improvements"}) {
		t.Fatalf("cap without inbound: %+v %v", plan, err)
	}
}

// fakeCtl records the order of the announcer calls a reload makes.
type fakeCtl struct {
	calls      []string
	prepareErr error
	applyErr   error
	mode       string
}

func (f *fakeCtl) SetRouters(context.Context, []plugin.RouterExport) error { return nil }
func (f *fakeCtl) Routers() []plugin.RouterExport                          { return nil }
func (f *fakeCtl) PrepareRuntime(mode string, _ int) error {
	f.calls = append(f.calls, "prepare "+mode)
	return f.prepareErr
}
func (f *fakeCtl) ApplyRuntime(_ context.Context, mode string, _ []netip.Prefix, _ int) error {
	f.calls = append(f.calls, "apply "+mode)
	if f.applyErr == nil {
		f.mode = mode
	}
	return f.applyErr
}

// A reload that is refused never changes the announcer's mode: Prepare
// runs first and only checks, Apply runs after the plugin swap, and a
// failure at either step leaves the sources as they were.
func TestReloadRefusedNeverAppliesMode(t *testing.T) {
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hold.Close() })
	busy := hold.LocalAddr().String()
	free, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	freeAddr := free.LocalAddr().String()
	_ = free.Close()

	neighbors := "bgp:\n  neighbors:\n    - {address: 192.0.2.251, description: edge-a}\n"
	observe := strings.Replace(reloadBase, "mode: inject", "mode: observe", 1) + neighbors
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(y string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(observe)
	cfg := mustParse(t, observe)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := plugins.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plugins.Stop(context.Background()) })
	ctl := &fakeCtl{mode: "observe"}
	rl := &reloader{
		path: path, getenv: noEnv, log: log, cur: cfg, plugins: plugins, ctl: ctl,
		opts: pluginhost.Options{Logger: log, Getenv: noEnv},
	}
	flow := func(addr string) string {
		return "sources:\n  - {type: flow, name: tap, config: {listen: '" + addr + "'}}\n"
	}
	inject := func(extra string) string { return reloadBase + neighbors + extra }

	// The announcer cannot enter inject: refused, nothing applied.
	ctl.prepareErr = errors.New("announce: inject needs an iBGP session")
	write(inject(""))
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil || !strings.Contains(refused.Error(), "iBGP") {
		t.Fatalf("prepare failure: refused %v fatal %v", refused, fatal)
	}
	if !slices.Equal(ctl.calls, []string{"prepare inject"}) || ctl.mode != "observe" {
		t.Fatalf("calls %v mode %s", ctl.calls, ctl.mode)
	}

	// The plugin swap fails (the flow port is taken): Apply never runs.
	ctl.prepareErr, ctl.calls = nil, nil
	write(inject(flow(busy)))
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil {
		t.Fatalf("swap failure: refused %v fatal %v", refused, fatal)
	}
	if !slices.Equal(ctl.calls, []string{"prepare inject"}) || ctl.mode != "observe" {
		t.Fatalf("after a failed swap: calls %v mode %s", ctl.calls, ctl.mode)
	}

	// Apply fails after the swap: the new source is stopped again, so its
	// port is free, and the old config still runs.
	ctl.calls, ctl.applyErr = nil, errors.New("withdraw failed")
	write(inject(flow(freeAddr)))
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil || !strings.Contains(refused.Error(), "withdraw failed") {
		t.Fatalf("apply failure: refused %v fatal %v", refused, fatal)
	}
	if !slices.Equal(ctl.calls, []string{"prepare inject", "apply inject"}) || ctl.mode != "observe" {
		t.Fatalf("calls %v mode %s", ctl.calls, ctl.mode)
	}
	if len(plugins.SourcesSnapshot()) != 0 {
		t.Fatalf("sources = %+v", plugins.SourcesSnapshot())
	}
	again, err := net.ListenPacket("udp", freeAddr)
	if err != nil {
		t.Fatalf("the refused reload left its source listening: %v", err)
	}
	_ = again.Close()

	// A good reload: Prepare, then Apply, in that order, and the overview's
	// setup facts follow the new sources.
	var setup httpapi.Setup
	rl.setup = func(st httpapi.Setup) { setup = st }
	ctl.calls, ctl.applyErr = nil, nil
	write(inject(flow(freeAddr)))
	applied, refused, fatal := rl.reload(ctx)
	if fatal != nil || refused != nil || !slices.Contains(applied, "mode") {
		t.Fatalf("good reload: applied %v refused %v fatal %v", applied, refused, fatal)
	}
	if !slices.Equal(ctl.calls, []string{"prepare inject", "apply inject"}) || ctl.mode != "inject" {
		t.Fatalf("calls %v mode %s", ctl.calls, ctl.mode)
	}
	if !slices.Equal(setup.Sources, []string{"flow"}) {
		t.Fatalf("setup sources = %v", setup.Sources)
	}
}
