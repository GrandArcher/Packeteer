package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const irrYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
thresholds: {min_rtt_delta_ms: 5}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
  - {name: transit-c, source_ip: 192.0.2.13, next_hop: 192.0.2.3}
`

// #214: the recorded RPSL fixture, through the file source, the checker,
// and fillIRR, labels each provider's learned path for the API and for
// Decide. prefer_registered keeps the recommendation off the provider
// whose origin is not registered; without it the fastest path wins. The
// shipped mode stays observe, so nothing is announced either way.
func TestIRRFixtureThroughDecide(t *testing.T) {
	fixture, err := os.ReadFile("../../internal/plugins/irr/file/testdata/irr.db")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "irr.db")
	if err := os.WriteFile(path, fixture, 0o644); err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	paths := fakePaths{
		"transit-a": {{64500, 64496}},
		"transit-b": {{64501, 64511}},
		"transit-c": {{64502, 64497}},
	}
	now := time.Now()
	results := []probe.Result{}
	for name, rtt := range map[string]time.Duration{"transit-a": 80, "transit-b": 20, "transit-c": 40} {
		results = append(results, probe.Result{Provider: name, Prefix: p, Prober: "icmp", Time: now,
			Stats: probe.Stats{Sent: 4, Received: 4, RTTAvg: rtt * time.Millisecond}})
	}

	for _, prefer := range []bool{true, false} {
		y := irrYAML + "irr:\n  enabled: true\n  as_sets: {transit-c: AS-EXAMPLE}\n  sources:\n    - {type: file, name: local, config: {path: " + path + "}}\n"
		if prefer {
			y += "  prefer_registered: true\n"
		}
		cfg := mustParse(t, y)
		plugins, err := pluginhost.Build(cfg, pluginhost.Options{})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := plugins.Start(ctx); err != nil {
			t.Fatal(err)
		}
		checker := newIRRChecker(cfg, plugins)
		done := make(chan struct{})
		go func() { checker.Run(ctx); close(done) }()

		in := policy.Input{Results: results, ProviderUp: map[string]bool{"transit-a": true, "transit-b": true, "transit-c": true},
			RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{p: "transit-a"}}
		deadline := time.Now().Add(5 * time.Second)
		for {
			in.IRR = nil
			fillIRR(&in, paths, checker)
			if in.IRR[p]["transit-a"].State != plugin.IRRUnknown && in.IRR[p]["transit-b"].State != plugin.IRRUnknown && in.IRR[p]["transit-c"].ASSetState != plugin.IRRUnknown {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("checker did not answer: %+v", in.IRR)
			}
			time.Sleep(time.Millisecond)
		}
		labels := in.IRR[p]
		if labels["transit-a"].State != plugin.IRRRegistered || labels["transit-a"].Database != "RADB" || labels["transit-a"].Source != "local" ||
			labels["transit-b"].State != plugin.IRRNotRegistered || !slices.Equal(labels["transit-b"].Origins, []uint32{64496, 64497}) ||
			labels["transit-c"].State != plugin.IRRRegistered || labels["transit-c"].ASSetState != plugin.IRRRegistered {
			t.Fatalf("labels = %+v", labels)
		}

		pc, err := policyConfig(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if pc.IRRPreferRegistered != prefer {
			t.Fatalf("IRRPreferRegistered = %v, want %v", pc.IRRPreferRegistered, prefer)
		}
		st, out := policy.Decide(policy.State{}, in, pc, plugins.Scorer.Plugin, now)
		want := "transit-b"
		if prefer {
			want = "transit-c"
		}
		if imp, ok := st.Improvements[p]; !ok || imp.Provider != want {
			t.Fatalf("prefer=%v: improvement %+v ok=%v, want %s", prefer, imp, ok, want)
		}
		for _, c := range out.Decisions[0].Candidates {
			if c.Provider == "transit-b" && c.IRR != plugin.IRRNotRegistered {
				t.Fatalf("transit-b candidate = %+v", c)
			}
			if c.Provider == "transit-b" && prefer != strings.Contains(c.Why, "IRR not registered") {
				t.Fatalf("prefer=%v: transit-b candidate = %+v", prefer, c)
			}
		}
		if cfg.Mode != "observe" {
			t.Fatalf("mode = %s", cfg.Mode)
		}

		snap := httpapi.Assemble(httpapi.Input{Version: "test", Mode: cfg.Mode, Started: true, At: now, Results: results,
			Paths: map[netip.Prefix][]rib.Route{p: {{Prefix: p, Provider: "transit-c", NextHop: netip.MustParseAddr("192.0.2.3"), ASPath: []uint32{64502, 64497}}}},
			IRR:   checker.Lookup})
		if lp := snap.Prefixes[0].Paths[0]; lp.IRR != "registered" || lp.IRRSource != "local" || lp.IRRASSet != "AS-EXAMPLE" || lp.IRRASSetState != "registered" {
			t.Fatalf("API path = %+v", lp)
		}
		cancel()
		<-done
		stopCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		_ = plugins.Stop(stopCtx)
		stop()
	}
}

// With irr off the checker has no sources and labels nothing.
func TestIRROff(t *testing.T) {
	cfg := mustParse(t, irrYAML)
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	checker := newIRRChecker(cfg, plugins)
	if checker.Enabled() || newIRRChecker(cfg, nil).Enabled() {
		t.Fatal("irr off built an enabled checker")
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	in := policy.Input{Results: []probe.Result{{Provider: "transit-a", Prefix: p}}}
	fillIRR(&in, fakePaths{"transit-a": {{64496}}}, checker)
	if in.IRR != nil {
		t.Fatalf("irr off labelled: %+v", in.IRR)
	}
	if pc, _ := policyConfig(cfg); pc.IRRPreferRegistered {
		t.Fatal("prefer_registered on by default")
	}
}
