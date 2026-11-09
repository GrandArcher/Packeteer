package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// waitSource is a target source that sends packets of its own.
type waitSource struct {
	plugin.Base
	wait func(context.Context, netip.Addr) error
}

func (*waitSource) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

func (w *waitSource) SetPacketWait(fn func(context.Context, netip.Addr) error) { w.wait = fn }

// The traceroute source sends discovery packets of its own, so the wiring
// must reach it for both probe.exclude and probe.per_asn_pps.
var (
	_ probeExcludeSetter = (*traceroute.Source)(nil)
	_ packetWaitSetter   = (*traceroute.Source)(nil)
)

const excludeYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
bgp:
  neighbors:
    - address: 192.0.2.254
probe:
  interval: 30s
  rate_limit_pps: 100
  per_asn_pps: 10
  exclude:
    prefixes: [203.0.113.0/24, "2001:db8:1::/48"]
    asns: [64496]
`

// probe.exclude and probe.per_asn_pps (#203) reach the engine options,
// the indirect tracer, and the traceroute sources; both need a restart.
func TestProbeExclusionWiring(t *testing.T) {
	cfg, err := config.Parse([]byte(excludeYAML))
	if err != nil {
		t.Fatal(err)
	}
	x := probeExclusion(cfg, nil)
	if x == nil || len(x.Prefixes) != 2 || !x.ASNs[64496] || x.Origin == nil {
		t.Fatalf("exclusion = %+v", x)
	}
	if !x.Prefix(netip.MustParsePrefix("203.0.113.0/25")) || !x.Addr(netip.MustParseAddr("2001:db8:1::9")) || x.Prefix(netip.MustParsePrefix("198.51.100.0/24")) {
		t.Fatal("prefix rules not applied")
	}
	// Before the RIB view is ready the origin lookup knows nothing: the
	// ASN rules and the per-ASN cap wait for it, the prefix list applies.
	var view *rib.View
	origin := originLookup(func() *rib.View { return view })
	if origin(netip.MustParsePrefix("203.0.113.0/24")) != 0 {
		t.Fatal("origin from a nil view")
	}
	view, err = newRIB(cfg, nil)
	if err != nil || view == nil {
		t.Fatalf("newRIB: %v", err)
	}
	if view.Ready() || origin(netip.MustParsePrefix("203.0.113.0/24")) != 0 || originLookup(nil)(netip.MustParsePrefix("203.0.113.0/24")) != 0 {
		t.Fatal("origin from an unready view")
	}
	tr := indirectTracer(cfg, x)
	if !tr.Skip(netip.MustParseAddr("203.0.113.5")) || tr.Skip(netip.MustParseAddr("198.51.100.5")) {
		t.Fatal("excluded hop not skipped by the indirect tracer")
	}
	if indirectTracer(cfg, nil).Skip(netip.MustParseAddr("203.0.113.5")) {
		t.Fatal("nil exclusion skipped a hop")
	}
	plain, err := config.Parse([]byte(strings.Replace(excludeYAML, "  per_asn_pps: 10\n  exclude:\n    prefixes: [203.0.113.0/24, \"2001:db8:1::/48\"]\n    asns: [64496]\n", "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if probeExclusion(plain, nil) != nil {
		t.Fatal("exclusion built from an empty list")
	}
	perASN := perASNLimits(cfg, nil)
	if perASN == nil || perASNLimits(plain, nil) != nil {
		t.Fatal("per-ASN limiter not built from probe.per_asn_pps alone")
	}
	// Self-tracing sources get the shared cap; nothing is installed when
	// it is off.
	tracer := &waitSource{}
	set := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "tr", Type: "traceroute", Plugin: tracer}}}
	wirePacketWait(set, nil)
	if tracer.wait != nil {
		t.Fatal("packet wait installed with no per-ASN cap")
	}
	wirePacketWait(set, perASN)
	if tracer.wait == nil {
		t.Fatal("packet wait not installed")
	}
	if err := tracer.wait(context.Background(), netip.MustParseAddr("198.51.100.1")); err != nil {
		t.Fatal(err)
	}
	restart, online := classify(plain, cfg)
	if !slices.Contains(restart, "probe.per_asn_pps") || !slices.Contains(restart, "probe.exclude") || len(online) != 0 {
		t.Fatalf("restart = %v online = %v", restart, online)
	}
}
