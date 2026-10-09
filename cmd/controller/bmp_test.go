package main

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const bmpConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
    bmp: only
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.22
    bmp: prefer
  - name: transit-c
    source_ip: 192.0.2.13
    next_hop: 192.0.2.23
bgp:
  neighbors:
    - address: 192.0.2.254
rib_sources:
  - type: bmp
    config:
      listen: "127.0.0.1:0"
      routers: [192.0.2.254]
`

// The configured BMP station is built from config, wired to the RIB view,
// and its events drive the route check the decision input carries.
func TestBMPWiringAndRouteCheck(t *testing.T) {
	cfg, err := config.Parse([]byte(bmpConfig))
	if err != nil {
		t.Fatal(err)
	}
	set, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.RIBSources) != 1 || set.RIBSources[0].Type != "bmp" {
		t.Fatalf("rib sources = %+v", set.RIBSources)
	}
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wireRIBSources(set, nil); err == nil {
		t.Fatal("rib sources without a view must refuse to start")
	}
	// Capture the sink the station would call.
	var sink func(plugin.RIBEvent)
	set.RIBSources[0].Plugin = &sinkSpy{RIBSource: set.RIBSources[0].Plugin, got: &sink}
	if err := wireRIBSources(set, view); err != nil || sink == nil {
		t.Fatalf("sink not wired: %v", err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	p := netip.MustParsePrefix("198.51.100.0/24")
	sink(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr("192.0.2.22")}})
	sink(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr("192.0.2.21")},
		Paths: []plugin.RIBPath{{Prefix: p, NextHop: netip.MustParseAddr("192.0.2.21"), ASPath: []uint32{64496}}}, PostPolicy: true})
	if rt, ok := view.Exact(p); !ok || rt.Provider != "transit-a" {
		t.Fatalf("BMP path not in the view: %+v %v", rt, ok)
	}
	in := policy.Input{Results: []probe.Result{
		{Prefix: p, Provider: "transit-a"}, {Prefix: p, Provider: "transit-b"}, {Prefix: p, Provider: "transit-c"},
	}}
	fillRouteChecks(&in, view)
	// transit-a has the path; transit-b's peer is up with no path; transit-c
	// is bmp off, so it is not checked.
	if got := in.NoRoute[p]; len(got) != 1 || !got["transit-b"] {
		t.Fatalf("NoRoute = %+v", in.NoRoute)
	}
}

// A prefix a peer sent but the router's import policy rejected (seen only
// pre-policy) must not pass the announcer's RIB gate, even while the iBGP
// view is ready.
func TestPrePolicyPrefixFailsAnnouncerGate(t *testing.T) {
	cfg, err := config.Parse([]byte(bmpConfig))
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	gate := ribGate{v: view}
	edge := netip.MustParseAddr("192.0.2.254")
	hijack := netip.MustParsePrefix("203.0.113.0/25")
	for _, nh := range []string{"192.0.2.21", "192.0.2.22"} {
		view.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr(nh)},
			Paths: []plugin.RIBPath{{Prefix: hijack, NextHop: netip.MustParseAddr(nh), ASPath: []uint32{64499}}}})
	}
	if gate.Contains(hijack) {
		t.Fatal("a pre-policy-only prefix passed ribGate.Contains")
	}
	if _, ok := gate.NextHop(hijack); ok {
		t.Fatal("a pre-policy-only prefix has a next hop for inbound steers")
	}
	view.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr("192.0.2.21")},
		Paths: []plugin.RIBPath{{Prefix: hijack, NextHop: netip.MustParseAddr("192.0.2.21"), ASPath: []uint32{64499}}}, PostPolicy: true})
	if !gate.Contains(hijack) {
		t.Fatal("a post-policy (router-accepted) path did not pass the gate")
	}
}

type sinkSpy struct {
	plugin.RIBSource
	got *func(plugin.RIBEvent)
}

func (s *sinkSpy) SetRIBSink(fn func(plugin.RIBEvent)) { *s.got = fn; s.RIBSource.SetRIBSink(fn) }

func TestOwnCommunity(t *testing.T) {
	if got, large, err := ownCommunity("64512:666"); err != nil || got != 64512<<16|666 || large != "" {
		t.Fatalf("64512:666 = %d %q, %v", got, large, err)
	}
	if got, large, err := ownCommunity(""); err != nil || got != 0 || large != "" {
		t.Fatalf("empty = %d %q, %v", got, large, err)
	}
	if _, _, err := ownCommunity("70000:1"); err == nil {
		t.Fatal("out-of-range community accepted")
	}
	if got, large, err := ownCommunity("4200000000:1:666"); err != nil || got != 0 || large != "4200000000:1:666" {
		t.Fatalf("large = %d %q, %v", got, large, err)
	}
	if _, large, err := ownCommunity("64512:0666"); err != nil || large != "" {
		t.Fatalf("canonical standard = %q, %v", large, err)
	}
}

func TestWarnBMPSelfFilter(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	warnBMPSelfFilter(log, map[string]string{"transit-a": config.BMPOff}, 0, "")
	if buf.Len() != 0 {
		t.Fatalf("warned with no provider on BMP: %s", buf.String())
	}
	warnBMPSelfFilter(log, map[string]string{"transit-a": config.BMPOnly}, 0, "")
	if !strings.Contains(buf.String(), "packeteer_community is unset") {
		t.Fatalf("no warning without packeteer_community: %s", buf.String())
	}
	buf.Reset()
	warnBMPSelfFilter(log, map[string]string{"transit-a": config.BMPPrefer}, 64512<<16|666, "")
	if !strings.Contains(buf.String(), "strips that community") {
		t.Fatalf("no community-stripping warning: %s", buf.String())
	}
	buf.Reset()
	warnBMPSelfFilter(log, map[string]string{"transit-a": config.BMPPrefer}, 0, "4200000000:1:666")
	if strings.Contains(buf.String(), "packeteer_community is unset") || !strings.Contains(buf.String(), "strips that community") {
		t.Fatalf("large community treated as unset: %s", buf.String())
	}
}
