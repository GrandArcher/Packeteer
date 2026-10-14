package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type rowsSrc struct {
	plugin.Base
	rows []plugin.PrefixVolume
}

func (r *rowsSrc) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

func (r *rowsSrc) Volumes(context.Context) ([]plugin.PrefixVolume, error) { return r.rows, nil }

func offloadVolume(prefix string, mbps float64) plugin.PrefixVolume {
	return plugin.PrefixVolume{Prefix: netip.MustParsePrefix(prefix), Bytes: uint64(mbps * 1e6 / 8 * 10), Window: 10 * time.Second}
}

const offloadConfig = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1, cost: 2, bmp: prefer}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2, bmp: prefer}
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    bmp: prefer
    peers:
      - {name: ix-peer-a, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31}
      - {name: ix-peer-b, asn: 64502, next_hop: 203.0.113.12, source_ip: 192.0.2.32}
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
rib_sources:
  - type: bmp
    config:
      routers: [192.0.2.254]
`

// #152: the report joins the sources' volumes, the exit the learned RIB
// shows, and the route check on the exchange peers. Observe mode, so the
// exit is the RIB's.
func TestOffloadReportJoinsVolumeExitAndRouteCheck(t *testing.T) {
	cfg := mustParse(t, offloadConfig)
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	learn := func(prefix, peer string, asPath ...uint32) {
		t.Helper()
		view.ApplyRIB(plugin.RIBEvent{
			Kind: plugin.RIBPaths, Router: edge, PostPolicy: true,
			Peer:  plugin.RIBPeer{Address: netip.MustParseAddr(peer)},
			Paths: []plugin.RIBPath{{Prefix: netip.MustParsePrefix(prefix), NextHop: netip.MustParseAddr(peer), ASPath: asPath}},
		})
	}
	// Transit exit, peer a advertises the exact prefix: a candidate.
	learn("198.51.100.0/24", "192.0.2.1", 64496, 64500)
	learn("198.51.100.0/24", "203.0.113.11", 64501, 64510, 64500)
	// Transit with no cost, both peers: a candidate with no saving.
	learn("192.0.2.0/25", "192.0.2.2", 64497, 64500)
	learn("192.0.2.0/25", "203.0.113.11", 64501, 64510, 64500)
	learn("192.0.2.0/25", "203.0.113.12", 64502, 64510, 64500)
	// The peer's path starts with another AS: the route check refuses it.
	learn("198.51.100.128/25", "192.0.2.1", 64496, 64500)
	learn("198.51.100.128/25", "203.0.113.12", 64599, 64510, 64500)
	// Exit is the peer itself.
	learn("192.0.2.128/25", "203.0.113.11", 64501, 64500)
	// No peer route.
	learn("2001:db8:1::/48", "192.0.2.1", 64496, 64500)

	plugins := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flows", Type: "static", Plugin: &rowsSrc{rows: []plugin.PrefixVolume{
		offloadVolume("198.51.100.0/24", 80),
		offloadVolume("192.0.2.0/25", 120),
		offloadVolume("198.51.100.128/25", 700),
		offloadVolume("192.0.2.128/25", 500),
		offloadVolume("2001:db8:1::/48", 900),
		offloadVolume("198.51.100.0/25", 10),
	}}}}}
	decider := policy.NewEngine(policy.Config{Mode: "observe"}, nil)

	got := offloadReport(cfg, plugins, view, decider)(100)
	if got.Prefixes != 2 || len(got.Rows) != 2 {
		t.Fatalf("report = %+v", got)
	}
	a, b := got.Rows[0], got.Rows[1]
	if a.Prefix != "192.0.2.0/25" || a.Transit != "transit-b" || a.EstSavings != nil || len(a.Peers) != 2 ||
		a.Peers[0].Peer != "ix-peer-a" || a.Peers[1].Peer != "ix-peer-b" || a.Peers[0].Exchange != "ix-lab" {
		t.Fatalf("first row = %+v", a)
	}
	if b.Prefix != "198.51.100.0/24" || b.Transit != "transit-a" || b.Mbps != 80 || b.EstSavings == nil || *b.EstSavings != 160 || len(b.Peers) != 1 {
		t.Fatalf("second row = %+v", b)
	}
	var csv strings.Builder
	if err := got.WriteCSV(&csv); err != nil || !strings.HasPrefix(csv.String(), "prefix,bytes,mbps,transit,peers,est_savings\n192.0.2.0/25,") {
		t.Fatalf("csv %q: %v", csv.String(), err)
	}
}

// #152: in inject mode the exit is where the active improvement sends the
// prefix, not the native path the RIB still shows. A prefix steered onto an
// exchange peer is no longer on a transit.
func TestOffloadReportUsesInjectedExit(t *testing.T) {
	cfg := mustParse(t, offloadConfig)
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	p := netip.MustParsePrefix("198.51.100.0/24")
	for _, peer := range []string{"192.0.2.1", "203.0.113.11"} {
		path := []uint32{64496, 64500}
		if peer == "203.0.113.11" {
			path = []uint32{64501, 64510, 64500}
		}
		view.ApplyRIB(plugin.RIBEvent{
			Kind: plugin.RIBPaths, Router: edge, PostPolicy: true,
			Peer:  plugin.RIBPeer{Address: netip.MustParseAddr(peer)},
			Paths: []plugin.RIBPath{{Prefix: p, NextHop: netip.MustParseAddr(peer), ASPath: path}},
		})
	}
	plugins := &pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flows", Type: "static", Plugin: &rowsSrc{rows: []plugin.PrefixVolume{offloadVolume(p.String(), 80)}}}}}

	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	decider := policy.NewEngine(policy.Config{
		Mode: "inject", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: time.Minute,
		MaxImprovements: 50, MaxResultAge: 2 * time.Minute, Allowlist: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
	}, scorer)
	report := offloadReport(cfg, plugins, view, decider)
	if got := report(10); got.Prefixes != 1 {
		t.Fatalf("before the move = %+v", got)
	}
	res := []probe.Result{
		{Provider: "transit-a", Prefix: p, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 80 * time.Millisecond}},
		{Provider: "ix-peer-a", Prefix: p, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 20 * time.Millisecond}},
	}
	decider.Evaluate(policy.Input{
		Results: res, ProviderUp: map[string]bool{"transit-a": true, "ix-peer-a": true},
		RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{p: "transit-a"},
	}, now)
	if imps := decider.Improvements(); len(imps) != 1 || imps[0].Provider != "ix-peer-a" {
		t.Fatalf("improvements = %+v", imps)
	}
	if got := report(10); got.Prefixes != 0 || len(got.Rows) != 0 {
		t.Fatalf("after the move to the peer = %+v", got)
	}
}
