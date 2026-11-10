package main

import (
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/onlyinvalid"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// freshVRPs is one fresh rpki.sources entry holding fixed payloads.
type freshVRPs struct {
	plugin.Base
	vrps *rpki.VRPs
}

func (f freshVRPs) Validate(p netip.Prefix, o uint32) plugin.RPKIValidity {
	return f.vrps.Validate(p, o)
}
func (f freshVRPs) Covering(p netip.Prefix) []plugin.RPKIVRP { return f.vrps.Covering(p) }
func (f freshVRPs) Status() plugin.RPKIStatus {
	return plugin.RPKIStatus{Source: "routinator", Up: true, VRPs: f.vrps.Len(), Updated: time.Now()}
}

// #401: with nothing configured there is no report; with the block on,
// the report reads the real RIB view (BMP paths), the rpki set, and the
// hijack feed file, and the SLURM exceptions are wired.
func TestNewOnlyInvalid(t *testing.T) {
	off, err := config.Parse([]byte(bmpConfig))
	if err != nil {
		t.Fatal(err)
	}
	if newOnlyInvalid(off, &pluginhost.Set{}, nil, rpki.NewSet(nil), irr.NewChecker(nil, irr.Options{}), nil, nil, nil) != nil {
		t.Fatal("built without rpki.only_invalid")
	}

	slurm := filepath.Join(t.TempDir(), "slurm.json")
	// BMP alone (#237): the view is ready while a BMP peer is up.
	bmpAlone := strings.Replace(bmpConfig, "bgp:\n  neighbors:\n    - address: 192.0.2.254\n", "", 1)
	bmpAlone = strings.Replace(bmpAlone, "    next_hop: 192.0.2.23\n", "    next_hop: 192.0.2.23\n    bmp: prefer\n", 1)
	y := bmpAlone + `rpki:
  enabled: true
  sources: [{type: rtr, config: {address: "127.0.0.1:3323"}}]
  only_invalid:
    enabled: true
    hijack_feeds: [{type: file, name: radar-export, config: {path: ../../internal/plugins/hijackfeed/file/testdata/incidents.json}}]
    slurm:
      path: ` + slurm + `
      prefixes: [198.51.100.0/24]
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins.HijackFeeds) != 1 || plugins.HijackFeeds[0].Name != "radar-export" {
		t.Fatalf("hijack feeds = %+v", plugins.HijackFeeds)
	}
	view, err := newRIB(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := netip.MustParseAddr("192.0.2.254")
	for _, nh := range []string{"192.0.2.21", "192.0.2.22"} {
		view.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPeerUp, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr(nh)}})
		view.ApplyRIB(plugin.RIBEvent{Kind: plugin.RIBPaths, Router: edge, Peer: plugin.RIBPeer{Address: netip.MustParseAddr(nh)}, PostPolicy: true,
			Paths: []plugin.RIBPath{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), NextHop: netip.MustParseAddr(nh), ASPath: []uint32{64496, 64500}}}})
	}
	vrps := rpki.NewVRPs()
	vrps.Apply([]rpki.Change{{Prefix: netip.MustParsePrefix("198.51.100.0/22"), MaxLen: 22, ASN: 64500}})
	var mu sync.Mutex
	var events []plugin.Event
	emit := func(e plugin.Event) { mu.Lock(); events = append(events, e); mu.Unlock() }
	svc := newOnlyInvalid(cfg, plugins, view, rpki.NewSet([]plugin.RPKI{freshVRPs{vrps: vrps}}), irr.NewChecker(nil, irr.Options{}), emit, auth.NewAuditor(nil, nil, nil), slog.New(slog.DiscardHandler))
	if svc == nil || svc.Exceptions == nil || svc.Exceptions.Path() != slurm {
		t.Fatalf("service = %+v", svc)
	}
	if !view.Ready() {
		t.Fatal("the BMP view is not ready")
	}
	svc.Scan(t.Context())
	c, ok := svc.Case(netip.MustParsePrefix("198.51.100.0/24"))
	// The same-origin ROA, two providers, and a quiet feed score 3, but
	// without IRR or route age that also fits a forged-origin hijack.
	if !ok || c.Origin != 64500 || len(c.Paths) != 2 || c.Score != 3 || c.Class != onlyinvalid.ClassUnclear {
		t.Fatalf("case = %+v, status %+v", c, svc.Status())
	}
	evidence := c.Evidence()
	for _, want := range []string{"irr_route +0: irr is off", "roa_same_origin +1", "providers +1: 2 providers agree on AS64500 (transit-a, transit-b)", "hijack_feeds +1: 1 of 1 feeds report no incident for AS64500"} {
		if !strings.Contains(evidence, want) {
			t.Errorf("evidence lacks %q: %s", want, evidence)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || events[0].Kind != plugin.EventRPKIOnlyInvalid {
		t.Fatalf("events = %+v", events)
	}
	if _, err := svc.Exceptions.Propose(t.Context(), onlyinvalid.Actor{User: "ops"}, c.Prefix); !errors.Is(err, onlyinvalid.ErrNotStale) {
		t.Fatalf("an unclear case got a proposal: %v", err)
	}
}
