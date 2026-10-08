package httpapi

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

func TestMEDDisplayAndASNMap(t *testing.T) {
	p198 := netip.MustParsePrefix("198.51.100.0/24")
	p203 := netip.MustParsePrefix("203.0.113.0/24")
	other := netip.MustParsePrefix("192.0.2.0/24")
	medA, medB, medRS := uint32(100), uint32(0), uint32(40)
	in := Input{
		Mode: "observe",
		Results: []probe.Result{
			{Provider: "transit-a", Prefix: p198},
			{Provider: "transit-a", Prefix: p203},
		},
		Routes: map[netip.Prefix]rib.Route{
			p198: {Prefix: p198, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a",
				Neighbor: netip.MustParseAddr("192.0.2.254"), Source: rib.SourceIBGP, PathID: 1, MED: &medA},
		},
		Paths: map[netip.Prefix][]rib.Route{
			p198: {
				{Prefix: p198, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a",
					Neighbor: netip.MustParseAddr("192.0.2.254"), Source: rib.SourceIBGP, PathID: 1,
					ASPath: []uint32{64496, 64500}, MED: &medA, MEDFrom: "iBGP 192.0.2.254, transit-a"},
				{Prefix: p198, NextHop: netip.MustParseAddr("192.0.2.5"), Provider: "transit-a",
					Neighbor: netip.MustParseAddr("192.0.2.254"), Source: rib.SourceIBGP, PathID: 2,
					ASPath: []uint32{64496, 64500}, MED: &medB, MEDFrom: "iBGP 192.0.2.254, transit-a"},
				{Prefix: p198, NextHop: netip.MustParseAddr("203.0.113.11"), Provider: "transit-a",
					Neighbor: netip.MustParseAddr("203.0.113.1"), Source: rib.SourceBMP, PathID: 7,
					ASPath: []uint32{64501, 64500}, MED: &medRS, MEDFrom: "peer 203.0.113.1, route server 203.0.113.1",
					Via: rib.ViaRouteServer},
			},
			p203: {
				{Prefix: p203, NextHop: netip.MustParseAddr("192.0.2.1"), Provider: "transit-a",
					Source: rib.SourceIBGP, ASPath: []uint32{64496, 64499}, MED: &medA, MEDFrom: "iBGP 192.0.2.254, transit-a"},
				{Prefix: p203, NextHop: netip.MustParseAddr("192.0.2.5"), Provider: "transit-a",
					Source: rib.SourceIBGP, PathID: 2, ASPath: []uint32{64496, 64499}, MED: &medB, MEDFrom: "iBGP 192.0.2.254, transit-a"},
			},
			// Learned, but not measured: the map must not include it.
			other: {{Prefix: other, NextHop: netip.MustParseAddr("192.0.2.9"), Provider: "transit-a", ASPath: []uint32{64496, 64500}}},
		},
	}
	snap := Assemble(in)
	var row Prefix
	for _, r := range snap.Prefixes {
		if r.Prefix == p198.String() {
			row = r
		}
		if r.Prefix == other.String() {
			t.Fatal("unmeasured prefix was exported")
		}
	}
	if len(row.Paths) != 3 {
		t.Fatalf("paths = %+v", row.Paths)
	}
	var selected, inactive int
	for _, path := range row.Paths {
		if path.Selected {
			selected++
			if path.MED == nil || *path.MED != 100 || path.MEDFrom == "" {
				t.Fatalf("selected med = %+v", path)
			}
		} else {
			inactive++
		}
		if path.NextHop == "192.0.2.5" && (path.MED == nil || *path.MED != 0) {
			t.Fatalf("med 0 dropped: %+v", path)
		}
		if path.NextHop == "203.0.113.11" && path.Via != rib.ViaRouteServer {
			t.Fatalf("via dropped: %+v", path)
		}
	}
	if selected != 1 || inactive != 2 {
		t.Fatalf("selected=%d inactive=%d", selected, inactive)
	}
	body, err := json.Marshal(snap.Decisions)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "med") {
		t.Fatalf("decision JSON mentions med: %s", body)
	}
	if len(snap.ASNMap) != 2 {
		t.Fatalf("map = %+v", snap.ASNMap)
	}
	var full, partial bool
	for _, node := range snap.ASNMap {
		if node.ASN != 64500 && node.ASN != 64499 {
			t.Fatalf("origin %d", node.ASN)
		}
		for _, site := range node.Sites {
			if site.Provider != "transit-a" {
				t.Fatalf("site %+v", site)
			}
			if site.NextHop == "203.0.113.11" {
				partial = site.Partial
				if !site.Partial {
					t.Fatal("route server site should be partial")
				}
			}
			if site.NextHop == "192.0.2.1" && node.ASN == 64500 && site.Partial {
				t.Fatal("full site marked partial")
			}
			if site.NextHop == "192.0.2.1" || site.NextHop == "192.0.2.5" {
				full = true
				if site.Partial {
					t.Fatalf("full table site partial: %+v", site)
				}
			}
		}
	}
	if !full || !partial {
		t.Fatalf("map sites full=%v partial=%v %+v", full, partial, snap.ASNMap)
	}
	for _, node := range snap.ASNMap {
		for _, site := range node.Sites {
			for _, pfx := range site.Prefixes {
				if pfx == other.String() {
					t.Fatal("map includes an unmeasured prefix")
				}
			}
		}
	}
}
