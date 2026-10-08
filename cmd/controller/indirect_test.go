package main

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
)

// TestIndirectOptions checks probe.indirect reaches the engine (#123):
// off when omitted or disabled, the configured trace shape when on, and
// hops on an exchange LAN skipped.
func TestIndirectOptions(t *testing.T) {
	base := `
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    peers:
      - {name: ix-peer, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31}
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
probe:
  interval: 30s
`
	for _, extra := range []string{"", "  indirect: {enabled: false}\n"} {
		cfg, err := config.Parse([]byte(base + extra))
		if err != nil {
			t.Fatal(err)
		}
		if indirectOptions(cfg) != nil {
			t.Fatalf("indirect on for %q", extra)
		}
	}
	cfg, err := config.Parse([]byte(base + "  indirect: {enabled: true, max_hops: 12, budget: 5s, cache_ttl: 10m, max_queue: 50}\n"))
	if err != nil {
		t.Fatal(err)
	}
	in := indirectOptions(cfg)
	if in == nil || in.Budget != 5*time.Second || in.CacheTTL != 10*time.Minute || in.MaxQueue != 50 || in.MinShare != 500*time.Millisecond {
		t.Fatalf("indirect = %+v", in)
	}
	tr, ok := in.Tracer.(traceroute.Tracer)
	if !ok || tr.MaxHops != 12 || tr.Probes != 3 || tr.MinReplies != 2 || tr.Port != 33434 || tr.Hop == nil {
		t.Fatalf("tracer = %+v", in.Tracer)
	}
	if !tr.Skip(netip.MustParseAddr("203.0.113.5")) || tr.Skip(netip.MustParseAddr("198.51.100.5")) {
		t.Fatal("exchange LAN hop not skipped")
	}
}
