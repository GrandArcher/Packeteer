package config

import (
	"strings"
	"testing"
	"time"
)

const indirectBase = `
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
probe:
  interval: 30s
`

func TestIndirectOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(indirectBase))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Probe.Indirect != nil {
		t.Fatalf("indirect = %+v, want nil", cfg.Probe.Indirect)
	}
	if cfg.Mode != ModeObserve {
		t.Fatalf("mode = %s", cfg.Mode)
	}
}

func TestIndirectDefaults(t *testing.T) {
	cfg, err := Parse([]byte(indirectBase + "  indirect: {enabled: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	in := cfg.Probe.Indirect
	want := ProbeIndirect{Enabled: true, MaxHops: 16, Probes: 3, MinReplies: 2, Timeout: 500 * time.Millisecond,
		Port: 33434, Budget: 10 * time.Second, CacheTTL: 30 * time.Minute, MaxQueue: 1024}
	if in == nil || *in != want {
		t.Fatalf("indirect = %+v, want %+v", in, want)
	}
	cfg, err = Parse([]byte(indirectBase + "  indirect: {enabled: true, probes: 1}\n"))
	if err != nil || cfg.Probe.Indirect.MinReplies != 1 {
		t.Fatalf("min_replies with one probe: %+v %v", cfg.Probe.Indirect, err)
	}
}

func TestIndirectValidation(t *testing.T) {
	for _, tc := range []struct{ block, want string }{
		{"max_hops: 65", "probe.indirect.max_hops"},
		{"probes: 11", "probe.indirect.probes"},
		{"probes: 2, min_replies: 3", "probe.indirect.min_replies"},
		{"timeout: 6s", "probe.indirect.timeout"},
		{"port: 70000", "probe.indirect.port"},
		{"budget: 31s", "probe.indirect.budget"},
		{"timeout: 2s, budget: 1s", "probe.indirect.budget"},
		{"cache_ttl: 30s", "probe.indirect.cache_ttl"},
		{"cache_ttl: 25h", "probe.indirect.cache_ttl"},
		{"max_queue: 100001", "probe.indirect.max_queue"},
		{"max_queue: -1", "probe.indirect.max_queue"},
		{"bogus: 1", "bogus"},
	} {
		_, err := Parse([]byte(indirectBase + "  indirect: {enabled: true, " + tc.block + "}\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %s", tc.block, err, tc.want)
		}
	}
}
