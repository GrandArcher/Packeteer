package config

import (
	"strings"
	"testing"
	"time"
)

func TestRingLGOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RingLG.Enabled {
		t.Fatalf("ring_lg is on without a block: %+v", cfg.RingLG)
	}
}

func TestRingLGParse(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
ring_lg:
  enabled: true
  requests_per_minute: 3
  cache_ttl: 30m
  timeout: 5s
`))
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.RingLG
	if !r.Enabled || r.RequestsPerMinute != 3 || r.CacheTTL != 30*time.Minute || r.Timeout != 5*time.Second {
		t.Fatalf("ring_lg = %+v", r)
	}
}

func TestRingLGRejected(t *testing.T) {
	cases := []struct{ block, want string }{
		{"requests_per_minute: 600", "ring_lg.requests_per_minute"},
		{"cache_ttl: 10s", "ring_lg.cache_ttl"},
		{"timeout: 5m", "ring_lg.timeout"},
		{"url: https://example.net/", "field url not found"},
		{"user: someone", "field user not found"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(validYAML + "ring_lg:\n  enabled: true\n  " + tc.block + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.block, err, tc.want)
		}
	}
}
