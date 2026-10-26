package config

import (
	"strings"
	"testing"
	"time"
)

func TestVerifyOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Verify.Enabled {
		t.Fatalf("verify is on without a block: %+v", cfg.Verify)
	}
}

func TestVerifyParse(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
verify:
  enabled: true
  outbound_window: 3m
  inbound_window: 15m
  verified_pct: 60
  moved_pct: 5
  min_mbps: 2
  backout: [inbound, outbound]
  backoff: 10m
  max_backoff: 2h
`))
	if err != nil {
		t.Fatal(err)
	}
	v := cfg.Verify
	if !v.Enabled || v.OutboundWindow != 3*time.Minute || v.InboundWindow != 15*time.Minute || v.VerifiedPct != 60 || v.MovedPct != 5 ||
		v.MinMbps != 2 || len(v.Backout) != 2 || v.Backoff != 10*time.Minute || v.MaxBackoff != 2*time.Hour {
		t.Fatalf("verify = %+v", v)
	}
	// An empty backout list is "warn only", not the default.
	cfg, err = Parse([]byte(validYAML + "verify:\n  enabled: true\n  backout: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Verify.Backout == nil || len(cfg.Verify.Backout) != 0 {
		t.Fatalf("backout: [] = %#v, want empty and not nil", cfg.Verify.Backout)
	}
}

func TestVerifyRejected(t *testing.T) {
	cases := []struct{ block, want string }{
		{"outbound_window: 1s", "verify.outbound_window"},
		{"inbound_window: 48h", "verify.inbound_window"},
		{"verified_pct: 150", "verify.verified_pct"},
		{"verified_pct: 40\n  moved_pct: 40", "verify.moved_pct"},
		{"min_mbps: -1", "verify.min_mbps"},
		{"backout: [both]", "verify.backout"},
		{"backoff: 2h\n  max_backoff: 1h", "verify.max_backoff"},
		{"action: revert", "field action not found"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(validYAML + "verify:\n  enabled: true\n  " + tc.block + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.block, err, tc.want)
		}
	}
	if _, err := Parse([]byte(validYAML + "verify:\n  backoff: 1h\n")); err == nil || !strings.Contains(err.Error(), "set enabled: true") {
		t.Errorf("settings without enabled: %v", err)
	}
}
