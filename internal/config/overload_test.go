package config

import (
	"strings"
	"testing"
)

const overloadTelemetry = `
telemetry:
  - type: fixed
    config:
      providers:
        - {name: transit-a, capacity_mbps: 1000, out_mbps: 10}
`

func TestInterfaceCapacityThreshold(t *testing.T) {
	yml := strings.Replace(validYAML, "    next_hop: 192.0.2.1\n", "    next_hop: 192.0.2.1\n    interface_capacity_threshold_pct: 85\n", 1)
	cfg, err := Parse([]byte(yml + overloadTelemetry))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Providers[0].InterfaceCapacityThresholdPct; got != 85 {
		t.Fatalf("transit-a threshold = %v, want 85", got)
	}
	if got := cfg.Providers[1].InterfaceCapacityThresholdPct; got != 0 {
		t.Fatalf("transit-b threshold = %v, want 0 (off)", got)
	}
}

func TestInterfaceCapacityThresholdRejected(t *testing.T) {
	cases := []struct{ name, pct, extra, want string }{
		{"negative", "-1", overloadTelemetry, "between 0 and 100"},
		{"over 100", "101", overloadTelemetry, "between 0 and 100"},
		{"no telemetry", "85", "", "requires a telemetry plugin"},
	}
	for _, tc := range cases {
		yml := strings.Replace(validYAML, "    next_hop: 192.0.2.1\n", "    next_hop: 192.0.2.1\n    interface_capacity_threshold_pct: "+tc.pct+"\n", 1)
		_, err := Parse([]byte(yml + tc.extra))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
	// Off needs no telemetry.
	yml := strings.Replace(validYAML, "    next_hop: 192.0.2.1\n", "    next_hop: 192.0.2.1\n    interface_capacity_threshold_pct: 0\n", 1)
	if _, err := Parse([]byte(yml)); err != nil {
		t.Fatalf("threshold 0 without telemetry: %v", err)
	}
}
