package config

import (
	"strings"
	"testing"
	"time"
)

func TestAtlasOffByDefault(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Atlas.Enabled || cfg.Atlas.AfterMove {
		t.Fatalf("atlas is on without a block: %+v", cfg.Atlas)
	}
}

func TestAtlasParse(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + `
atlas:
  enabled: true
  probe_id: 6001
  source: {type: country, value: DE}
  probes: 4
  after_move: true
  after_move_delay: 5m
  max_credits_per_day: 200
  max_measurements_per_hour: 2
  state_file: /tmp/atlas.json
`))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Atlas
	if !a.Enabled || a.ProbeID != 6001 || a.Source.Type != "country" || a.Source.Value != "DE" || a.Probes != 4 || !a.AfterMove ||
		a.AfterMoveDelay != 5*time.Minute || a.MaxCreditsPerDay != 200 || a.MaxMeasurementsPerHour != 2 || a.StateFile != "/tmp/atlas.json" {
		t.Fatalf("atlas = %+v", a)
	}
}

func TestAtlasRejected(t *testing.T) {
	cases := []struct{ block, want string }{
		{"probes: 50", "atlas.probes"},
		{"source: {type: area, value: Mars}", "atlas.source.value"},
		{"max_credits_per_day: 9999999", "atlas.max_credits_per_day"},
		{"api_key: abc", "field api_key not found"},
		{"base_url: https://example.net/", "field base_url not found"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(validYAML + "atlas:\n  enabled: true\n  " + tc.block + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.block, err, tc.want)
		}
	}
	if _, err := Parse([]byte(validYAML + "atlas:\n  probes: 3\n")); err == nil || !strings.Contains(err.Error(), "set enabled: true") {
		t.Errorf("settings without enabled: %v", err)
	}
}
