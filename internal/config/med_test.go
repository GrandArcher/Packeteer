package config

import (
	"strings"
	"testing"
)

func withMED(keys string) string {
	return strings.Replace(validYAML, "  min_rtt_delta_ms: 15\n", "  min_rtt_delta_ms: 15\n"+keys, 1)
}

func TestMEDTieBreakDefaultsOn(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Thresholds.MEDOn() || cfg.Thresholds.MEDMarginOrDefault() != DefaultMEDMargin {
		t.Fatalf("default: on=%v margin=%v", cfg.Thresholds.MEDOn(), cfg.Thresholds.MEDMarginOrDefault())
	}
	cfg, err = Parse([]byte(withMED("  med_tie_break: false\n  med_margin: 0\n")))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Thresholds.MEDOn() || cfg.Thresholds.MEDMarginOrDefault() != 0 {
		t.Fatalf("set: on=%v margin=%v", cfg.Thresholds.MEDOn(), cfg.Thresholds.MEDMarginOrDefault())
	}
}

func TestMEDMarginRejected(t *testing.T) {
	for _, v := range []string{"-1", ".nan", ".inf"} {
		_, err := Parse([]byte(withMED("  med_margin: " + v + "\n")))
		if err == nil || !strings.Contains(err.Error(), "thresholds.med_margin") {
			t.Errorf("med_margin %s: err = %v", v, err)
		}
	}
}
