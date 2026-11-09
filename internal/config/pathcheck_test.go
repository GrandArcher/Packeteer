package config

import (
	"strings"
	"testing"
	"time"
)

func TestPathCheckDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Probe.PathCheck.On() {
		t.Fatal("path check should be on by default")
	}
	if cfg.Probe.PathCheck.Interval != DefaultPathCheckInterval {
		t.Fatalf("interval = %s, want %s", cfg.Probe.PathCheck.Interval, DefaultPathCheckInterval)
	}
	if !cfg.Providers[0].PathCheckOn() {
		t.Fatal("provider should be checked by default")
	}
}

func TestPathCheckSettings(t *testing.T) {
	y := edit(t, minimalYAML, "  next_hop: 192.0.2.1",
		"  next_hop: 192.0.2.1\n    path_check: false")
	y = edit(t, y, "providers:", "probe:\n  path_check:\n    enabled: false\n    interval: 1m\nproviders:")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Probe.PathCheck.On() {
		t.Fatal("path check should be off")
	}
	if cfg.Probe.PathCheck.Interval != time.Minute {
		t.Fatalf("interval = %s, want 1m", cfg.Probe.PathCheck.Interval)
	}
	if cfg.Providers[0].PathCheckOn() {
		t.Fatal("provider opted out")
	}
}

func TestPathCheckExchangePeerOptOut(t *testing.T) {
	y := edit(t, exchangeYAML, "        source_ip: 192.0.2.31",
		"        source_ip: 192.0.2.31\n        path_check: false")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range cfg.Providers {
		if p.Name == "ix-peer-a" && p.PathCheckOn() {
			t.Fatal("peer a opted out")
		}
		if p.Name == "ix-peer-b" && !p.PathCheckOn() {
			t.Fatal("peer b should be checked")
		}
	}
}

func TestPathCheckIntervalErrors(t *testing.T) {
	y := edit(t, minimalYAML, "providers:", "probe:\n  path_check:\n    interval: 500ms\nproviders:")
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "probe.path_check.interval 500ms must be between") {
		t.Fatalf("short interval: err = %v", err)
	}
	y = edit(t, minimalYAML, "providers:", "probe:\n  path_check:\n    interval: 48h\nproviders:")
	if _, err := Parse([]byte(y)); err == nil || !strings.Contains(err.Error(), "must be between") {
		t.Fatalf("long interval: err = %v", err)
	}
}
