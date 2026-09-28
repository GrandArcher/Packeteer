package main

import (
	"context"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// The example config ships observe with the active tools off; the
// looking glass is the only tool, and building the tools sends nothing.
func TestTroubleshootWiring(t *testing.T) {
	cfg, err := config.Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != config.ModeObserve || cfg.Troubleshoot.Enabled {
		t.Fatalf("example config: mode %q troubleshoot %+v", cfg.Mode, cfg.Troubleshoot)
	}
	set, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	tools, err := newTools(cfg, set)
	if err != nil {
		t.Fatal(err)
	}
	st := tools.Status()
	if st.Enabled || st.Probe || st.Traceroute || st.Whois || len(st.Providers) != len(cfg.Providers) {
		t.Fatalf("status = %+v", st)
	}
	if _, err := tools.Whois(context.Background(), "AS64496"); err == nil {
		t.Fatal("whois ran with tools disabled")
	}

	cfg.Troubleshoot.Enabled = true
	cfg.Troubleshoot.Whois = &config.PluginSpec{Type: "rdap"}
	set, err = pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if set.Whois == nil || set.Whois.Type != "rdap" {
		t.Fatalf("whois plugin not built: %+v", set.Whois)
	}
	tools, err = newTools(cfg, set)
	if err != nil {
		t.Fatal(err)
	}
	if st := tools.Status(); !st.Enabled || !st.Traceroute || !st.Whois {
		t.Fatalf("enabled status = %+v", st)
	}
}
