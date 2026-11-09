package main

import (
	"log/slog"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pbr"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const siteCtlYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: local, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: far, site: dc-b, next_hop: 192.0.2.3}
probers:
  - type: icmp
  - type: agent
    config: {}
`

// A provider measured by probe agents (#230) goes to the engine with its
// site and no source address, and every host-side check that starts from a
// provider's source_ip leaves it out.
func TestSiteProviderIsOnlyInTheEngine(t *testing.T) {
	cfg, err := config.Parse([]byte(siteCtlYAML))
	if err != nil {
		t.Fatal(err)
	}
	probers := &pluginhost.Set{Probers: []pluginhost.Instance[plugin.Prober]{{Name: "p", Type: "fake", Plugin: &hungProber{allow: 1 << 30}}}}
	engine, err := newEngine(cfg, probers, slog.Default(), nil, nil, nil, packetLimiter(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ps := engine.Providers()
	if len(ps) != 2 || ps[0].Name != "local" || ps[0].Site != "" || ps[1].Name != "far" || ps[1].Site != "dc-b" || ps[1].Source.IsValid() {
		t.Fatalf("engine providers = %+v", ps)
	}
	tools, err := newTools(cfg, &pluginhost.Set{}, packetLimiter(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st := tools.Status(); len(st.Providers) != 1 || st.Providers[0] != "local" {
		t.Fatalf("tools providers = %+v", st.Providers)
	}
	if got := pathTargets(cfg); len(got) != 1 || got[0].Name != "local" {
		t.Fatalf("path targets = %+v", got)
	}
	if es := pbr.Entries(cfg); len(es) != 1 || es[0].Name != "local" {
		t.Fatalf("pbr entries = %+v", es)
	}
}
