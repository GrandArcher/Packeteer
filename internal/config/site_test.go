package config

import (
	"strings"
	"testing"
)

const siteBase = `
mode: observe
asn: 64512
router_id: 192.0.2.10
probers:
  - type: fixed
  - type: agent
    config: {}
providers:
  - {name: local, source_ip: 192.0.2.11, next_hop: 203.0.113.11}
`

func TestProviderSite(t *testing.T) {
	cfg, err := Parse([]byte(siteBase + "  - {name: far, site: dc-b, next_hop: 203.0.113.12}\n"))
	if err != nil {
		t.Fatal(err)
	}
	local, far := cfg.Providers[0], cfg.Providers[1]
	if !cfg.LocalProbe(local) || cfg.LocalProbe(far) {
		t.Errorf("LocalProbe: local %v far %v, want true and false", cfg.LocalProbe(local), cfg.LocalProbe(far))
	}
	for name, tc := range map[string]struct{ providers, want string }{
		"source":  {"  - {name: far, site: dc-b, source_ip: 192.0.2.12, next_hop: 203.0.113.12}\n", "source_ip, fwmark, and dscp must be empty"},
		"fwmark":  {"  - {name: far, site: dc-b, fwmark: 3, next_hop: 203.0.113.12}\n", "source_ip, fwmark, and dscp must be empty"},
		"domain":  {"  - {name: far, site: dc-b, domain: pop-b, next_hop: 203.0.113.12}\n", "site and domain cannot both be set"},
		"name":    {"  - {name: far, site: 'bad site', next_hop: 203.0.113.12}\n", "site \"bad site\""},
		"nexthop": {"  - {name: far, site: dc-b}\n", "next_hop"},
	} {
		if _, err := Parse([]byte(siteBase + tc.providers)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	noAgent := strings.Replace(siteBase, "  - type: agent\n    config: {}\n", "", 1) + "  - {name: far, site: dc-b, next_hop: 203.0.113.12}\n"
	if _, err := Parse([]byte(noAgent)); err == nil || !strings.Contains(err.Error(), "site requires a probers entry of type agent") {
		t.Errorf("no agent prober: err = %v", err)
	}
}

func TestAgentOnlyProbersCannotMeasureLocalProviders(t *testing.T) {
	agentOnly := strings.Replace(siteBase, "  - type: fixed\n", "", 1) + "  - {name: far, site: dc-b, next_hop: 203.0.113.12}\n"
	if _, err := Parse([]byte(agentOnly)); err == nil || !strings.Contains(err.Error(), "no probers entry other than agent") {
		t.Fatalf("err = %v, want a rejection of the local provider", err)
	}
}
