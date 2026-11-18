package main

import (
	"slices"
	"strings"
	"testing"
)

// The blocks of the Settings forms of #670 are read once at start, so Preview
// lists each one as a restart key and a reload refuses them (the page shows
// the list before Save).
func TestSettingsFormBlocksNeedRestart(t *testing.T) {
	const base = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
`
	for _, c := range []struct{ key, yaml string }{
		{"rpki", "rpki:\n  enabled: true\n  sources:\n    - type: rtr\n      config: {address: \"192.0.2.20:3323\"}\n"},
		{"registry", "registry:\n  enabled: true\n  asns: [64496]\n  sources:\n    - type: peeringdb\n"},
		{"mcp", "mcp:\n  enabled: true\n"},
		{"verify", "verify:\n  enabled: true\n"},
		{"preflight", "preflight:\n  router_check:\n    type: frr\n    config: {socket_env: PACKETEER_FRR_SOCKET}\n"},
	} {
		t.Run(c.key, func(t *testing.T) {
			restart, online := classify(mustParse(t, base), mustParse(t, base+c.yaml))
			if !slices.Contains(restart, c.key) || len(online) != 0 {
				t.Fatalf("restart %v online %v, want only %s in restart", restart, online, c.key)
			}
			if _, err := planReload(mustParse(t, base), mustParse(t, base+c.yaml), nil); err == nil || !strings.Contains(err.Error(), "restart required: changed "+c.key) {
				t.Fatalf("planReload: %v", err)
			}
		})
	}
}
