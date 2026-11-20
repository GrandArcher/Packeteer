package main

import (
	"slices"
	"strings"
	"testing"
)

// The blocks of the Settings forms of #670 and #687 (link-outs) are read once at start, so Preview
// lists each one as a restart key and a reload refuses them (the page shows
// the list before Save). Herd is covered by TestHerdChangeNeedsRestart.
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
		{"linkouts", "linkouts:\n  enabled: [he]\n  hide_internal: false\n"},
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

// A router check added through the editor may name only the documented
// variables: a name such as PACKETEER_ADMIN_PASSWORD would send that value to
// the router's address (#504).
func TestRouterCheckEnvNamesAreChecked(t *testing.T) {
	const base = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
`
	check := func(env string) error {
		next := mustParse(t, base+"preflight:\n  router_check:\n    type: routeros\n    config: {url: \"https://192.0.2.254\", username_env: PACKETEER_ROUTER_READ_USER, password_env: "+env+"}\n")
		return checkEnvNames(mustParse(t, base), next)
	}
	if err := check("PACKETEER_ROUTER_READ_PASSWORD"); err != nil {
		t.Fatalf("documented name refused: %v", err)
	}
	if err := check("PACKETEER_ADMIN_PASSWORD"); err == nil || !strings.Contains(err.Error(), "preflight.router_check/routeros") {
		t.Fatalf("err = %v, want the admin password name refused", err)
	}
}
