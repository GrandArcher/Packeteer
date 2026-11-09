package config

import (
	"strings"
	"testing"
)

// routersYAML is two edges (#27): edge-a forwards to transit-a and reaches
// transit-b through edge-b, edge-b forwards to transit-b.
const routersYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.22
bgp:
  neighbors:
    - address: 192.0.2.251
      providers: [transit-a]
      next_hops:
        transit-b: 192.0.2.252
    - address: 192.0.2.252
      providers: [transit-b]
`

func TestRoutersValid(t *testing.T) {
	cfg, err := Parse([]byte(routersYAML))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.BGP.Neighbors
	if !n[0].Routed() || n[0].NextHops["transit-b"] != "192.0.2.252" || len(n[1].Providers) != 1 {
		t.Fatalf("neighbors = %+v", n)
	}
	// A route reflector with no list reaches every provider.
	rr := edit(t, routersYAML, "    - address: 192.0.2.252\n      providers: [transit-b]\n", "    - address: 192.0.2.250\n")
	if _, err := Parse([]byte(rr)); err != nil {
		t.Fatalf("unrestricted neighbor: %v", err)
	}
	if _, err := Parse([]byte(minimalYAML + "bgp:\n  neighbors:\n    - address: 192.0.2.254\n")); err != nil {
		t.Fatalf("single router: %v", err)
	}
}

func TestRoutersErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"unknown provider": {edit(t, routersYAML, "providers: [transit-b]", "providers: [transit-z]"),
			`providers: "transit-z" is not a configured provider`},
		"duplicate provider": {edit(t, routersYAML, "providers: [transit-b]", "providers: [transit-b, transit-b]"),
			`duplicate "transit-b"`},
		"unknown via": {edit(t, routersYAML, "transit-b: 192.0.2.252", "transit-z: 192.0.2.252"),
			`next_hops: "transit-z" is not a configured provider`},
		"both lists": {edit(t, routersYAML, "providers: [transit-a]", "providers: [transit-a, transit-b]"),
			"also in providers"},
		"bad via": {edit(t, routersYAML, "transit-b: 192.0.2.252", "transit-b: edge-b"),
			"not a valid IP address"},
		"via family": {edit(t, routersYAML, "transit-b: 192.0.2.252", "transit-b: 2001:db8::252"),
			"same address family"},
		"unreached": {edit(t, routersYAML, "      next_hops:\n        transit-b: 192.0.2.252\n    - address: 192.0.2.252\n      providers: [transit-b]\n", ""),
			"providers[transit-b]: no bgp.neighbors entry reaches it"},
		"shared next hop": {edit(t, routersYAML, "next_hop: 192.0.2.22", "next_hop: 192.0.2.21"),
			"next_hop 192.0.2.21 is shared"},
	}
	for name, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// An excluded provider need not be reachable.
	ok := edit(t, routersYAML, "      next_hops:\n        transit-b: 192.0.2.252\n    - address: 192.0.2.252\n      providers: [transit-b]\n", "")
	ok = edit(t, ok, "    next_hop: 192.0.2.22\n", "    next_hop: 192.0.2.22\n    exclude: true\n")
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatalf("excluded unreached provider: %v", err)
	}
}
