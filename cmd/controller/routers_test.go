package main

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Two edges and a route reflector (#27). edge-a forwards to transit-a and
// reaches transit-b through edge-b; edge-b forwards to transit-b; the route
// reflector has no list and reaches both.
const routersConfig = `
mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.21}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.22}
allowlist: {prefixes: ["198.51.100.0/24"]}
bgp:
  neighbors:
    - {address: 192.0.2.251, description: edge-a, providers: [transit-a], next_hops: {transit-b: 192.0.2.252}}
    - {address: 192.0.2.252, description: edge-b, providers: [transit-b]}
    - {address: 192.0.2.250, description: rr}
announcer: {type: gobgp}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, rtt_ms: 1}
`

func TestRouterExports(t *testing.T) {
	cfg, err := config.Parse([]byte(routersConfig))
	if err != nil {
		t.Fatal(err)
	}
	got, err := routerExports(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr
	if len(got) != 3 {
		t.Fatalf("routers = %+v", got)
	}
	if got[0].Neighbor != a("192.0.2.251") || len(got[0].Blocked) != 0 || got[0].Via[a("192.0.2.22")] != a("192.0.2.252") || len(got[0].Via) != 1 {
		t.Errorf("edge-a = %+v", got[0])
	}
	if got[1].Neighbor != a("192.0.2.252") || !slices.Equal(got[1].Blocked, []netip.Addr{a("192.0.2.21")}) || len(got[1].Via) != 0 {
		t.Errorf("edge-b = %+v", got[1])
	}
	if got[2].Neighbor != a("192.0.2.250") || len(got[2].Blocked) != 0 || len(got[2].Via) != 0 {
		t.Errorf("rr = %+v", got[2])
	}

	single, err := config.Parse([]byte(strings.Replace(routersConfig, `    - {address: 192.0.2.251, description: edge-a, providers: [transit-a], next_hops: {transit-b: 192.0.2.252}}
    - {address: 192.0.2.252, description: edge-b, providers: [transit-b]}
`, "", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := routerExports(single); err != nil || got != nil {
		t.Fatalf("unrestricted neighbors: %+v %v", got, err)
	}
}

func TestRunRoutersCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(routersConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{
		"192.0.2.251 edge-a providers=transit-a transit-b_via=192.0.2.252",
		"192.0.2.252 edge-b providers=transit-b",
		"  - 192.0.2.250 rr\n",
		"check: ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
}
