package main

import (
	"testing"

	"github.com/GrandArcher/Packeteer/internal/policy"
)

const portConfigYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1, cost: 8}
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    port: {capacity_mbps: 10000, commit_mbps: 6000, port_cost: 1500}
    peers:
      - {name: ix-peer-a, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31}
  - name: ix-two
    lans: [198.51.100.0/24]
    peers:
      - {name: ix-two-peer, asn: 64502, next_hop: 198.51.100.11, source_ip: 192.0.2.32}
bgp:
  neighbors:
    - {address: 192.0.2.254, add_path: true}
`

func TestPolicyConfigPorts(t *testing.T) {
	pc, err := policyConfig(mustParse(t, portConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.Ports) != 1 || pc.Ports[0] != (policy.PortPolicy{Name: "ix-lab", CapacityMbps: 10000, CommitMbps: 6000}) {
		t.Fatalf("ports = %+v", pc.Ports)
	}
	by := map[string]policy.ProviderPolicy{}
	for _, p := range pc.Providers {
		by[p.Name] = p
	}
	if p := by["ix-peer-a"]; p.Port != "ix-lab" || !p.HasCost || p.Cost != 0 {
		t.Fatalf("peer on a port = %+v, want port ix-lab at marginal cost 0", p)
	}
	if p := by["ix-two-peer"]; p.Port != "" || p.HasCost {
		t.Fatalf("peer on an exchange with no port block = %+v", p)
	}
	if p := by["transit-a"]; p.Port != "" || !p.HasCost || p.Cost != 8 {
		t.Fatalf("transit = %+v", p)
	}
}
