package ixf

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const sampleIXF = `{
  "version": "1.0",
  "generator": "test",
  "ixp_list": [{
    "ixp_id": 1,
    "shortname": "example-ix",
    "name": "Example IX",
    "support_email": "ops@example.invalid",
    "vlan": [{
      "id": 10,
      "name": "peering",
      "ipv4": {"prefix": "192.0.2.0", "mask_length": 24},
      "ipv6": {"prefix": "2001:db8:0:0:0:0:0:0", "mask_length": 64}
    }],
    "switch": [
      {"id": 8, "name": "sw2", "colo": "cab-b", "city": "Doc City", "country": "ZZ", "manufacturer": "acme", "model": "s1", "software": "sw"},
      {"id": 7, "name": "sw1", "colo": "cab-a"}
    ]
  }],
  "member_list": [
    {
      "asnum": 64497,
      "name": "Member B",
      "url": "https://member.example.invalid/hidden",
      "contact_email": ["hidden@example.invalid"],
      "contact_phone": ["+0-000-000-0000"],
      "connection_list": [{
        "ixp_id": 1,
        "state": "active",
        "if_list": [
          {"switch_id": 99, "if_speed": 1000},
          {"switch_id": 7, "if_speed": 10000, "if_phys_speed": 100000}
        ],
        "vlan_list": [{
          "vlan_id": 10,
          "ipv4": {
            "address": "::ffff:192.0.2.10",
            "routeserver": true,
            "as_macro": "AS64497:AS-EXAMPLE",
            "max_prefix": 100,
            "mac_addresses": ["02:00:00:00:00:01"]
          },
          "ipv6": {"address": "2001:db8:0:0:0:0:0:10", "routeserver": false, "max_prefix": 50}
        }]
      }]
    },
    {
      "asnum": 64496,
      "name": "Caf\u00e9",
      "connection_list": [{
        "ixp_id": 1,
        "state": "active",
        "if_list": [{"switch_id": 8, "if_speed": 1000}],
        "vlan_list": [{"vlan_id": 10, "ipv4": {"address": "192.0.2.20", "routeserver": false}}]
      }]
    }
  ]
}`

func TestParseSample(t *testing.T) {
	p, err := parseIXF([]byte(sampleIXF))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.members) != 2 || p.addresses != 3 {
		t.Fatalf("members %d addresses %d", len(p.members), p.addresses)
	}
	if p.members[0].ASN != 64496 || p.members[0].Name != "Caf\u00e9" {
		t.Fatalf("first member %+v", p.members[0])
	}
	a := p.members[0].Connections[0]
	if len(a.Addresses) != 1 || a.Addresses[0].Family != "ipv4" || a.Addresses[0].Address != "192.0.2.20" || a.Addresses[0].RouteServer {
		t.Fatalf("member A addresses %+v", a.Addresses)
	}
	if a.Interfaces[0].Switch != "sw2" || a.Interfaces[0].Colo != "cab-b" || a.Interfaces[0].SpeedMbps != 1000 || a.Interfaces[0].PhysSpeedMbps != nil {
		t.Fatalf("member A interface %+v", a.Interfaces[0])
	}
	b := p.members[1]
	if b.ASN != 64497 || b.Name != "Member B" || b.Connections[0].State != "active" {
		t.Fatalf("member B %+v", b)
	}
	ifaces := b.Connections[0].Interfaces
	if ifaces[0].SwitchID != 7 || ifaces[0].Switch != "sw1" || ifaces[0].Colo != "cab-a" || ifaces[0].SpeedMbps != 10000 || ifaces[0].PhysSpeedMbps == nil || *ifaces[0].PhysSpeedMbps != 100000 {
		t.Fatalf("speed interface %+v", ifaces[0])
	}
	if ifaces[1].SwitchID != 99 || ifaces[1].Switch != "" || ifaces[1].Colo != "" || ifaces[1].SpeedMbps != 1000 {
		t.Fatalf("missing switch %+v", ifaces[1])
	}
	addrs := b.Connections[0].Addresses
	if addrs[0].Family != "ipv4" || addrs[0].Address != "192.0.2.10" || !addrs[0].RouteServer || addrs[0].MaxPrefix != 100 || addrs[0].ASMacro != "AS64497:AS-EXAMPLE" || addrs[0].VLANID != 10 {
		t.Fatalf("v4 %+v", addrs[0])
	}
	if addrs[1].Family != "ipv6" || addrs[1].Address != "2001:db8::10" || addrs[1].RouteServer || addrs[1].MaxPrefix != 50 {
		t.Fatalf("v6 %+v", addrs[1])
	}
	if len(p.ixps) != 1 || p.ixps[0].VLANs[0].IPv4 != "192.0.2.0/24" || p.ixps[0].VLANs[0].IPv6 != "2001:db8::/64" {
		t.Fatalf("ixp %+v", p.ixps)
	}
	if p.ixps[0].Switches[0].ID != 7 || p.ixps[0].Switches[1].City != "Doc City" || p.ixps[0].Switches[1].Manufacturer != "acme" {
		t.Fatalf("switches %+v", p.ixps[0].Switches)
	}
	raw, err := json.Marshal(struct {
		IXPs    []plugin.IXPSite   `json:"ixps"`
		Members []plugin.IXPMember `json:"members"`
	}{p.ixps, p.members})
	if err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"hidden@example.invalid", "+0-000-000-0000", "02:00:00:00:00:01", "ops@example.invalid", "member.example.invalid"} {
		if strings.Contains(string(raw), hidden) {
			t.Fatalf("view contains %s: %s", hidden, raw)
		}
	}
}

func TestParseEmpty(t *testing.T) {
	p, err := parseIXF([]byte(`{"version":"1.0","ixp_list":[],"member_list":[]}`))
	if err != nil || len(p.members) != 0 || p.addresses != 0 || p.members == nil || p.ixps == nil {
		t.Fatalf("%+v %v", p, err)
	}
}

func TestParseRejects(t *testing.T) {
	secret := docSecret
	cases := []struct {
		body string
		want string
		hide string
	}{
		{`{"version":"0.7","member_list":[]}`, `version must be "1.0"`, ""},
		{`{"version":1.0}`, `version must be "1.0"`, ""},
		{`{"version":`, "invalid JSON", ""},
		{`{"version":"1.0","member_list":[{"asnum":0,"name":"n"}]}`, "asnum is invalid", ""},
		{`{"version":"1.0","member_list":[{"asnum":64496,"name":"n","connection_list":[{"vlan_list":[{"ipv4":{"address":"` + secret + `"}}]}]}]}`, "address is not an IP address", secret},
		{`{"version":"1.0","member_list":[{"asnum":64496,"name":"` + strings.Repeat("LONGTOKEN", 40) + `"}]}`, "longer than", "LONGTOKEN"},
	}
	for _, tc := range cases {
		_, err := parseIXF([]byte(tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("body %s err %v", tc.want, err)
		}
		if tc.hide != "" && strings.Contains(err.Error(), tc.hide) {
			t.Fatalf("error echoes %s: %v", tc.hide, err)
		}
	}
	_, err := parseIXF([]byte(overList("member_list", maxMembers+1, `{"asnum":64496,"name":"n"}`)))
	if err == nil || !strings.Contains(err.Error(), "member_list: more than") {
		t.Fatal(err)
	}
	_, err = parseIXF([]byte(overList("ixp_list", maxIXPs+1, `{"ixp_id":1}`)))
	if err == nil || !strings.Contains(err.Error(), "ixp_list: more than") {
		t.Fatal(err)
	}
	sw := `{"id":1,"name":"sw"}`
	body := `{"version":"1.0","ixp_list":[{"ixp_id":1,"switch":[` + joinN(sw, maxSwitchesIXP+1) + `]}]}`
	if _, err := parseIXF([]byte(body)); err == nil || !strings.Contains(err.Error(), "switch: more than") {
		t.Fatal(err)
	}
	full := `{"ixp_id":1,"switch":[` + joinN(sw, maxSwitchesIXP) + `]}`
	full2 := `{"ixp_id":2,"switch":[` + joinN(sw, maxSwitchesIXP) + `]}`
	if _, err := parseIXF([]byte(`{"version":"1.0","ixp_list":[` + full + `,` + full2 + `]}`)); err != nil {
		t.Fatal(err)
	}
	over := `{"version":"1.0","ixp_list":[` + full + `,` + full2 + `,{"ixp_id":3,"switch":[` + sw + `]}]}`
	if _, err := parseIXF([]byte(over)); err == nil || !strings.Contains(err.Error(), "more than 4000 switches") {
		t.Fatal(err)
	}
	conn := `{"version":"1.0","member_list":[{"asnum":64496,"connection_list":[` + joinN(`{}`, maxConns+1) + `]}]}`
	if _, err := parseIXF([]byte(conn)); err == nil || !strings.Contains(err.Error(), "connection_list: more than") {
		t.Fatal(err)
	}
	ifaces := `{"version":"1.0","member_list":[{"asnum":64496,"connection_list":[{"if_list":[` + joinN(`{"switch_id":1,"if_speed":10}`, maxIfaces+1) + `]}]}]}`
	if _, err := parseIXF([]byte(ifaces)); err == nil || !strings.Contains(err.Error(), "if_list: more than") {
		t.Fatal(err)
	}
	vlans := `{"version":"1.0","member_list":[{"asnum":64496,"connection_list":[{"vlan_list":[` + joinN(`{}`, maxVLANs+1) + `]}]}]}`
	if _, err := parseIXF([]byte(vlans)); err == nil || !strings.Contains(err.Error(), "vlan_list: more than") {
		t.Fatal(err)
	}
}

func overList(field string, n int, item string) string {
	return `{"version":"1.0","` + field + `":[` + joinN(item, n) + `]}`
}

func joinN(item string, n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = item
	}
	return strings.Join(parts, ",")
}
