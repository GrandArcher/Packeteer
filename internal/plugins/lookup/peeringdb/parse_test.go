package peeringdb

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestCleanAddr(t *testing.T) {
	for _, tc := range []struct {
		in    string
		want4 bool
		out   string
		ok    bool
	}{
		{"", true, "", true},
		{"192.0.2.10", true, "192.0.2.10", true},
		{"2001:db8::10", false, "2001:db8::10", true},
		{"2001:DB8:0:0::10", false, "2001:db8::10", true},
		{"::ffff:192.0.2.10", true, "192.0.2.10", true},
		{"192.0.2.10", false, "", false},
		{"2001:db8::10", true, "", false},
		{"not-an-ip", true, "", false},
		{"0.0.0.0", true, "", false},
		{"127.0.0.1", true, "", false},
		{"224.0.0.1", true, "", false},
		{"169.254.1.1", true, "", false},
		{"::1", false, "", false},
		{"fe80::1", false, "", false},
		{"ff02::1", false, "", false},
	} {
		out, ok := cleanAddr(tc.in, tc.want4)
		if out != tc.out || ok != tc.ok {
			t.Errorf("cleanAddr(%q, %v) = %q, %v; want %q, %v", tc.in, tc.want4, out, ok, tc.out, tc.ok)
		}
	}
}

func TestDecodeIXF(t *testing.T) {
	rows, err := decodeIXF([]byte(`{"version":"1.0","member_list":[
{"asnum":64496,"name":null,"connection_list":[
 {"state":"active","vlan_list":[{"ipv4":{"address":"192.0.2.10","routeserver":true},"ipv6":{"address":"bad","routeserver":true}}]},
 {"state":"connected","vlan_list":[{"ipv6":{"address":"2001:db8::10"}}]},
 {"state":"inactive","vlan_list":[{"ipv4":{"address":"192.0.2.99"}}]},
 {"vlan_list":[{"ipv4":{"address":"192.0.2.77"}}]},
 {"state":"active","vlan_list":[{"ipv4":{"address":"127.0.0.1"}}]}]},
{"asnum":0,"name":"No ASN","connection_list":[{"state":"active","vlan_list":[{"ipv4":{"address":"192.0.2.50"}}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	// The bad IPv6 drops that family only, so its routeserver flag does not
	// count; the loopback-only row and the zero ASN are dropped whole.
	want := []rawIXF{
		{asn: 64496, v4: "192.0.2.10", rs: true},
		{asn: 64496, v6: "2001:db8::10"},
		{asn: 64496, v4: "192.0.2.77"},
	}
	if len(rows) != len(want) {
		t.Fatalf("rows %+v", rows)
	}
	for i := range want {
		if rows[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, rows[i], want[i])
		}
	}
}

func TestDecodeIXFRejects(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"version":  {`{"version":"0.6","member_list":[]}`, "version"},
		"no doc":   {`[]`, "invalid JSON"},
		"bad json": {`{`, "invalid JSON"},
		"long":     {`{"version":"1.0","member_list":[{"asnum":64496,"name":"` + strings.Repeat("n", maxNameLen+1) + `"}]}`, "longer than the cap"},
		"number":   {`{"version":"1.0","member_list":[{"asnum":64496,"name":7}]}`, ""},
	} {
		_, err := decodeIXF([]byte(tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

func TestDecodeDirectorySkipsNonOK(t *testing.T) {
	ix, err := decodeIX([]byte(`{"data":[{"id":1,"name":"A","status":"ok"},{"id":2,"name":"B","status":"pending"},{"id":0,"name":"C","status":"ok"}]}`))
	if err != nil || len(ix) != 1 || ix[0].id != 1 {
		t.Fatalf("ix %+v err %v", ix, err)
	}
	nets, err := decodeNet([]byte(`{"data":[{"id":1,"asn":64496,"status":"ok"},{"id":2,"asn":0,"status":"ok"},{"id":3,"asn":64497,"status":"deleted"}]}`))
	if err != nil || len(nets) != 1 || nets[0].asn != 64496 {
		t.Fatalf("nets %+v err %v", nets, err)
	}
	orgs, err := decodeOrg([]byte(`{"data":[{"id":1,"name":"O1","status":"ok"},{"id":2,"name":"O2","status":"deleted"}]}`))
	if err != nil || len(orgs) != 1 || orgs[1] != "O1" {
		t.Fatalf("orgs %+v err %v", orgs, err)
	}
	if _, err := decodeOrg([]byte(`{"data":[{"id":1,"name":"` + strings.Repeat("o", maxNameLen+1) + `","status":"ok"}]}`)); err == nil {
		t.Fatal("long org name accepted")
	}
	lans, err := decodeLAN([]byte(`{"data":null}`))
	if err != nil || len(lans) != 0 {
		t.Fatalf("null data: %+v %v", lans, err)
	}
}

func TestNetPolicyLimit(t *testing.T) {
	_, err := decodeNet([]byte(`{"data":[{"id":1,"asn":64496,"policy_general":"` + strings.Repeat("p", maxPolicyLen+1) + `","status":"ok"}]}`))
	if err == nil {
		t.Fatal("long policy accepted")
	}
}

func TestMergeKeepsDifferentConcreteAddressSeparate(t *testing.T) {
	ex := exch{name: "example-ix", ixID: 1}
	members := []plugin.LookupMembership{
		{Exchange: "example-ix", ASN: 64496, IPv4: "192.0.2.10"},
		{Exchange: "example-ix", ASN: 64496, IPv4: "192.0.2.11", IPv6: "2001:db8::11"},
	}
	rows := []rawIXF{
		{asn: 64496, name: "N", v4: "192.0.2.10", v6: "2001:db8::10", rs: true},
		{asn: 64496, v4: "192.0.2.12"},
		{asn: 64496, v6: "2001:db8::99"},
	}
	merged, nets := mergeIXF(ex, "Example IX", rows, members, nil)
	if merged[0].IPv6 != "2001:db8::10" || !merged[0].RouteServer || merged[0].Name != "N" {
		t.Fatalf("first row not filled in: %+v", merged[0])
	}
	if merged[1].RouteServer || merged[1].IPv6 != "2001:db8::11" {
		t.Fatalf("second row changed: %+v", merged[1])
	}
	if len(merged) != 4 || merged[2].IPv4 != "192.0.2.12" || merged[3].IPv6 != "2001:db8::99" || merged[2].IXName != "Example IX" {
		t.Fatalf("merged %+v", merged)
	}
	if len(nets) != 1 || nets[0].ASN != 64496 || nets[0].Name != "N" {
		t.Fatalf("nets %+v", nets)
	}
}

func TestMatchRowPrefersMostSharedAddresses(t *testing.T) {
	rows := []plugin.LookupMembership{
		{ASN: 64496, IPv4: "192.0.2.10"},
		{ASN: 64496, IPv4: "192.0.2.10", IPv6: "2001:db8::10"},
		{ASN: 64496, IPv4: "192.0.2.20"},
	}
	cand := []int{0, 1, 2}
	if got := matchRow(rows, cand, rawIXF{asn: 64496, v4: "192.0.2.10", v6: "2001:db8::10"}); got != 1 {
		t.Fatalf("matched %d, want 1", got)
	}
	if got := matchRow(rows, cand, rawIXF{asn: 64496, v4: "192.0.2.99"}); got != -1 {
		t.Fatalf("other address matched %d", got)
	}
	if got := matchRow(rows, nil, rawIXF{asn: 64496, v4: "192.0.2.10"}); got != -1 {
		t.Fatalf("no candidates matched %d", got)
	}
}

func TestDedupeMembersMergesSameAttachment(t *testing.T) {
	in := []plugin.LookupMembership{
		{Exchange: "b", ASN: 64496, IPv4: "192.0.2.10"},
		{Exchange: "a", ASN: 64497, IPv4: "192.0.2.11", Name: "B"},
		{Exchange: "a", ASN: 64497, IPv4: "192.0.2.11", RouteServer: true, IXName: "Example IX"},
		{Exchange: "a", ASN: 64496, IPv4: "192.0.2.10"},
	}
	out := dedupeMembers(in)
	if len(out) != 3 {
		t.Fatalf("out %+v", out)
	}
	if out[0].Exchange != "a" || out[0].ASN != 64496 || out[1].ASN != 64497 || out[2].Exchange != "b" {
		t.Fatalf("order %+v", out)
	}
	if m := out[1]; !m.RouteServer || m.Name != "B" || m.IXName != "Example IX" {
		t.Fatalf("merged %+v", m)
	}
}

func TestDedupeNetworksFillsGaps(t *testing.T) {
	one, zero := 1, 0
	out := dedupeNetworks([]plugin.LookupNetwork{
		{ASN: 64497, Name: "B"},
		{ASN: 64496},
		{ASN: 64496, Name: "A", Org: "Org A", Policy: "Open", PolicyURL: "https://a.example.invalid", InfoPrefixes4: &one, InfoPrefixes6: &zero},
	})
	if len(out) != 2 || out[0].ASN != 64496 {
		t.Fatalf("out %+v", out)
	}
	a := out[0]
	if a.Name != "A" || a.Org != "Org A" || a.Policy != "Open" || a.PolicyURL == "" || a.InfoPrefixes4 == nil || a.InfoPrefixes6 == nil || *a.InfoPrefixes6 != 0 {
		t.Fatalf("merged %+v", a)
	}
}

func TestIXFRowCapIsPerExchange(t *testing.T) {
	list := []exch{{name: "a", ixID: 1}}
	ixf := map[string][]rawIXF{}
	for i := 0; i <= maxMemberships; i++ {
		ixf["a"] = append(ixf["a"], rawIXF{asn: uint32(64500 + i), v4: "192.0.2.10"})
	}
	v, err := assemble(list, []rawIX{{id: 1, name: "Example IX"}}, nil, nil, nil, ixf, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Memberships) != 0 || !strings.Contains(v.Exchanges[0].IXFError, "row cap") {
		t.Fatalf("members %d ixf error %q", len(v.Memberships), v.Exchanges[0].IXFError)
	}
}
