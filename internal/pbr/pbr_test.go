package pbr

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// cfg has a plain provider, two IX peers sharing one source by DSCP, one
// peer tagged by fwmark and DSCP, and an IPv6 peer. Documentation
// addresses only.
func testEntries(t *testing.T) []Entry {
	t.Helper()
	c, err := config.Parse([]byte(`
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: "ix peer/a", source_ip: 192.0.2.31, next_hop: 203.0.113.11, dscp: 10}
  - {name: ix-peer-b, source_ip: 192.0.2.31, next_hop: 203.0.113.12, dscp: 12}
  - {name: ix-peer-c, source_ip: 192.0.2.31, next_hop: 203.0.113.13, dscp: 14, fwmark: 103}
  - {name: ix-peer-v6, source_ip: "2001:db8:ffff::31", next_hop: "2001:db8:ffff::1", dscp: 16}
`))
	if err != nil {
		t.Fatal(err)
	}
	return Entries(c)
}

func TestEntries(t *testing.T) {
	es := testEntries(t)
	if len(es) != 5 || es[1].N != 2 || es[1].Ident() != "pk2-ix_peer_a" || es[3].FwMark != 103 || es[4].Source.String() != "2001:db8:ffff::31" {
		t.Fatalf("entries = %+v", es)
	}
}

func TestEntriesSkipRemoteProviders(t *testing.T) {
	cfg := &config.Config{Domain: "pop-a", Providers: []config.Provider{
		{Name: "local", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"},
		{Name: "far", NextHop: "192.0.2.2", Domain: "pop-b"},
	}}
	if es := Entries(cfg); len(es) != 1 || es[0].Name != "local" {
		t.Fatalf("entries = %+v", es)
	}
}

func TestGenerateLinux(t *testing.T) {
	out, err := Generate(Linux, testEntries(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ip route add default via 192.0.2.1 table 1001\n",
		"ip rule add from 192.0.2.11 lookup 1001 priority 2001\n",
		// dscp only: nftables maps it to a mark equal to the table id
		"nft add rule inet packeteer probes ip saddr 192.0.2.31 ip dscp 10 meta mark set 1002\n",
		"ip rule add from 192.0.2.31 fwmark 1002 lookup 1002 priority 2002\n",
		// fwmark set: the probe socket carries it, no nft rule
		"ip rule add from 192.0.2.31 fwmark 103 lookup 1004 priority 2004\n",
		"ip -6 route add default via 2001:db8:ffff::1 table 1005\n",
		"nft add rule inet packeteer probes ip6 saddr 2001:db8:ffff::31 ip6 dscp 16 meta mark set 1005\n",
		"ip -6 rule add from 2001:db8:ffff::31 fwmark 1005 lookup 1005 priority 2005\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "meta mark set 103") || strings.Count(out, "nft add table") != 1 {
		t.Errorf("fwmark provider got an nft rule, or the table is not added once:\n%s", out)
	}
}

func TestGenerateRouterFormats(t *testing.T) {
	es := testEntries(t)
	es[3].FwMark = 0 // routers only see the DSCP
	for format, wants := range map[string][]string{
		FRR: {
			"pbr-map PACKETEER seq 1\n match src-ip 192.0.2.11/32\n set nexthop 192.0.2.1\nexit\n",
			"pbr-map PACKETEER seq 2\n match src-ip 192.0.2.31/32\n match dscp 10\n set nexthop 203.0.113.11\nexit\n",
			"match src-ip 2001:db8:ffff::31/128\n match dscp 16\n set nexthop 2001:db8:ffff::1\n",
			"!  pbr-policy PACKETEER",
		},
		Junos: {
			"set firewall family inet filter PACKETEER-PROBES term pk1-transit-a from source-address 192.0.2.11/32\n",
			"term pk1-transit-a then next-ip 192.0.2.1\n",
			"term pk3-ix-peer-b from dscp 12\n",
			"set firewall family inet6 filter PACKETEER-PROBES term pk5-ix-peer-v6 from traffic-class 16\n",
			"term pk5-ix-peer-v6 then next-ip6 2001:db8:ffff::1\n",
			"set firewall family inet filter PACKETEER-PROBES term rest then accept\n",
			"set firewall family inet6 filter PACKETEER-PROBES term rest then accept\n",
		},
		Cisco: {
			"ip access-list extended ACL-pk1-transit-a\n permit ip host 192.0.2.11 any\n",
			"ip access-list extended ACL-pk3-ix-peer-b\n permit ip host 192.0.2.31 any dscp 12\n",
			"route-map PACKETEER-PROBES permit 3\n match ip address ACL-pk3-ix-peer-b\n set ip next-hop 203.0.113.12\n",
			"ipv6 access-list ACL-pk5-ix-peer-v6\n permit ipv6 host 2001:db8:ffff::31 any dscp 16\n",
			"set ipv6 next-hop 2001:db8:ffff::1\n",
			"!  ip policy route-map PACKETEER-PROBES\n!  ipv6 policy route-map PACKETEER-PROBES\n",
		},
		MikroTik: {
			"/routing table add name=pk1-transit-a fib\n",
			"/ip route add dst-address=0.0.0.0/0 gateway=192.0.2.1 routing-table=pk1-transit-a\n",
			"/routing rule add src-address=192.0.2.11/32 action=lookup-only-in-table table=pk1-transit-a\n",
			"/ip firewall mangle add chain=prerouting src-address=192.0.2.31/32 dscp=12 action=mark-routing new-routing-mark=pk3-ix-peer-b passthrough=no\n",
			"/ipv6 route add dst-address=::/0 gateway=2001:db8:ffff::1 routing-table=pk5-ix-peer-v6\n",
			"/ipv6 firewall mangle add chain=prerouting src-address=2001:db8:ffff::31/128 dscp=16 action=mark-routing",
		},
	} {
		out, err := Generate(format, es)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q in:\n%s", format, want, out)
			}
		}
	}
}

func TestGenerateRejectsFwmarkOnlyForRouters(t *testing.T) {
	es := testEntries(t) // ix-peer-c has fwmark and dscp: fine
	es[2].DSCP, es[2].FwMark = 0, 102
	for _, format := range []string{FRR, Junos, Cisco, MikroTik} {
		if _, err := Generate(format, es); err == nil || !strings.Contains(err.Error(), "ix-peer-b sets fwmark but no dscp") {
			t.Errorf("%s: err = %v", format, err)
		}
	}
	if _, err := Generate(Linux, es); err != nil {
		t.Errorf("linux: %v", err)
	}
}

func TestGenerateErrors(t *testing.T) {
	base := testEntries(t)
	if _, err := Generate("bogus", base); err == nil || !strings.Contains(err.Error(), `unknown format "bogus"`) {
		t.Errorf("unknown format: %v", err)
	}
	if _, err := Generate(Linux, nil); err == nil {
		t.Error("no entries must fail")
	}
	many := make([]Entry, maxFRRSeq+1)
	for i := range many {
		many[i] = Entry{N: i + 1, Name: "p", Source: base[0].Source, NextHop: base[0].NextHop}
	}
	if _, err := Generate(FRR, many); err == nil || !strings.Contains(err.Error(), "700") {
		t.Errorf("frr sequence limit: %v", err)
	}
}

// The nft mark of a dscp-only provider is its table id; a configured fwmark
// with the same value on the same source would match both rules.
func TestGenerateLinuxMarkClash(t *testing.T) {
	src, nh := netip.MustParseAddr("192.0.2.31"), netip.MustParseAddr("203.0.113.11")
	es := []Entry{
		{N: 1, Name: "a", Source: src, NextHop: nh, DSCP: 10},
		{N: 2, Name: "b", Source: src, NextHop: nh, FwMark: 1001},
	}
	if _, err := Generate(Linux, es); err == nil || !strings.Contains(err.Error(), "fwmark 1001") {
		t.Errorf("clash on one source: %v", err)
	}
	es[1].Source = netip.MustParseAddr("192.0.2.32")
	if _, err := Generate(Linux, es); err != nil {
		t.Errorf("same value on another source is fine: %v", err)
	}
}

// A provider name is free text in the config; it must not reach a router
// config as anything but a plain identifier.
func TestIdentSanitizesNames(t *testing.T) {
	for name, want := range map[string]string{
		"transit-a":                    "pk7-transit-a",
		"x\nreload; rm -rf /":          "pk7-x_reload_rm_-rf",
		"":                             "pk7",
		"@@@":                          "pk7",
		strings.Repeat("a", 40):        "pk7-" + strings.Repeat("a", 20),
		"ix peer \"quoted\" $(whoami)": "pk7-ix_peer_quoted_whoam",
	} {
		if got := (Entry{N: 7, Name: name}).Ident(); got != want {
			t.Errorf("Ident(%q) = %q, want %q", name, got, want)
		}
	}
}
