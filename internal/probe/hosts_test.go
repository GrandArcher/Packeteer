package probe

import (
	"net/netip"
	"testing"
)

func TestProbeHostsPinWins(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	pin := netip.MustParseAddr("198.51.100.9")
	gw := netip.MustParseAddr("192.0.2.21")
	src := netip.MustParseAddr("192.0.2.11")
	got := ProbeHosts(p, pin, netip.MustParseAddr("198.51.100.50"), gw, src)
	if len(got) != 1 || got[0] != pin {
		t.Fatalf("pin = %v", got)
	}
}

func TestProbeHostsAutoAndGateway(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	gw := netip.MustParseAddr("192.0.2.21")
	src := netip.MustParseAddr("192.0.2.11")
	got := ProbeHosts(p, netip.Addr{}, netip.Addr{}, gw, src)
	want := []string{"198.51.100.1", "198.51.100.64", "198.51.100.128", "192.0.2.21"}
	if len(got) != len(want) {
		t.Fatalf("hosts = %v", got)
	}
	for i, s := range want {
		if got[i].String() != s {
			t.Fatalf("hosts = %v", got)
		}
	}
	// The probe source is our side, not a far-side gateway.
	if got := ProbeHosts(p, netip.Addr{}, netip.Addr{}, src, src); len(got) != 3 || got[2].String() == src.String() {
		t.Fatalf("source used as gateway: %v", got)
	}
	// Wrong family and non-unicast are not targets.
	if got := ProbeHosts(p, netip.Addr{}, netip.Addr{}, netip.MustParseAddr("2001:db8::1"), src); len(got) != 3 {
		t.Fatalf("v6 gateway on v4 prefix: %v", got)
	}
	if got := ProbeHosts(p, netip.Addr{}, netip.Addr{}, netip.MustParseAddr("127.0.0.1"), src); len(got) != 3 {
		t.Fatalf("loopback gateway: %v", got)
	}
}

func TestProbeHostsCandidateFirst(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	gw := netip.MustParseAddr("192.0.2.21")
	src := netip.MustParseAddr("192.0.2.11")
	busy := netip.MustParseAddr("198.51.100.50")
	// A new candidate takes an in-prefix slot. The halfway point yields
	// so the gateway still fits. Four addresses, candidate first.
	got := ProbeHosts(p, netip.Addr{}, busy, gw, src)
	want := []string{"198.51.100.50", "198.51.100.1", "198.51.100.64", "192.0.2.21"}
	if len(got) != len(want) {
		t.Fatalf("hosts = %v", got)
	}
	for i, s := range want {
		if got[i].String() != s {
			t.Fatalf("hosts = %v", got)
		}
	}
	// A candidate that is already an automatic host is probed first and
	// is not duplicated, so the halfway point and the gateway both fit.
	quarter := netip.MustParseAddr("198.51.100.64")
	got = ProbeHosts(p, netip.Addr{}, quarter, gw, src)
	want = []string{"198.51.100.64", "198.51.100.1", "198.51.100.128", "192.0.2.21"}
	if len(got) != len(want) {
		t.Fatalf("quarter candidate = %v", got)
	}
	for i, s := range want {
		if got[i].String() != s {
			t.Fatalf("quarter candidate = %v", got)
		}
	}
	// No usable gateway: the candidate and all three automatic hosts.
	got = ProbeHosts(p, netip.Addr{}, busy, src, src)
	want = []string{"198.51.100.50", "198.51.100.1", "198.51.100.64", "198.51.100.128"}
	if len(got) != len(want) {
		t.Fatalf("no gateway = %v", got)
	}
	for i, s := range want {
		if got[i].String() != s {
			t.Fatalf("no gateway = %v", got)
		}
	}
	// A candidate outside the prefix is ignored.
	got = ProbeHosts(p, netip.Addr{}, netip.MustParseAddr("203.0.113.9"), gw, src)
	want = []string{"198.51.100.1", "198.51.100.64", "198.51.100.128", "192.0.2.21"}
	if len(got) != len(want) || got[0].String() != want[0] {
		t.Fatalf("outside candidate = %v", got)
	}
}

func TestAutoHostsBounds(t *testing.T) {
	cases := []struct {
		prefix string
		want   []string
	}{
		{"198.51.100.5/32", []string{"198.51.100.5"}},
		{"198.51.100.0/31", []string{"198.51.100.1"}},
		{"198.51.100.0/30", []string{"198.51.100.1", "198.51.100.2"}},
		{"2001:db8::/32", []string{"2001:db8::1", "2001:db8::10:0", "2001:db8::4000:0"}},
	}
	for _, tc := range cases {
		got := autoHosts(netip.MustParsePrefix(tc.prefix))
		if len(got) != len(tc.want) {
			t.Fatalf("%s = %v", tc.prefix, got)
		}
		for i, s := range tc.want {
			if got[i].String() != s {
				t.Fatalf("%s = %v", tc.prefix, got)
			}
		}
		if len(got) > maxInPrefix {
			t.Fatalf("%s exceeded cap", tc.prefix)
		}
	}
}
