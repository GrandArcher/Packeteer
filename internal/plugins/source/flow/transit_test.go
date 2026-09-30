package flow

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The operator's own network is 192.0.2.0/25; the customer (transiting)
// networks are 192.0.2.128/25 and 2001:db8:c::/48. Documentation prefixes only.
const transitYAML = "listen: 127.0.0.1:2055\ntransit:\n  customers: [192.0.2.128/25, \"2001:db8:c::/48\"]\n"

func mixOf(t *testing.T, s *Source) map[string]plugin.TrafficMix {
	t.Helper()
	rows, err := s.TrafficMix(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]plugin.TrafficMix{}
	for _, r := range rows {
		out[r.Prefix.String()] = r
	}
	return out
}

// Simulated flows: a NetFlow v5 export mixes local and customer sources
// toward three destinations; the class follows the transit byte share.
func TestTransitClassificationNetFlowV5(t *testing.T) {
	s := mustSource(t, transitYAML)
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	local := netip.MustParseAddr("192.0.2.10")
	cust := netip.MustParseAddr("192.0.2.200")
	toTransit := netip.MustParseAddr("198.51.100.10") // customer-originated only
	toLocal := netip.MustParseAddr("203.0.113.10")    // local only
	toMixed := netip.MustParseAddr("203.0.113.130")   // /25 below via RIB lookup
	s.SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) {
		if netip.MustParsePrefix("203.0.113.128/25").Contains(a) {
			return netip.MustParsePrefix("203.0.113.128/25"), true
		}
		return netip.Prefix{}, false
	})
	var recs []v5tcp
	for i := 0; i < 4; i++ {
		recs = append(recs, v5tcp{src: cust, dst: toTransit, proto: 17})
		recs = append(recs, v5tcp{src: local, dst: toLocal, proto: 17})
	}
	// Mixed: 3 customer records and 1 local (75% transit).
	recs = append(recs,
		v5tcp{src: cust, dst: toMixed, proto: 17},
		v5tcp{src: cust, dst: toMixed, proto: 17},
		v5tcp{src: cust, dst: toMixed, proto: 17},
		v5tcp{src: local, dst: toMixed, proto: 17},
	)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5TCP(0, recs))

	m := mixOf(t, s)
	if r := m["198.51.100.0/24"]; r.Class != plugin.TrafficTransit || r.TransitBytes != 400 || r.LocalBytes != 0 {
		t.Fatalf("transit prefix = %+v", r)
	}
	if r := m["203.0.113.0/24"]; r.Class != plugin.TrafficLocal || r.LocalBytes != 400 || r.TransitBytes != 0 {
		t.Fatalf("local prefix = %+v", r)
	}
	if r := m["203.0.113.128/25"]; r.Class != plugin.TrafficTransit || r.TransitPct() != 75 {
		t.Fatalf("mixed prefix = %+v (%v%%)", r, r.TransitPct())
	}
	// Classification does not change the targets or their weights.
	if ts := targetsOf(t, s); len(ts) != 3 || ts[0].Weight != 400 {
		t.Fatalf("targets = %+v", ts)
	}

	// A higher share_pct turns the 75% prefix local.
	s2 := mustSource(t, transitYAML+"  share_pct: 80\n")
	pin(s2, now)
	s2.SetPrefixLookup(s.lookup)
	s2.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5TCP(0, recs))
	if r := mixOf(t, s2)["203.0.113.128/25"]; r.Class != plugin.TrafficLocal {
		t.Fatalf("share_pct 80: %+v", r)
	}

	// Past the window the classification is gone with the counters.
	pin(s, now.Add(6*time.Minute))
	if m := mixOf(t, s); len(m) != 0 {
		t.Fatalf("after window: %+v", m)
	}
}

// Simulated sFlow and IPFIX: the source address is read from sampled
// records and raw headers (sFlow) and from IPFIX source IEs (IPv6).
func TestTransitClassificationSFlowAndIPFIX(t *testing.T) {
	s := mustSource(t, transitYAML)
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	exp := netip.MustParseAddr("192.0.2.8")
	s.ingest(now, exp, buildSFlowV4(10, netip.MustParseAddr("192.0.2.129"), netip.MustParseAddr("198.51.100.20"), 1500))
	s.ingest(now, exp, buildSFlowV6(1, netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:aaaa::1"), 128))
	// Raw Ethernet header with no source set: unknown, not classified.
	s.ingest(now, exp, buildSFlowEthernet(netip.MustParseAddr("203.0.113.15"), 60))

	cust6 := netip.MustParseAddr("2001:db8:c::5")
	dst6 := netip.MustParseAddr("2001:db8:ffff::20")
	rec := append(append(append([]byte{}, cust6.AsSlice()...), dst6.AsSlice()...), 0, 0, 0, 0, 0, 0, 0, 90)
	s.ingest(now, exp, buildIPFIX(1, tmplSetIPFIX(300, [][2]uint16{{ieSrcV6, 16}, {ieDstV6, 16}, {ieInBytes, 8}}), dataSet(300, rec)))

	m := mixOf(t, s)
	if r := m["198.51.100.0/24"]; r.Class != plugin.TrafficTransit || r.TransitBytes != 15000 {
		t.Fatalf("sflow v4 = %+v", r)
	}
	if r := m["2001:db8:aaaa::/48"]; r.Class != plugin.TrafficLocal || r.LocalBytes != 128 {
		t.Fatalf("sflow v6 = %+v", r)
	}
	if r, ok := m["203.0.113.0/24"]; ok {
		t.Fatalf("unknown source classified: %+v", r)
	}
	if r := m["2001:db8:ffff::/48"]; r.Class != plugin.TrafficTransit || r.TransitBytes != 90 {
		t.Fatalf("ipfix v6 = %+v", r)
	}
	// The unclassified prefix is still a target.
	found := false
	for _, tg := range targetsOf(t, s) {
		found = found || tg.Prefix.String() == "203.0.113.0/24"
	}
	if !found {
		t.Fatal("unclassified prefix dropped from targets")
	}
}

func TestTransitOffByDefault(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\n")
	now := time.Unix(1_700_000_000, 0)
	pin(s, now)
	s.ingest(now, netip.MustParseAddr("192.0.2.8"), buildV5TCP(0, []v5tcp{{src: netip.MustParseAddr("192.0.2.200"), dst: netip.MustParseAddr("198.51.100.10")}}))
	if rows, err := s.TrafficMix(context.Background()); err != nil || rows != nil {
		t.Fatalf("rows = %+v err %v", rows, err)
	}
	if len(targetsOf(t, s)) != 1 {
		t.Fatal("targets changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.TrafficMix(ctx); err == nil {
		t.Fatal("canceled context")
	}
}

func TestTransitConfigErrors(t *testing.T) {
	for _, tc := range []struct{ y, want string }{
		{"transit: {}\n", "transit.customers is required"},
		{"transit:\n  customers: [0.0.0.0/0]\n", "default route"},
		{"transit:\n  customers: [192.0.2.1/24]\n", "host bits"},
		{"transit:\n  customers: [nope]\n", "not a valid CIDR"},
		{"transit:\n  customers: [192.0.2.0/24, 192.0.2.0/24]\n", "duplicate"},
		{"transit:\n  customers: [192.0.2.0/24]\n  share_pct: 101\n", "share_pct"},
		{"transit:\n  customers: [192.0.2.0/24]\n  share_pct: -1\n", "share_pct"},
		{"transit:\n  customers: [192.0.2.0/24]\n  bogus: 1\n", "bogus"},
	} {
		_, err := build("listen: 127.0.0.1:2055\n" + tc.y)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.y, err, tc.want)
		}
	}
}
