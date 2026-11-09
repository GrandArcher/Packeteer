package exchange

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func vol(prefix string, mbps float64) plugin.PrefixVolume {
	return plugin.PrefixVolume{Prefix: netip.MustParsePrefix(prefix), Bytes: uint64(mbps * 1e6 / 8 * 10), Window: 10 * time.Second}
}

func offloadInput() OffloadInput {
	cost := 2.5
	exit := map[string]string{
		"198.51.100.0/24": "transit-a",
		"192.0.2.0/25":    "transit-b",
		"192.0.2.128/25":  "ix-peer-a",
		"203.0.113.0/25":  "transit-a",
		"198.51.100.0/25": "transit-a",
		"2001:db8:1::/48": "transit-a",
		"2001:db8:2::/48": "transit-a",
	}
	adv := map[string]map[string]bool{
		"198.51.100.0/24": {"ix-peer-a": true},
		"192.0.2.0/25":    {"ix-peer-a": true, "ix-peer-b": true},
		"192.0.2.128/25":  {"ix-peer-a": true},
		"198.51.100.0/25": {"ix-peer-a": true},
		"2001:db8:1::/48": {"ix-peer-b": true},
		"2001:db8:2::/48": {"ix-peer-b": true},
	}
	return OffloadInput{
		Volumes: []plugin.PrefixVolume{
			vol("198.51.100.0/24", 80),
			vol("192.0.2.0/25", 120),
			vol("192.0.2.128/25", 500),
			vol("203.0.113.0/25", 900),
			vol("198.51.100.0/25", 0),
			vol("2001:db8:1::/48", 40),
			vol("2001:db8:2::/48", 40),
		},
		Transits: []Transit{{Name: "transit-a", Cost: &cost}, {Name: "transit-b"}},
		Peers:    []OffloadPeer{{Exchange: "ix-lab", Name: "ix-peer-a"}, {Exchange: "ix-lab", Name: "ix-peer-b"}},
		Exit:     func(p netip.Prefix) string { return exit[p.String()] },
		Advertises: func(p netip.Prefix, peer string) bool {
			return adv[p.String()][peer]
		},
	}
}

func TestBuildOffloadListsTransitPrefixesAnExchangePeerAdvertises(t *testing.T) {
	got := BuildOffload(offloadInput(), 0)
	// 192.0.2.128/25 leaves through a peer, 203.0.113.0/25 has no peer
	// route, 198.51.100.0/25 carries no bytes.
	var order []string
	for _, r := range got.Rows {
		order = append(order, r.Prefix)
	}
	if want := "192.0.2.0/25 198.51.100.0/24 2001:db8:1::/48 2001:db8:2::/48"; strings.Join(order, " ") != want {
		t.Fatalf("rows = %s, want %s", strings.Join(order, " "), want)
	}
	first := got.Rows[0]
	if first.Transit != "transit-b" || len(first.Peers) != 2 || first.Peers[1] != (OffloadPeerRef{Exchange: "ix-lab", Peer: "ix-peer-b"}) {
		t.Fatalf("first row = %+v", first)
	}
	if first.EstSavings != nil {
		t.Fatalf("a transit with no cost has savings %v", *first.EstSavings)
	}
	second := got.Rows[1]
	if second.Mbps != 80 || second.Bytes != 100000000 || second.EstSavings == nil || *second.EstSavings != 200 {
		t.Fatalf("second row = %+v", second)
	}
	// Equal bytes sort by prefix text.
	if got.Rows[2].Prefix != "2001:db8:1::/48" {
		t.Fatalf("tie order = %s", got.Rows[2].Prefix)
	}
	if got.Prefixes != 4 || got.Mbps != 280 || got.Bytes != 350000000 || got.EstSavings == nil || *got.EstSavings != 400 || got.Truncated {
		t.Fatalf("totals = %+v", got)
	}
}

func TestBuildOffloadLimitKeepsTotals(t *testing.T) {
	got := BuildOffload(offloadInput(), 1)
	if len(got.Rows) != 1 || got.Rows[0].Prefix != "192.0.2.0/25" || !got.Truncated || got.Prefixes != 4 || got.Mbps != 280 {
		t.Fatalf("limit 1 = %+v", got)
	}
}

func TestBuildOffloadEmptyIsAnEmptyList(t *testing.T) {
	in := offloadInput()
	in.Advertises = func(netip.Prefix, string) bool { return false }
	got := BuildOffload(in, 10)
	if got.Rows == nil || len(got.Rows) != 0 || got.Prefixes != 0 || got.EstSavings != nil || got.Truncated {
		t.Fatalf("empty report = %+v", got)
	}
}

func TestOffloadCSV(t *testing.T) {
	var sb strings.Builder
	if err := BuildOffload(offloadInput(), 2).WriteCSV(&sb); err != nil {
		t.Fatal(err)
	}
	want := "prefix,bytes,mbps,transit,peers,est_savings\n" +
		"192.0.2.0/25,150000000,120.00,transit-b,ix-lab/ix-peer-a ix-lab/ix-peer-b,\n" +
		"198.51.100.0/24,100000000,80.00,transit-a,ix-lab/ix-peer-a,200.00\n"
	if sb.String() != want {
		t.Fatalf("csv =\n%s\nwant\n%s", sb.String(), want)
	}
}
