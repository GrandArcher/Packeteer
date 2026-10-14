package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func bmpPath(router, peer netip.Addr, p, nh string, id uint32) plugin.RIBEvent {
	return plugin.RIBEvent{
		Kind: plugin.RIBPaths, Router: router, Peer: plugin.RIBPeer{Address: peer}, PostPolicy: true,
		Paths: []plugin.RIBPath{{Prefix: netip.MustParsePrefix(p), NextHop: netip.MustParseAddr(nh), ASPath: []uint32{64501, 64500}, PathID: id}},
	}
}

// #156: /api/exchanges/member compares one member's route server and
// bilateral prefixes, read from a learned RIB view fed over BMP.
func TestExchangeMemberAvailability(t *testing.T) {
	edge := netip.MustParseAddr("192.0.2.254")
	member := netip.MustParseAddr("203.0.113.11")
	rs := netip.MustParseAddr("203.0.113.1")
	lan := netip.MustParsePrefix("203.0.113.0/24")
	view, err := rib.New(rib.Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"),
		Neighbors: []rib.Neighbor{{Address: edge}},
		LANs:      []netip.Prefix{lan},
		Providers: map[netip.Addr]string{member: "ix-peer-a"},
		PeerASN:   map[string]uint32{"ix-peer-a": 64501},
		BMP:       map[string]string{"ix-peer-a": rib.BMPPrefer},
	})
	if err != nil {
		t.Fatal(err)
	}
	view.ApplyRIB(bmpPath(edge, rs, "192.0.2.0/25", member.String(), 1))
	view.ApplyRIB(bmpPath(edge, member, "192.0.2.128/25", member.String(), 1))
	view.ApplyRIB(bmpPath(edge, rs, "198.51.100.0/24", member.String(), 2))
	view.ApplyRIB(bmpPath(edge, member, "198.51.100.0/24", member.String(), 2))
	view.ApplyRIB(bmpPath(edge, member, "203.0.113.128/25", member.String(), 3))

	exs := []exchange.Exchange{{Name: "ix-lab", LANs: []netip.Prefix{lan}, Peers: []exchange.Peer{{Name: "ix-peer-a", ASN: 64501, NextHop: member}}}}
	snap := sampleSnap()
	snap.Exchanges = exchange.Build(exs, view.NextHops([]netip.Prefix{lan}), nil, nil)
	s, err := New(Options{Snapshot: func() Snapshot { return snap }})
	if err != nil {
		t.Fatal(err)
	}
	hist := exchange.NewHistory()
	hist.Record(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), snap.Exchanges)
	s.SetExchangeMembers(ExchangeMembers{History: hist, Prefixes: view.MemberPrefixes})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	get := func(query string) (int, memberDetail) {
		t.Helper()
		code, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/member?"+query, "", "")
		var d memberDetail
		_ = json.Unmarshal(body, &d)
		return code, d
	}
	code, d := get("exchange=ix-lab&next_hop=203.0.113.11")
	want := exchange.Availability{RouteServerOnly: 1, BilateralOnly: 2, Both: 1, Flag: exchange.FlagRSPartial}
	if code != http.StatusOK || d.Availability != want || len(d.History) != 1 || d.History[0].BilateralOnly != 2 || d.Prefixes != nil {
		t.Fatalf("member = %d %+v", code, d)
	}
	code, d = get("exchange=ix-lab&next_hop=203.0.113.11&class=bilateral_only&limit=1")
	if code != http.StatusOK || d.Class != "bilateral_only" || d.PrefixesTotal != 2 || !slices.Equal(d.Prefixes, []string{"192.0.2.128/25"}) {
		t.Fatalf("bilateral_only limit 1 = %d %+v", code, d)
	}
	code, d = get("exchange=ix-lab&next_hop=203.0.113.11&class=both")
	if code != http.StatusOK || !slices.Equal(d.Prefixes, []string{"198.51.100.0/24"}) {
		t.Fatalf("both = %d %+v", code, d)
	}

	for _, q := range []string{
		"exchange=ix-lab&next_hop=nope",
		"exchange=ix-lab&next_hop=203.0.113.11&class=all",
		"exchange=ix-lab&next_hop=203.0.113.11&class=both&limit=0",
		"exchange=ix-lab&next_hop=203.0.113.11&class=both&limit=1001",
	} {
		if code, _ := get(q); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
	// A next hop that is not on the exchange is not read from the RIB.
	for _, q := range []string{"exchange=ix-lab&next_hop=192.0.2.21", "exchange=other&next_hop=203.0.113.11"} {
		if code, _ := get(q); code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", q, code)
		}
	}
	if code, _, _ := do(t, http.MethodPost, ts.URL+"/api/exchanges/member?exchange=ix-lab&next_hop=203.0.113.11", "", ""); code == http.StatusOK {
		t.Error("POST was accepted")
	}
}
