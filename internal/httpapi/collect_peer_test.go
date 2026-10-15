package httpapi

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// The collector joins the BMP Adj-RIB-In counts into the exchange peer
// stats for /api/exchanges and the metric (#147).
func TestCollectorPeerAdjRIBIn(t *testing.T) {
	c := NewCollector("dev", "observe", nil)
	c.SetExchanges([]exchange.Exchange{{
		Name: "ix-lab", LANs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Peers: []exchange.Peer{{Name: "ix-peer-a", ASN: 64501, NextHop: netip.MustParseAddr("203.0.113.11")}},
	}}, nil)
	c.SetPeerPrefixes(func() map[string]int { return map[string]int{"ix-peer-a": 12} })
	c.SetStarted(true)
	snap := c.Snapshot()
	if len(snap.Exchanges) != 1 || len(snap.Exchanges[0].Peers) != 1 {
		t.Fatalf("exchanges = %+v", snap.Exchanges)
	}
	if got := snap.Exchanges[0].Peers[0].AdjRIBIn; got != 12 {
		t.Fatalf("adj_rib_in = %d, want 12", got)
	}
	if body := string(Metrics(snap)); !strings.Contains(body, `packeteer_exchange_peer_adj_rib_in{exchange="ix-lab",peer="ix-peer-a"} 12`) {
		t.Fatalf("metric missing: %s", body)
	}
}
