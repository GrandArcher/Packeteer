package httpapi

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
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

// The exchange port's reading comes from the telemetry row named like the
// exchange (#151).
func TestCollectorExchangePort(t *testing.T) {
	c := NewCollector("dev", "observe", nil)
	c.SetExchanges([]exchange.Exchange{{
		Name: "ix-lab", LANs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Peers: []exchange.Peer{{Name: "ix-peer-a", ASN: 64501, NextHop: netip.MustParseAddr("203.0.113.11")}},
		Port:  &exchange.PortConfig{CapacityMbps: 1000, CommitMbps: 600},
	}}, nil)
	c.SetTelemetry(func() []plugin.Usage {
		return []plugin.Usage{{Provider: "ix-lab", CommitMbps: 1, Samples: 3, Single: true, UsageMbps: 500, OutMbps: 520, Updated: time.Now()}}
	})
	c.SetStarted(true)
	snap := c.Snapshot()
	pt := snap.Exchanges[0].Port
	if pt == nil || pt.State != exchange.PortOK || pt.LoadMbps != 520 || pt.P95Mbps != 500 || pt.HeadroomMbps != 100 {
		t.Fatalf("port = %+v", pt)
	}
	if len(snap.Telemetry) != 1 || snap.Telemetry[0].CommitMbps != 600 {
		t.Fatalf("telemetry = %+v, want the port row to carry the port commit 600", snap.Telemetry)
	}
	b, err := json.Marshal(snap.Exchanges[0])
	if err != nil || !strings.Contains(string(b), `"port":{"state":"ok","capacity_mbps":1000,"commit_mbps":600`) {
		t.Fatalf("json = %s %v", b, err)
	}
}

func TestCollectorExchangePortMaxAge(t *testing.T) {
	c := NewCollector("dev", "observe", nil)
	c.SetExchanges([]exchange.Exchange{{
		Name: "ix-lab", LANs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Peers: []exchange.Peer{{Name: "ix-peer-a", ASN: 64501, NextHop: netip.MustParseAddr("203.0.113.11")}},
		Port:  &exchange.PortConfig{CapacityMbps: 1000},
	}}, nil)
	c.SetTelemetry(func() []plugin.Usage {
		return []plugin.Usage{{Provider: "ix-lab", CommitMbps: 1, Samples: 3, Single: true, UsageMbps: 500, Updated: time.Now().Add(-20 * time.Minute)}}
	})
	c.SetStarted(true)
	if st := c.Snapshot().Exchanges[0].Port.State; st != exchange.PortStale {
		t.Fatalf("default limit: state = %s, want stale", st)
	}
	c.SetPortMaxAge(time.Hour)
	if st := c.Snapshot().Exchanges[0].Port.State; st != exchange.PortOK {
		t.Fatalf("scorer limit of 1h: state = %s, want ok", st)
	}
}
