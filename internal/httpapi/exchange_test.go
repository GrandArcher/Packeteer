package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// /api/exchanges and the exchange metrics (#27).
func TestExchangesEndpointAndMetrics(t *testing.T) {
	snap := sampleSnap()
	snap.Exchanges = exchange.Build([]exchange.Exchange{{
		Name:  "ix-lab",
		LANs:  []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		Peers: []exchange.Peer{{Name: "ix-peer-a", ASN: 64501, NextHop: netip.MustParseAddr("203.0.113.11")}},
	}}, []rib.NextHopCount{
		{NextHop: netip.MustParseAddr("203.0.113.11"), Prefixes: 4, ASN: 64501, Via: rib.ViaBilateral},
		{NextHop: netip.MustParseAddr("203.0.113.13"), Prefixes: 2, ASN: 64503},
	}, map[string]bool{"ix-peer-a": true}, map[string][]exchange.Move{"ix-peer-a": {{Prefix: "192.0.2.0/24", VolumeMbps: 12.5}}}, nil)
	ts := newTestServer(t, snap, "", "")

	code, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges", "", "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	var doc struct {
		Exchanges []exchange.Stats `json:"exchanges"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Exchanges) != 1 || doc.Exchanges[0].Peers[0].Prefixes != 4 || doc.Exchanges[0].Peers[0].Via != rib.ViaBilateral || doc.Exchanges[0].Discovered[0].ASN != 64503 {
		t.Fatalf("body %s", body)
	}
	if pa := doc.Exchanges[0].Peers[0]; pa.MovedMbps != 12.5 || len(pa.Moves) != 1 || pa.Moves[0].Prefix != "192.0.2.0/24" {
		t.Fatalf("moves: %s", body)
	}
	if !strings.Contains(string(body), `"via":"bilateral"`) {
		t.Fatalf("peer via missing: %s", body)
	}

	_, _, body = do(t, http.MethodGet, ts.URL+"/metrics", "", "")
	for _, want := range []string{
		`packeteer_exchange_peer_prefixes{exchange="ix-lab",peer="ix-peer-a"} 4`,
		`packeteer_exchange_peer_improvements{exchange="ix-lab",peer="ix-peer-a"} 1`,
		`packeteer_exchange_discovered_peers{exchange="ix-lab"} 1`,
		"packeteer_exchange_lan_targets_dropped 0",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	snap.Exchanges[0].Peers[0].AdjRIBIn = 12
	if body := Metrics(snap); !strings.Contains(string(body), `packeteer_exchange_peer_adj_rib_in{exchange="ix-lab",peer="ix-peer-a"} 12`) {
		t.Fatalf("adj_rib_in metric missing: %s", body)
	}
	snap.ExchangeLANDrops = 4
	body = Metrics(snap)
	if !strings.Contains(string(body), "packeteer_exchange_lan_targets_dropped 4") {
		t.Fatalf("non-zero drops missing: %s", body)
	}

	// No exchanges: an empty list, not null.
	ts = newTestServer(t, sampleSnap(), "", "")
	_, _, body = do(t, http.MethodGet, ts.URL+"/api/exchanges", "", "")
	if !strings.Contains(string(body), `"exchanges":[]`) {
		t.Fatalf("empty body %s", body)
	}
}

// #149: per-peer next-hop reachability on /api/exchanges and the metrics.
func TestExchangeHealthEndpointAndMetrics(t *testing.T) {
	lan := netip.MustParsePrefix("203.0.113.0/24")
	exs := []exchange.Exchange{{
		Name: "ix-lab", LANs: []netip.Prefix{lan},
		Peers: []exchange.Peer{
			{Name: "ix-peer-a", ASN: 64501, NextHop: netip.MustParseAddr("203.0.113.11")},
			{Name: "ix-peer-b", ASN: 64502, NextHop: netip.MustParseAddr("203.0.113.12")},
			{Name: "ix-peer-c", ASN: 64503, NextHop: netip.MustParseAddr("203.0.113.13")},
		},
	}, {Name: "ix-off", LANs: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")},
		Peers: []exchange.Peer{{Name: "off-peer", ASN: 64504, NextHop: netip.MustParseAddr("198.51.100.11")}}}}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h := exchange.NewHealth([]exchange.HealthSpec{{Exchange: "ix-lab", Peers: []string{"ix-peer-a", "ix-peer-b", "ix-peer-c"},
		HealthOptions: exchange.HealthOptions{LossPct: 50, MinPeers: 2, Window: 5 * time.Minute}}})
	h.Update(now, []exchange.HopSample{
		{Peer: "ix-peer-a", Measured: true, RTT: 4 * time.Millisecond},
		{Peer: "ix-peer-b", Measured: true, LossPct: 100},
		{Peer: "ix-peer-c", Measured: true, LossPct: 100},
	})
	snap := sampleSnap()
	snap.Exchanges = exchange.Build(exs, nil, nil, nil, h.Snapshot())
	ts := newTestServer(t, snap, "", "")

	_, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges", "", "")
	var doc struct {
		Exchanges []exchange.Stats `json:"exchanges"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	lab := doc.Exchanges[0]
	if !lab.Degraded || len(lab.DegradedPeers) != 2 || lab.Peers[0].Reach.State != "reachable" || lab.Peers[0].Reach.RTTMs != 4 ||
		lab.Peers[1].Reach.State != "unreachable" || !lab.Peers[1].Reach.Degraded || doc.Exchanges[1].Peers[0].Reach.State != "unknown" {
		t.Fatalf("body %s", body)
	}

	_, _, body = do(t, http.MethodGet, ts.URL+"/metrics", "", "")
	for _, want := range []string{
		`packeteer_exchange_peer_reachable{exchange="ix-lab",peer="ix-peer-a"} 1`,
		`packeteer_exchange_peer_reachable{exchange="ix-lab",peer="ix-peer-b"} 0`,
		`packeteer_exchange_peer_rtt_seconds{exchange="ix-lab",peer="ix-peer-a"} 0.004`,
		`packeteer_exchange_peer_loss_percent{exchange="ix-lab",peer="ix-peer-c"} 100`,
		`packeteer_exchange_degraded{exchange="ix-lab"} 1`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %s", want)
		}
	}
	// An unreachable peer has no RTT, and an exchange that is not probed
	// has no reachability or degraded series.
	for _, banned := range []string{`rtt_seconds{exchange="ix-lab",peer="ix-peer-b"}`, `degraded{exchange="ix-off"}`, `peer_reachable{exchange="ix-off"`, `peer_loss_percent{exchange="ix-off"`} {
		if strings.Contains(string(body), banned) {
			t.Errorf("metrics has %s", banned)
		}
	}
}
