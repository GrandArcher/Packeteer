package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

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
		{NextHop: netip.MustParseAddr("203.0.113.11"), Prefixes: 4, ASN: 64501},
		{NextHop: netip.MustParseAddr("203.0.113.13"), Prefixes: 2, ASN: 64503},
	}, map[string]bool{"ix-peer-a": true}, map[string]int{"ix-peer-a": 1})
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
	if len(doc.Exchanges) != 1 || doc.Exchanges[0].Peers[0].Prefixes != 4 || doc.Exchanges[0].Discovered[0].ASN != 64503 {
		t.Fatalf("body %s", body)
	}

	_, _, body = do(t, http.MethodGet, ts.URL+"/metrics", "", "")
	for _, want := range []string{
		`packeteer_exchange_peer_prefixes{exchange="ix-lab",peer="ix-peer-a"} 4`,
		`packeteer_exchange_peer_improvements{exchange="ix-lab",peer="ix-peer-a"} 1`,
		`packeteer_exchange_discovered_peers{exchange="ix-lab"} 1`,
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %s", want)
		}
	}

	// No exchanges: an empty list, not null.
	ts = newTestServer(t, sampleSnap(), "", "")
	_, _, body = do(t, http.MethodGet, ts.URL+"/api/exchanges", "", "")
	if !strings.Contains(string(body), `"exchanges":[]`) {
		t.Fatalf("empty body %s", body)
	}
}
