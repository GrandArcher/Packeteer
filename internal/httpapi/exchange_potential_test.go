package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

// #154: GET /api/exchanges/potential-peers serves the report as JSON or
// CSV and passes the class and the row limit to the report.
func TestExchangePotentialPeersEndpoint(t *testing.T) {
	var classes []string
	var limits []int
	ts := offloadServer(t, &ExchangeMembers{PotentialPeers: func(class string, limit int) exchange.PotentialPeers {
		classes, limits = append(classes, class), append(limits, limit)
		return exchange.PotentialPeers{
			ASNs: 1, Bytes: 100000000, Mbps: 80,
			Classes: map[string]exchange.ClassTotal{exchange.ClassRouteServer: {ASNs: 1, Bytes: 100000000}},
			Rows: []exchange.PotentialRow{{
				ASN: 64510, Class: exchange.ClassRouteServer, Bytes: 100000000, Mbps: 80, Prefixes: 2, LANPrefixes: 1, LANBytes: 60000000,
				Members: []exchange.MemberRef{{Exchange: "ix-lab", Peer: "ix-peer-a", NextHop: "203.0.113.11", Via: "route_server"}},
			}},
		}
	}})

	code, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers?class=route_server", "", "")
	var got exchange.PotentialPeers
	if err := json.Unmarshal(body, &got); err != nil || code != http.StatusOK {
		t.Fatalf("json = %d %s: %v", code, body, err)
	}
	if len(got.Rows) != 1 || got.Rows[0].ASN != 64510 || got.Rows[0].Members[0].Peer != "ix-peer-a" || got.Classes[exchange.ClassRouteServer].ASNs != 1 {
		t.Fatalf("report = %s", body)
	}
	if classes[0] != "route_server" || limits[0] != defaultExchangeRows {
		t.Fatalf("class %q limit %d", classes[0], limits[0])
	}

	code, hdr, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers?format=csv", "", "")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(hdr.Get("Content-Disposition"), "packeteer-potential-peers.csv") {
		t.Fatalf("csv = %d %v", code, hdr)
	}
	if want := "asn,class,bytes,mbps,prefixes,lan_prefixes,lan_bytes,members\nAS64510,route_server,100000000,80.00,2,1,60000000,ix-lab/ix-peer-a\n"; string(body) != want {
		t.Fatalf("csv body = %q", body)
	}
	if classes[1] != "" || limits[1] != maxExchangeRows {
		t.Fatalf("csv class %q limit %d", classes[1], limits[1])
	}

	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers?limit=7", "", ""); code != http.StatusOK || limits[2] != 7 {
		t.Fatalf("limit=7: %d %v", code, limits)
	}
	for _, q := range []string{"limit=0", "limit=1001", "limit=x", "format=xml", "class=both"} {
		if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers?"+q, "", ""); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
	if len(limits) != 3 {
		t.Errorf("a refused request reached the report: %v", limits)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if code, _, _ := do(t, method, ts.URL+"/api/exchanges/potential-peers", "", ""); code == http.StatusOK {
			t.Errorf("%s was accepted", method)
		}
	}
}

func TestExchangePotentialPeersWithoutExchanges(t *testing.T) {
	ts := offloadServer(t, nil)
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers", "", ""); code != http.StatusNotFound {
		t.Fatalf("no exchanges = %d, want 404", code)
	}
}
