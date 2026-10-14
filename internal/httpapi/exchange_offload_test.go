package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
)

func offloadServer(t *testing.T, m *ExchangeMembers) *httptest.Server {
	t.Helper()
	s, err := New(Options{Snapshot: func() Snapshot { return sampleSnap() }})
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		s.SetExchangeMembers(*m)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// #152: GET /api/exchanges/offload serves the report as JSON or CSV and
// passes the row limit to the report.
func TestExchangeOffloadEndpoint(t *testing.T) {
	saving := 160.0
	var limits []int
	ts := offloadServer(t, &ExchangeMembers{Offload: func(limit int) exchange.Offload {
		limits = append(limits, limit)
		return exchange.Offload{
			Prefixes: 1, Bytes: 100000000, Mbps: 80, EstSavings: &saving,
			Rows: []exchange.OffloadRow{{
				Prefix: "198.51.100.0/24", Bytes: 100000000, Mbps: 80, Transit: "transit-a",
				Peers: []exchange.OffloadPeerRef{{Exchange: "ix-lab", Peer: "ix-peer-a"}}, EstSavings: &saving,
			}},
		}
	}})

	code, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/offload", "", "")
	var got struct {
		exchange.Offload
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(body, &got); err != nil || code != http.StatusOK {
		t.Fatalf("json = %d %s: %v", code, body, err)
	}
	if got.Prefixes != 1 || len(got.Rows) != 1 || got.Rows[0].Transit != "transit-a" || got.Rows[0].Peers[0].Peer != "ix-peer-a" || *got.Rows[0].EstSavings != 160 {
		t.Fatalf("report = %s", body)
	}
	if limits[0] != defaultExchangeRows {
		t.Fatalf("json limit = %d", limits[0])
	}

	code, hdr, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/offload?format=csv", "", "")
	if code != http.StatusOK || !strings.HasPrefix(hdr.Get("Content-Type"), "text/csv") || !strings.Contains(hdr.Get("Content-Disposition"), "packeteer-exchange-offload.csv") {
		t.Fatalf("csv = %d %v", code, hdr)
	}
	if want := "prefix,bytes,mbps,transit,peers,est_savings\n198.51.100.0/24,100000000,80.00,transit-a,ix-lab/ix-peer-a,160.00\n"; string(body) != want {
		t.Fatalf("csv body = %q", body)
	}
	if limits[1] != maxExchangeRows {
		t.Fatalf("csv limit = %d, want the cap", limits[1])
	}

	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/exchanges/offload?limit=7", "", ""); code != http.StatusOK || limits[2] != 7 {
		t.Fatalf("limit=7: %d %v", code, limits)
	}
	for _, q := range []string{"limit=0", "limit=1001", "limit=x", "format=xml"} {
		if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/exchanges/offload?"+q, "", ""); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if code, _, _ := do(t, method, ts.URL+"/api/exchanges/offload", "", ""); code == http.StatusOK {
			t.Errorf("%s was accepted", method)
		}
	}
}

func TestExchangeOffloadWithoutExchanges(t *testing.T) {
	ts := offloadServer(t, nil)
	if code, _, _ := do(t, http.MethodGet, ts.URL+"/api/exchanges/offload", "", ""); code != http.StatusNotFound {
		t.Fatalf("no exchanges = %d, want 404", code)
	}
}
