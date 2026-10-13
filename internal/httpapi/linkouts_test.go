package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/linkout"
)

type linkoutBody struct {
	Prefix map[string][]linkout.Link `json:"prefix"`
	ASN    map[string][]linkout.Link `json:"asn"`
}

func getLinkouts(t *testing.T, base, query string) (int, linkoutBody) {
	t.Helper()
	code, _, raw := do(t, http.MethodGet, base+"/api/linkouts"+query, "", "")
	var out linkoutBody
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	return code, out
}

func linkoutURL(ls []linkout.Link, name string) string {
	for _, l := range ls {
		if l.Name == name {
			return l.URL
		}
	}
	return ""
}

func TestLinkoutsAPI(t *testing.T) {
	base := newTestServer(t, Snapshot{Version: "test", Mode: "observe"}, "", "").URL
	q := url.Values{"prefix": {"198.51.100.0/24", "2001:db8::/32", "10.0.0.0/8"}, "asn": {"64496", "65000"}}
	code, got := getLinkouts(t, base, "?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if u := linkoutURL(got.Prefix["198.51.100.0/24"], "HE BGP Toolkit"); u != "https://bgp.he.net/net/198.51.100.0/24" {
		t.Errorf("IPv4 HE link = %q", u)
	}
	if u := linkoutURL(got.Prefix["2001:db8::/32"], "bgp.tools"); u != "https://bgp.tools/prefix/2001:db8::/32" {
		t.Errorf("IPv6 bgp.tools link = %q", u)
	}
	if u := linkoutURL(got.ASN["64496"], "PeeringDB"); u != "https://www.peeringdb.com/asn/64496" {
		t.Errorf("PeeringDB link = %q", u)
	}
	if u := linkoutURL(got.ASN["64496"], "Cloudflare Radar"); u != "https://radar.cloudflare.com/routing/as64496" {
		t.Errorf("Cloudflare Radar link = %q", u)
	}
	// hide_internal is on by default: the entry exists and is empty.
	if l, ok := got.Prefix["10.0.0.0/8"]; !ok || len(l) != 0 {
		t.Errorf("RFC 1918 prefix = %v, present %v", l, ok)
	}
	if l, ok := got.ASN["65000"]; !ok || len(l) != 0 {
		t.Errorf("private ASN = %v, present %v", l, ok)
	}
}

func TestLinkoutsAPIRejects(t *testing.T) {
	base := newTestServer(t, Snapshot{Version: "test", Mode: "observe"}, "", "").URL
	var many []string
	for range maxLinkoutObjects + 1 {
		many = append(many, "asn=64496")
	}
	for _, q := range []string{
		"?prefix=not-a-prefix", "?prefix=192.0.2.1", "?prefix=" + url.QueryEscape("192.0.2.0/24?x=1"),
		"?asn=0", "?asn=AS64496", "?asn=4294967296", "?asn=" + url.QueryEscape("64496/../x"),
		"?" + strings.Join(many, "&"),
	} {
		if code, _ := getLinkouts(t, base, q); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q[:min(len(q), 40)], code)
		}
	}
	if code, got := getLinkouts(t, base, ""); code != http.StatusOK || len(got.Prefix)+len(got.ASN) != 0 {
		t.Errorf("empty query = %d %+v", code, got)
	}
}

// TestLinkoutsConfigured wires a parsed linkouts block into the server the
// way the controller does.
func TestLinkoutsConfigured(t *testing.T) {
	cfg, err := config.Parse([]byte(`
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: lab-a, source_ip: 192.0.2.1, next_hop: 192.0.2.254}
linkouts:
  enabled: [nlnog_ring]
  hide_internal: false
  custom:
    - {name: internal LG, url: "https://lg.example.net/route?p={prefix}"}
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Snapshot: func() Snapshot { return Snapshot{} }, Linkouts: linkout.New(cfg.Linkouts)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	_, got := getLinkouts(t, ts.URL, "?prefix=10.0.0.0/8&asn=65000")
	want := []linkout.Link{
		{Name: "NLNOG RING looking glass", URL: "https://lg.ring.nlnog.net/prefix?q=10.0.0.0/8"},
		{Name: "internal LG", URL: "https://lg.example.net/route?p=10.0.0.0/8"},
	}
	if !reflect.DeepEqual(got.Prefix["10.0.0.0/8"], want) {
		t.Errorf("prefix links = %v, want %v", got.Prefix["10.0.0.0/8"], want)
	}
	if len(got.ASN["65000"]) != 0 {
		t.Errorf("asn links = %v, want none (no ASN site enabled)", got.ASN["65000"])
	}
}

func TestProviderCarriesExchangePeer(t *testing.T) {
	in := Input{Providers: []config.Provider{
		{Name: "ix-a", SourceIP: "192.0.2.1", NextHop: "192.0.2.2", Exchange: "ix-lab", PeerASN: 64496},
		{Name: "transit", SourceIP: "192.0.2.3", NextHop: "192.0.2.4"},
	}}
	rows := assembleProviders(in)
	if rows[0].Exchange != "ix-lab" || rows[0].PeerASN != 64496 || rows[1].Exchange != "" || rows[1].PeerASN != 0 {
		t.Fatalf("rows = %+v", rows)
	}
	raw, _ := json.Marshal(rows[1])
	if strings.Contains(string(raw), "peer_asn") || strings.Contains(string(raw), "exchange") {
		t.Errorf("a non-exchange provider carries exchange keys: %s", raw)
	}
}
