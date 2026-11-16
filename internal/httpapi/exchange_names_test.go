package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// cachedLookup is a recorded directory view: documentation ASNs, one network
// with a name, one with none.
func cachedLookup() plugin.LookupView {
	return plugin.LookupView{
		Configured: true, NetworkCount: 2,
		Networks: []plugin.LookupNetwork{
			{ASN: 64510, Name: "Lab Network Ten", Org: "Lab Org Ten"},
			{ASN: 64511, Org: "Lab Org Eleven"},
		},
	}
}

// namesServer serves the potential-peers report and /api/exchanges, with the
// lookup set to view (nil leaves it unset). calls counts the view reads, which
// are the only thing the request path may do with the lookup.
func namesServer(t *testing.T, view *plugin.LookupView, calls *int) (*httptest.Server, *[]exchange.PotentialRow) {
	t.Helper()
	snap := sampleSnap()
	snap.Exchanges = []exchange.Stats{{Name: "ix-lab", Discovered: []exchange.Discovered{
		{NextHop: "203.0.113.13", ASN: 64510, Prefixes: 3},
		{NextHop: "203.0.113.14", ASN: 64512, Prefixes: 1},
		{NextHop: "203.0.113.15", Prefixes: 1},
	}}}
	s, err := New(Options{Snapshot: func() Snapshot { return snap }})
	if err != nil {
		t.Fatal(err)
	}
	if view != nil {
		s.SetLookup(func() plugin.LookupView { *calls++; return *view })
	}
	rows := []exchange.PotentialRow{
		{ASN: 64510, Class: exchange.ClassRouteServer, Members: []exchange.MemberRef{}},
		{ASN: 64511, Class: exchange.ClassBilateral, Members: []exchange.MemberRef{}},
		{ASN: 64512, Class: exchange.ClassAbsent, Members: []exchange.MemberRef{}},
	}
	s.SetExchangeMembers(ExchangeMembers{PotentialPeers: func(string, int) exchange.PotentialPeers {
		return exchange.PotentialPeers{ASNs: 3, Rows: rows}
	}})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, &rows
}

// #629: the potential-peers JSON and CSV carry the cached network name; an
// ASN with no cached name has none, and the report's own rows are not written.
func TestPotentialPeersNamesFromCachedLookup(t *testing.T) {
	view := cachedLookup()
	calls := 0
	ts, rows := namesServer(t, &view, &calls)

	code, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers", "", "")
	var got exchange.PotentialPeers
	if err := json.Unmarshal(body, &got); err != nil || code != http.StatusOK || len(got.Rows) != 3 {
		t.Fatalf("json = %d %s: %v", code, body, err)
	}
	if got.Rows[0].Name != "Lab Network Ten" || got.Rows[1].Name != "" || got.Rows[2].Name != "" {
		t.Fatalf("names = %q %q %q", got.Rows[0].Name, got.Rows[1].Name, got.Rows[2].Name)
	}
	if strings.Count(string(body), `"name"`) != 1 {
		t.Fatalf("an unnamed row has a name key: %s", body)
	}
	if (*rows)[0].Name != "" {
		t.Fatal("the report's rows were written")
	}

	_, _, body = do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers?format=csv", "", "")
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "asn,name,class,") ||
		!strings.HasPrefix(lines[1], "AS64510,Lab Network Ten,route_server,") ||
		!strings.HasPrefix(lines[2], "AS64511,,bilateral,") {
		t.Fatalf("csv = %q", body)
	}
	if calls != 2 {
		t.Fatalf("lookup view read %d times for 2 requests", calls)
	}
}

// #629: without a configured lookup, or while its cache is stale (the view
// then has no networks), the report is the ASN alone.
func TestPotentialPeersWithoutCachedNames(t *testing.T) {
	stale := plugin.LookupView{Configured: true, Stale: true, Error: "refresh failed"}
	for name, view := range map[string]*plugin.LookupView{"unset": nil, "stale": &stale} {
		calls := 0
		ts, _ := namesServer(t, view, &calls)
		_, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges/potential-peers", "", "")
		if !strings.Contains(string(body), `"asn":64510`) || strings.Contains(string(body), `"name"`) {
			t.Errorf("%s: body = %s", name, body)
		}
		_, _, body = do(t, http.MethodGet, ts.URL+"/api/exchanges", "", "")
		if !strings.Contains(string(body), `"next_hop":"203.0.113.13"`) || strings.Contains(string(body), "Lab Network") {
			t.Errorf("%s: exchanges = %s", name, body)
		}
	}
}

// #629: a discovered member carries the cached name next to its AS, so the
// settings form can show it; a member with no cached name or no AS has none.
func TestDiscoveredMembersNamedFromCachedLookup(t *testing.T) {
	view := cachedLookup()
	calls := 0
	ts, _ := namesServer(t, &view, &calls)
	code, _, body := do(t, http.MethodGet, ts.URL+"/api/exchanges", "", "")
	var got struct {
		Exchanges []exchange.Stats `json:"exchanges"`
	}
	if err := json.Unmarshal(body, &got); err != nil || code != http.StatusOK || len(got.Exchanges) != 1 {
		t.Fatalf("exchanges = %d %s: %v", code, body, err)
	}
	var names []string
	for _, d := range got.Exchanges[0].Discovered {
		names = append(names, d.NextHop+"="+d.Name)
	}
	if want := "203.0.113.13=Lab Network Ten 203.0.113.14= 203.0.113.15="; strings.Join(names, " ") != want {
		t.Fatalf("discovered = %q, want %q", strings.Join(names, " "), want)
	}
}

// #629: naming members copies the snapshot instead of writing it.
func TestWithMemberNamesLeavesSnapshot(t *testing.T) {
	view := cachedLookup()
	s, err := New(Options{Snapshot: func() Snapshot { return sampleSnap() }})
	if err != nil {
		t.Fatal(err)
	}
	s.SetLookup(func() plugin.LookupView { return view })
	exs := []exchange.Stats{{Name: "ix-lab", Discovered: []exchange.Discovered{{NextHop: "203.0.113.13", ASN: 64510}}}}
	out := s.withMemberNames(exs)
	if out[0].Discovered[0].Name != "Lab Network Ten" || exs[0].Discovered[0].Name != "" {
		t.Fatalf("out %+v in %+v", out[0].Discovered, exs[0].Discovered)
	}
}
