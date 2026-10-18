package peeringdb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const docKey = "doc-key-0123456789abcdef"

const (
	ixJSON  = `{"data":[{"id":1,"name":"Example IX","city":"Example City","country":"ZZ","status":"ok"}]}`
	lanJSON = `{"data":[
{"net_id":10,"ix_id":1,"asn":64496,"ipaddr4":"192.0.2.10","ipaddr6":"2001:db8::10","is_rs_peer":true,"status":"ok"},
{"net_id":11,"ix_id":1,"asn":64497,"ipaddr4":"192.0.2.11","ipaddr6":null,"is_rs_peer":false,"status":"ok"},
{"net_id":12,"ix_id":1,"asn":64498,"ipaddr4":"not-an-ip","ipaddr6":null,"is_rs_peer":false,"status":"ok"},
{"net_id":13,"ix_id":1,"asn":64499,"ipaddr4":"192.0.2.13","ipaddr6":null,"is_rs_peer":false,"status":"deleted"}]}`
	netJSON = `{"data":[
{"id":10,"org_id":100,"asn":64496,"name":"Net A","policy_general":"Open","policy_url":"https://a.example.invalid/peering","info_prefixes4":120,"info_prefixes6":0,"status":"ok"},
{"id":11,"org_id":101,"asn":64497,"name":"Net B","policy_general":"Selective","status":"ok"}]}`
	orgJSON = `{"data":[{"id":100,"name":"Org A","status":"ok"},{"id":101,"name":"Org B","status":"ok"}]}`
)

// pdb is a fake PeeringDB. A nil body field serves an empty data array.
type pdb struct {
	mu       sync.Mutex
	ix, lan  string
	net, org string
	status   int
	requests []string
	auth     []string
	methods  []string
}

func newPDB() *pdb { return &pdb{ix: ixJSON, lan: lanJSON, net: netJSON, org: orgJSON} }

func (p *pdb) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.requests = append(p.requests, r.URL.RequestURI())
	p.auth = append(p.auth, r.Header.Get("Authorization"))
	p.methods = append(p.methods, r.Method)
	status, body := p.status, ""
	switch r.URL.Path {
	case "/api/ix":
		body = p.ix
	case "/api/netixlan":
		body = p.lan
	case "/api/net":
		body = p.net
	case "/api/org":
		body = p.org
	}
	p.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if body == "" {
		http.NotFound(w, r)
		return
	}
	_, _ = io.WriteString(w, body)
}

func (p *pdb) snapshot() (reqs, auth []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.requests...), append([]string(nil), p.auth...)
}

func newSource(t *testing.T, yml, key string) *Source {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML(yml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Getenv: func(k string) string {
		if k == APIKeyEnv {
			return key
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := p.(*Source)
	s.sleep = func(context.Context, time.Duration) error { return nil }
	return s
}

func exchangesYAML(base string) string {
	return "base_url: " + base + "\nexchanges:\n  - {name: example-ix, ix_id: 1}\n"
}

func TestFetchBuildsView(t *testing.T) {
	fake := newPDB()
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), docKey)
	s.http.Transport = srv.Client().Transport
	s.fetch(t.Context())

	v := s.View()
	if v.Error != "" || v.Stale || v.Anonymous || !v.Configured || v.Fetched.IsZero() {
		t.Fatalf("view %+v", v)
	}
	if v.NetworkCount != 2 || v.MembershipCount != 2 {
		t.Fatalf("counts %d %d", v.NetworkCount, v.MembershipCount)
	}
	ex := v.Exchanges[0]
	if ex.Name != "example-ix" || ex.IXName != "Example IX" || ex.City != "Example City" || ex.Country != "ZZ" || ex.Error != "" {
		t.Fatalf("exchange %+v", ex)
	}
	a := v.Networks[0]
	if a.ASN != 64496 || a.Name != "Net A" || a.Org != "Org A" || a.Policy != "Open" || a.PolicyURL != "https://a.example.invalid/peering" {
		t.Fatalf("network A %+v", a)
	}
	if a.InfoPrefixes4 == nil || *a.InfoPrefixes4 != 120 || a.InfoPrefixes6 == nil || *a.InfoPrefixes6 != 0 {
		t.Fatalf("info prefixes A %v %v", a.InfoPrefixes4, a.InfoPrefixes6)
	}
	b := v.Networks[1]
	if b.Org != "Org B" || b.InfoPrefixes4 != nil || b.InfoPrefixes6 != nil {
		t.Fatalf("network B %+v", b)
	}
	want := []plugin.LookupMembership{
		{Exchange: "example-ix", IXID: 1, IXName: "Example IX", ASN: 64496, Name: "Net A", IPv4: "192.0.2.10", IPv6: "2001:db8::10", RouteServer: true},
		{Exchange: "example-ix", IXID: 1, IXName: "Example IX", ASN: 64497, Name: "Net B", IPv4: "192.0.2.11"},
	}
	for i, m := range want {
		if v.Memberships[i] != m {
			t.Fatalf("membership %d = %+v, want %+v", i, v.Memberships[i], m)
		}
	}
	// 64498 has only an unparsable address, so it has no usable attachment,
	// and 64499 is deleted.
	for _, m := range v.Memberships {
		if m.ASN == 64498 || m.ASN == 64499 {
			t.Fatalf("kept %+v", m)
		}
	}

	reqs, auth := fake.snapshot()
	wantReqs := []string{
		"/api/ix?id__in=1",
		"/api/netixlan?ix_id__in=1&status=ok",
		"/api/net?id__in=10,11,12",
		"/api/org?id__in=100,101",
	}
	if len(reqs) != len(wantReqs) {
		t.Fatalf("requests %v", reqs)
	}
	for i := range wantReqs {
		if reqs[i] != wantReqs[i] || auth[i] != "Api-Key "+docKey {
			t.Fatalf("request %d = %q auth %q", i, reqs[i], auth[i])
		}
	}
	for _, m := range fake.methods {
		if m != http.MethodGet {
			t.Fatalf("method %s", m)
		}
	}
}

func TestAnonymousSendsNoAuthorization(t *testing.T) {
	fake := newPDB()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), "")
	s.fetch(t.Context())
	v := s.View()
	if !v.Anonymous || v.Error != "" || v.NetworkCount != 2 {
		t.Fatalf("view %+v", v)
	}
	_, auth := fake.snapshot()
	for _, a := range auth {
		if a != "" {
			t.Fatalf("anonymous request carried %q", a)
		}
	}
}

func TestRequestsArePaced(t *testing.T) {
	for _, tc := range []struct {
		key      string
		min, max time.Duration
	}{
		{"", 2500 * time.Millisecond, anonymousGap},
		{docKey, 1500 * time.Millisecond, keyedGap},
	} {
		fake := newPDB()
		srv := httptest.NewTLSServer(fake)
		s := newSource(t, exchangesYAML(srv.URL), tc.key)
		s.http.Transport = srv.Client().Transport
		var waits []time.Duration
		s.sleep = func(_ context.Context, d time.Duration) error {
			waits = append(waits, d)
			return nil
		}
		s.fetch(t.Context())
		srv.Close()
		reqs, _ := fake.snapshot()
		if len(waits) != len(reqs)-1 {
			t.Fatalf("key %q: %d waits for %d requests", tc.key, len(waits), len(reqs))
		}
		for _, d := range waits {
			if d < tc.min || d > tc.max {
				t.Fatalf("key %q: wait %s outside %s..%s", tc.key, d, tc.min, tc.max)
			}
		}
	}
}

func TestChunksLargeIDLists(t *testing.T) {
	var lan, nets, orgs strings.Builder
	lan.WriteString(`{"data":[`)
	nets.WriteString(`{"data":[`)
	orgs.WriteString(`{"data":[`)
	const n = netChunk + 1
	for i := 1; i <= n; i++ {
		sep := ","
		if i == 1 {
			sep = ""
		}
		fmt.Fprintf(&lan, `%s{"net_id":%d,"ix_id":1,"asn":%d,"ipaddr4":"192.0.2.%d","status":"ok"}`, sep, i, 65000+i, i%250+1)
		fmt.Fprintf(&nets, `%s{"id":%d,"org_id":%d,"asn":%d,"name":"N%d","status":"ok"}`, sep, i, 1000+i, 65000+i, i)
		fmt.Fprintf(&orgs, `%s{"id":%d,"name":"O%d","status":"ok"}`, sep, 1000+i, i)
	}
	lan.WriteString(`]}`)
	nets.WriteString(`]}`)
	orgs.WriteString(`]}`)
	fake := newPDB()
	fake.lan, fake.net, fake.org = lan.String(), nets.String(), orgs.String()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), "")
	s.fetch(t.Context())
	reqs, _ := fake.snapshot()
	var netReqs, orgReqs int
	for _, r := range reqs {
		switch {
		case strings.HasPrefix(r, "/api/net?"):
			netReqs++
			if got := strings.Count(r, ",") + 1; got > netChunk {
				t.Fatalf("net request has %d ids", got)
			}
		case strings.HasPrefix(r, "/api/org?"):
			orgReqs++
		}
	}
	if netReqs != 2 || orgReqs != 2 {
		t.Fatalf("net %d org %d requests: %v", netReqs, orgReqs, reqs)
	}
	if v := s.View(); v.Error != "" || v.NetworkCount != netChunk+1 {
		t.Fatalf("view error %q networks %d", v.Error, v.NetworkCount)
	}
}

func TestUnknownIXIDIsReportedPerExchange(t *testing.T) {
	fake := newPDB()
	fake.ix = `{"data":[]}`
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), "")
	s.fetch(t.Context())
	v := s.View()
	if v.Error != "" || v.Exchanges[0].Error != "ix id not in peeringdb" || v.MembershipCount != 0 {
		t.Fatalf("view %+v", v)
	}
}

func TestIXFMergesAndKeepsKeyOut(t *testing.T) {
	var ixfAuth atomic.Value
	ixfAuth.Store("unset")
	ixf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ixfAuth.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{"version":"1.0","member_list":[
{"asnum":64497,"name":"Net B (ixf)","connection_list":[{"state":"active","vlan_list":[{"ipv4":{"address":"192.0.2.11","routeserver":true},"ipv6":{"address":"2001:db8::11"}}]}]},
{"asnum":64500,"name":"Net C","connection_list":[{"state":"active","vlan_list":[{"ipv4":{"address":"192.0.2.20","routeserver":false}}]}]},
{"asnum":64501,"name":"Down","connection_list":[{"state":"inactive","vlan_list":[{"ipv4":{"address":"192.0.2.21"}}]}]}]}`)
	}))
	defer ixf.Close()
	fake := newPDB()
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	yml := "base_url: " + srv.URL + "\nexchanges:\n  - {name: example-ix, ix_id: 1, ixf_url: " + ixf.URL + "/members.json}\n"
	s := newSource(t, yml, docKey)
	s.http.Transport = srv.Client().Transport
	s.fetch(t.Context())
	v := s.View()
	if v.Error != "" || v.Exchanges[0].IXFError != "" {
		t.Fatalf("errors %q %q", v.Error, v.Exchanges[0].IXFError)
	}
	if got := ixfAuth.Load().(string); got != "" {
		t.Fatalf("IX-F request carried Authorization %q", got)
	}
	var b, c *plugin.LookupMembership
	for i := range v.Memberships {
		switch v.Memberships[i].ASN {
		case 64497:
			b = &v.Memberships[i]
		case 64500:
			c = &v.Memberships[i]
		case 64501:
			t.Fatalf("inactive connection kept: %+v", v.Memberships[i])
		}
	}
	if b == nil || !b.RouteServer || b.IPv6 != "2001:db8::11" || b.Name != "Net B" {
		t.Fatalf("merged B %+v", b)
	}
	if c == nil || c.IPv4 != "192.0.2.20" || c.RouteServer || c.Exchange != "example-ix" {
		t.Fatalf("IX-F-only C %+v", c)
	}
	if v.NetworkCount != 3 {
		t.Fatalf("networks %d", v.NetworkCount)
	}
}

func TestIXFFailureKeepsDirectoryRows(t *testing.T) {
	ixf := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"version":"2.0","member_list":[]}`)
	}))
	defer ixf.Close()
	srv := httptest.NewServer(newPDB())
	defer srv.Close()
	s := newSource(t, "base_url: "+srv.URL+"\nexchanges:\n  - {name: example-ix, ix_id: 1, ixf_url: "+ixf.URL+"/x.json}\n", "")
	s.fetch(t.Context())
	v := s.View()
	if v.Error != "" || v.MembershipCount != 2 || !strings.Contains(v.Exchanges[0].IXFError, "version") {
		t.Fatalf("view %+v", v)
	}
}

func TestRedirectIsRefusedAndKeyStaysHome(t *testing.T) {
	var other atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.Add(1)
	}))
	defer elsewhere.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), docKey)
	s.http.Transport = srv.Client().Transport
	s.fetch(t.Context())
	v := s.View()
	if other.Load() != 0 {
		t.Fatal("a redirect was followed")
	}
	if !strings.Contains(v.Error, "redirects are not followed") || strings.Contains(v.Error, docKey) || v.NetworkCount != 0 {
		t.Fatalf("view %+v", v)
	}
}

func TestFailedRefreshKeepsLastGoodThenGoesStale(t *testing.T) {
	fake := newPDB()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), "")
	s.fetch(t.Context())
	fake.mu.Lock()
	fake.status = http.StatusInternalServerError
	fake.mu.Unlock()
	s.fetch(t.Context())
	v := s.View()
	if v.Error != "lookup: HTTP 500" || v.Stale || v.NetworkCount != 2 || len(v.Networks) != 2 {
		t.Fatalf("after one failure %+v", v)
	}

	s.mu.Lock()
	s.view.Fetched = time.Now().Add(-(staleFactor*s.refresh + time.Minute))
	s.mu.Unlock()
	v = s.View()
	if !v.Stale || v.Error != "lookup is stale" || v.NetworkCount != 0 || v.MembershipCount != 0 || len(v.Networks) != 0 || len(v.Memberships) != 0 {
		t.Fatalf("stale view %+v", v)
	}
	if ex := v.Exchanges[0]; ex.Name != "example-ix" || ex.IXName != "" || ex.City != "" {
		t.Fatalf("stale exchange %+v", ex)
	}
	if s.view.Exchanges[0].IXName == "" {
		t.Fatal("View mutated the stored exchanges")
	}

	fake.mu.Lock()
	fake.status = 0
	fake.mu.Unlock()
	s.fetch(t.Context())
	if v = s.View(); v.Stale || v.Error != "" || v.NetworkCount != 2 {
		t.Fatalf("after recovery %+v", v)
	}
}

func TestOversizeAndMalformedResponsesAreRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*pdb)
		want   string
	}{
		"oversize": {func(p *pdb) { p.ix = `{"data":[` + strings.Repeat(" ", minMaxBytes+10) + `]}` }, "larger than"},
		"bad json": {func(p *pdb) { p.lan = `{"data":` }, "invalid JSON"},
		"wrong type": {func(p *pdb) {
			p.net = `{"data":[{"id":10,"asn":64496,"name":42,"status":"ok"}]}`
		}, "invalid JSON"},
		"long field": {func(p *pdb) {
			p.net = `{"data":[{"id":10,"asn":64496,"name":"` + strings.Repeat("x", maxNameLen+1) + `","status":"ok"}]}`
		}, "longer than the cap"},
	} {
		t.Run(name, func(t *testing.T) {
			fake := newPDB()
			tc.mutate(fake)
			srv := httptest.NewServer(fake)
			defer srv.Close()
			s := newSource(t, exchangesYAML(srv.URL)+"max_bytes: 1024\n", "")
			s.fetch(t.Context())
			v := s.View()
			if !strings.Contains(v.Error, tc.want) || v.NetworkCount != 0 || !v.Fetched.IsZero() {
				t.Fatalf("view %+v", v)
			}
		})
	}
}

func TestRowCapFailsRefresh(t *testing.T) {
	var lan strings.Builder
	lan.WriteString(`{"data":[`)
	for i := 0; i <= maxMemberships; i++ {
		if i > 0 {
			lan.WriteString(",")
		}
		lan.WriteString(`{"net_id":1,"ix_id":1,"asn":64496,"ipaddr4":"192.0.2.1","status":"ok"}`)
	}
	lan.WriteString(`]}`)
	rows, err := decodeLAN([]byte(lan.String()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = assemble([]exch{{name: "example-ix", ixID: 1}}, []rawIX{{id: 1, name: "Example IX"}}, nil, nil, rows, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "row cap") {
		t.Fatalf("err %v", err)
	}
}

func TestPublishedErrorRedactsKey(t *testing.T) {
	s := newSource(t, "exchanges:\n  - {name: example-ix, ix_id: 1}\n", docKey)
	s.publishErr(fmt.Errorf("lookup: dial failed for %s", docKey))
	if v := s.View(); strings.Contains(v.Error, docKey) || !strings.Contains(v.Error, "redacted") {
		t.Fatalf("error %q", v.Error)
	}
	if strings.Contains(fmt.Sprintf("%+v", s.View()), docKey) {
		t.Fatal("view contains the key")
	}
}

func TestStartRefreshesAndStopEnds(t *testing.T) {
	fake := newPDB()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	s := newSource(t, exchangesYAML(srv.URL), "")
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for s.View().Fetched.IsZero() {
		if time.Now().After(deadline) {
			t.Fatal("no first fetch")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := s.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, _ := fake.snapshot()
	if len(before) != 4 {
		t.Fatalf("requests %v", before)
	}
	select {
	case <-s.done:
	default:
		t.Fatal("loop still running after Stop")
	}
}

func TestNewValidation(t *testing.T) {
	ex := "exchanges:\n  - {name: example-ix, ix_id: 1}\n"
	for name, tc := range map[string]struct {
		yml, key, want string
	}{
		"no exchanges":      {"refresh: 24h\n", "", "exchanges is required"},
		"bad name":          {"exchanges:\n  - {name: -x, ix_id: 1}\n", "", "invalid"},
		"zero ix id":        {"exchanges:\n  - {name: a, ix_id: 0}\n", "", "ix_id must be positive"},
		"dup name":          {"exchanges:\n  - {name: a, ix_id: 1}\n  - {name: a, ix_id: 2}\n", "", "duplicate exchange name"},
		"dup id":            {"exchanges:\n  - {name: a, ix_id: 1}\n  - {name: b, ix_id: 1}\n", "", "duplicate ix_id"},
		"refresh low":       {ex + "refresh: 1m\n", "", "refresh"},
		"refresh high":      {ex + "refresh: 48h\n", "", "refresh"},
		"timeout low":       {ex + "timeout: 1ms\n", "", "timeout"},
		"max bytes low":     {ex + "max_bytes: 10\n", "", "max_bytes"},
		"max bytes high":    {ex + "max_bytes: 999999999\n", "", "max_bytes"},
		"unknown key":       {ex + "write: true\n", "", "write"},
		"key space":         {ex, "ab\u00e9cd", "invalid character"},
		"key non-ascii":     {ex, "ab\u00e9cd", "invalid character"},
		"key too long":      {ex, strings.Repeat("k", maxKeyLen+1), "too long"},
		"key over http":     {"base_url: http://pdb.example.invalid\n" + ex, docKey, "https"},
		"base userinfo":     {"base_url: https://user:pw@pdb.example.invalid\n" + ex, "", "userinfo"},
		"base query":        {"base_url: https://pdb.example.invalid/?a=b\n" + ex, "", "query"},
		"base scheme":       {"base_url: ftp://pdb.example.invalid\n" + ex, "", "http or https"},
		"base holds key":    {"base_url: https://pdb.example.invalid/" + docKey + "\n" + ex, docKey, "API key"},
		"ixf holds key":     {"exchanges:\n  - {name: a, ix_id: 1, ixf_url: \"https://ixf.example.invalid/" + docKey + "\"}\n", docKey, "API key"},
		"ixf bad scheme":    {"exchanges:\n  - {name: a, ix_id: 1, ixf_url: \"file:///etc/passwd\"}\n", "", "http or https"},
		"ixf has query":     {"exchanges:\n  - {name: a, ix_id: 1, ixf_url: \"https://ixf.example.invalid/x?k=1\"}\n", "", "query"},
		"too many exchange": {tooManyExchanges(), "", "exceeds"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := plugin.ConfigFromYAML(tc.yml)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(cfg, plugin.Env{Getenv: func(string) string { return tc.key }})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if tc.key != "" && strings.Contains(err.Error(), tc.key) {
				t.Fatalf("error contains the key: %v", err)
			}
		})
	}
}

func tooManyExchanges() string {
	var b strings.Builder
	b.WriteString("exchanges:\n")
	for i := 1; i <= maxExchanges+1; i++ {
		fmt.Fprintf(&b, "  - {name: ix%d, ix_id: %d}\n", i, i)
	}
	return b.String()
}

func TestNewDefaultsAndDoesNotDial(t *testing.T) {
	s := newSource(t, "exchanges:\n  - {name: example-ix, ix_id: 1}\n", "")
	if s.refresh != 24*time.Hour || s.base.String() != DefaultBaseURL || s.maxBytes != DefaultMaxBytes || s.gap != anonymousGap {
		t.Fatalf("defaults refresh %s base %s max %d gap %s", s.refresh, s.base, s.maxBytes, s.gap)
	}
	v := s.View()
	if !v.Configured || !v.Anonymous || !v.Fetched.IsZero() || len(v.Exchanges) != 1 || v.Networks == nil || v.Memberships == nil {
		t.Fatalf("initial view %+v", v)
	}
}
