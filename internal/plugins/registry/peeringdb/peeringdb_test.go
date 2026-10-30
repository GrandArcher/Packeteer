package peeringdb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const testKey = "test-key-not-a-secret"

type fakePDB struct {
	mu      sync.Mutex
	net     map[string]any
	puts    []map[string]any
	putAuth []string
	status  int
}

func newFake(t *testing.T) (*fakePDB, *Checker) {
	t.Helper()
	f := &fakePDB{net: map[string]any{"id": 42, "asn": 64496, "name": "Example Net", "info_prefixes4": 1, "info_prefixes6": 10}}
	data := func(w http.ResponseWriter, v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/net", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("asn") == "64511" {
			data(w, []any{})
			return
		}
		data(w, []any{f.net})
	})
	mux.HandleFunc("/api/net/42", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodPut {
			var body map[string]any
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body)
			f.puts = append(f.puts, body)
			f.putAuth = append(f.putAuth, r.Header.Get("Authorization"))
			if f.status != 0 {
				w.WriteHeader(f.status)
				return
			}
			data(w, []any{body})
			return
		}
		data(w, []any{f.net})
	})
	mux.HandleFunc("/api/netixlan", func(w http.ResponseWriter, r *http.Request) {
		data(w, []any{
			map[string]any{"id": 7, "ix_id": 77, "ipaddr4": "198.51.100.10", "ipaddr6": "2001:db8::10", "speed": 1000},
			map[string]any{"id": 8, "ix_id": 77, "ipaddr4": "198.51.100.99", "ipaddr6": nil, "speed": 10000},
			map[string]any{"id": 9, "ix_id": 88, "ipaddr4": "192.0.2.5", "speed": 100},
		})
	})
	mux.HandleFunc("/api/netfac", func(w http.ResponseWriter, r *http.Request) { data(w, []any{}) })
	mux.HandleFunc("/api/poc", func(w http.ResponseWriter, r *http.Request) {
		data(w, []any{
			map[string]any{"id": 5, "role": "NOC", "updated": "2020-01-01T00:00:00Z"},
			map[string]any{"id": 6, "role": "Abuse", "updated": "2026-09-01T00:00:00Z"},
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return f, newChecker(t, srv, testKey)
}

func newChecker(t *testing.T, srv *httptest.Server, key string) *Checker {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte("{base_url: \""+srv.URL+"\"}"), &node); err != nil {
		t.Fatal(err)
	}
	p, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{Name: "peeringdb", Getenv: func(k string) string {
		if k == "PACKETEER_PEERINGDB_API_KEY" {
			return key
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Checker)
	c.http = srv.Client()
	c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	c.limit = rate.NewLimiter(rate.Inf, 1)
	c.now = func() time.Time { return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC) }
	return c
}

func facts() plugin.RegistryFacts {
	return plugin.RegistryFacts{
		ASNs:       []uint32{64496},
		Announced4: map[uint32]int{64496: 3},
		Announced6: map[uint32]int{64496: 1},
		Headroom:   20,
		Sessions: []plugin.RegistrySession{{
			Exchange: "ix-example", IXID: 77, SpeedMbps: 10000,
			Addrs: []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.11")},
		}},
	}
}

func kinds(fs []plugin.RegistryFinding) map[string]plugin.RegistryFinding {
	out := map[string]plugin.RegistryFinding{}
	for _, f := range fs {
		out[f.Kind+"|"+f.Subject] = f
	}
	return out
}

// #289: Check flags a max-prefix value below the announced count with the
// field diff and a change that raises it by the headroom, a configured
// session with no connection record, a speed that disagrees, a listed
// connection no session uses, a network with no facility, and a contact
// not updated for two years. An exchange with no configured ix id is left
// alone.
func TestCheck(t *testing.T) {
	_, c := newFake(t)
	fs, err := c.Check(context.Background(), facts())
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(fs)
	if len(fs) != 6 {
		t.Fatalf("findings = %+v", fs)
	}

	mp := got["pdb_maxprefix|AS64496 info_prefixes4"]
	if mp.Severity != plugin.RegistryWarning || mp.Diff != "net 42\n- info_prefixes4: 1\n+ info_prefixes4: 4" {
		t.Fatalf("maxprefix = %+v", mp)
	}
	want := plugin.RegistryChange{Registry: "peeringdb", Op: "update_field", Class: "net", Key: "42", Field: "info_prefixes4", Old: "1", New: "4"}
	if mp.Change == nil || *mp.Change != want {
		t.Fatalf("maxprefix change = %+v", mp.Change)
	}
	if m := got["pdb_ix_missing|AS64496 ix-example 198.51.100.11"]; m.Severity != plugin.RegistryWarning || m.Change != nil ||
		m.Diff != "+ netixlan ix_id 77, asn 64496, address 198.51.100.11, speed 10000" {
		t.Fatalf("ix missing = %+v", m)
	}
	sp := got["pdb_ix_speed|AS64496 ix-example 198.51.100.10 speed"]
	if sp.Diff != "netixlan 7\n- speed: 1000\n+ speed: 10000" || sp.Change == nil || sp.Change.Class != "netixlan" || sp.Change.New != "10000" {
		t.Fatalf("ix speed = %+v", sp)
	}
	if st := got["pdb_ix_stale|AS64496 ix 77 198.51.100.99"]; st.Severity != plugin.RegistryInfo {
		t.Fatalf("ix stale = %+v", st)
	}
	if got["pdb_facility_missing|AS64496 facilities"].Severity != plugin.RegistryWarning {
		t.Fatalf("facility finding missing: %+v", fs)
	}
	old := got["pdb_contact_old|AS64496 contact 5"]
	if old.Severity != plugin.RegistryInfo || !strings.Contains(old.Message, "NOC contact of AS64496 was last updated 2020-01-01") {
		t.Fatalf("contact = %+v", old)
	}
}

// #289: an exchange without local_lan_addrs is not compared, and the scan
// says so instead of calling every record stale; an unknown port speed is
// left out of the diff.
func TestIXNeedsLocalAddrs(t *testing.T) {
	_, c := newFake(t)
	f := facts()
	f.Sessions = []plugin.RegistrySession{
		{Exchange: "ix-example", IXID: 77, SpeedMbps: 10000},
		{Exchange: "ix-other", IXID: 88, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.6")}},
	}
	fs, err := c.Check(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	got := kinds(fs)
	un := got["pdb_ix_unchecked|AS64496 ix-example"]
	if un.Severity != plugin.RegistryInfo || un.Message != "exchanges ix-example sets no local_lan_addrs, so the PeeringDB connection records at ix 77 are not compared" {
		t.Fatalf("unchecked = %+v", fs)
	}
	if m := got["pdb_ix_missing|AS64496 ix-other 192.0.2.6"]; m.Diff != "+ netixlan ix_id 88, asn 64496, address 192.0.2.6" {
		t.Fatalf("missing without a speed = %+v", m)
	}
	if _, ok := got["pdb_ix_stale|AS64496 ix 88 192.0.2.5"]; !ok {
		t.Fatalf("ix 88 record not compared: %+v", fs)
	}
	for _, x := range fs {
		if strings.Contains(x.Subject, "ix 77") || x.Kind == "pdb_ix_speed" {
			t.Errorf("ix 77 compared without addresses: %+v", x)
		}
	}
}

// #289: the IPv4 and IPv6 address of one connection record make one speed
// finding, not two pushes of the same record.
func TestIXSpeedOncePerRecord(t *testing.T) {
	_, c := newFake(t)
	f := facts()
	f.Sessions[0].Addrs = []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("2001:db8::10")}
	fs, err := c.Check(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var speeds []string
	for _, x := range fs {
		if x.Kind == "pdb_ix_speed" {
			speeds = append(speeds, x.Subject)
		}
	}
	if len(speeds) != 1 || speeds[0] != "AS64496 ix-example 198.51.100.10 speed" {
		t.Fatalf("speed findings = %v", speeds)
	}
}

// #289: a count at or above the announced count but below the headroom is
// info; at or above the headroom there is no finding; no record is a
// finding of its own.
func TestMaxPrefixHeadroomAndMissingNet(t *testing.T) {
	f, c := newFake(t)
	f.net["info_prefixes4"] = 3
	f.net["info_prefixes6"] = 2
	fs, err := c.Check(context.Background(), facts())
	if err != nil {
		t.Fatal(err)
	}
	mp := kinds(fs)["pdb_maxprefix|AS64496 info_prefixes4"]
	if mp.Severity != plugin.RegistryInfo || mp.Change.New != "4" {
		t.Fatalf("low headroom = %+v", mp)
	}
	if _, ok := kinds(fs)["pdb_maxprefix|AS64496 info_prefixes6"]; ok {
		t.Fatal("6 announced with 2 listed and 20% headroom is enough")
	}

	ff := facts()
	ff.ASNs = []uint32{64511}
	fs, err = c.Check(context.Background(), ff)
	if err != nil || len(fs) != 1 || fs[0].Kind != "pdb_net_missing" || fs[0].Subject != "AS64511" {
		t.Fatalf("no record = %+v %v", fs, err)
	}
}

// #289: Push re-reads the record, PUTs it with only the confirmed field
// changed and the key in the Authorization header.
func TestPush(t *testing.T) {
	f, c := newFake(t)
	ch := plugin.RegistryChange{Registry: "peeringdb", Op: "update_field", Class: "net", Key: "42", Field: "info_prefixes4", Old: "1", New: "4"}
	if err := c.Push(context.Background(), ch); err != nil {
		t.Fatal(err)
	}
	if len(f.puts) != 1 || f.putAuth[0] != "Api-Key "+testKey {
		t.Fatalf("puts = %v auth = %v", f.puts, f.putAuth)
	}
	put := f.puts[0]
	if put["info_prefixes4"] != float64(4) || put["info_prefixes6"] != float64(10) || put["name"] != "Example Net" || put["id"] != float64(42) {
		t.Fatalf("put body = %v", put)
	}
}

// #289: a push is refused without a key, for a field outside the list,
// when the record changed since the scan, and for a bad id or value; none
// sends a PUT. A failing PUT is an error.
func TestPushRefusals(t *testing.T) {
	f, c := newFake(t)
	ctx := context.Background()
	base := plugin.RegistryChange{Registry: "peeringdb", Op: "update_field", Class: "net", Key: "42", Field: "info_prefixes4", Old: "1", New: "4"}

	for name, mut := range map[string]func(*plugin.RegistryChange){
		"name field": func(c *plugin.RegistryChange) { c.Field = "name"; c.Old = "Example Net"; c.New = "1" },
		"wrong op":   func(c *plugin.RegistryChange) { c.Op = "delete_object" },
		"wrong type": func(c *plugin.RegistryChange) { c.Registry = "ripe" },
		"bad class":  func(c *plugin.RegistryChange) { c.Class = "org" },
	} {
		ch := base
		mut(&ch)
		if err := c.Push(ctx, ch); err != plugin.ErrRegistryNoPush {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	for name, mut := range map[string]func(*plugin.RegistryChange){
		"changed since": func(c *plugin.RegistryChange) { c.Old = "2" },
		"bad id":        func(c *plugin.RegistryChange) { c.Key = "x" },
		"bad value":     func(c *plugin.RegistryChange) { c.New = "-1" },
	} {
		ch := base
		mut(&ch)
		if err := c.Push(ctx, ch); err == nil {
			t.Errorf("%s: pushed", name)
		}
	}
	if len(f.puts) != 0 {
		t.Fatalf("PUT sent for a refused change: %v", f.puts)
	}

	f.status = http.StatusForbidden
	if err := c.Push(ctx, base); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("403 = %v", err)
	}

	c.apiKey = ""
	if err := c.Push(ctx, base); err == nil || !strings.Contains(err.Error(), "PACKETEER_PEERINGDB_API_KEY") {
		t.Fatalf("no key = %v", err)
	}
}

// #289: a redirect is not followed, so the key cannot reach another host.
func TestNoRedirect(t *testing.T) {
	var other int
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other++ }))
	defer target.Close()
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer src.Close()
	c := newChecker(t, src, testKey)
	if _, err := c.Check(context.Background(), facts()); err == nil || !strings.Contains(err.Error(), "HTTP 302") || other != 0 {
		t.Fatalf("err = %v, redirect target hit %d times", err, other)
	}
}

// #289: the config is validated at load time and the key never appears in
// an error.
func TestConfig(t *testing.T) {
	for cfg, bad := range map[string]bool{
		"{}":                                   false,
		"{timeout: 1ms}":                       true,
		"{base_url: 'ftp://x'}":                true,
		"{base_url: 'http://pdb.example.net'}": false,
		"{unknown: 1}":                         true,
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
			t.Fatal(err)
		}
		_, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{})
		if (err != nil) != bad {
			t.Errorf("%s: err = %v", cfg, err)
		}
	}
	var node yaml.Node
	_ = yaml.Unmarshal([]byte("{base_url: 'http://pdb.example.net'}"), &node)
	_, err := New(plugin.NewConfig(node.Content[0]), plugin.Env{Getenv: func(string) string { return testKey }})
	if err == nil || strings.Contains(err.Error(), testKey) {
		t.Fatalf("a key with an http base_url: %v", err)
	}
}
