package mikrotik

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeRouterOS is the part of the RouterOS 7 REST API the steerer uses:
// each family has its own route list, and a request must carry the login.
type fakeRouterOS struct {
	mu     sync.Mutex
	rows   map[string][]map[string]string // "/ip/route" -> routes
	next   int
	calls  []string
	failOn string
}

func newFakeRouterOS() *fakeRouterOS {
	return &fakeRouterOS{rows: map[string][]map[string]string{"/ip/route": nil, "/ipv6/route": nil}}
}

func (f *fakeRouterOS) add(kind, dst, gw, comment string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next++
	id := fmt.Sprintf("*%d", f.next)
	f.rows[kind] = append(f.rows[kind], map[string]string{".id": id, "dst-address": dst, "gateway": gw, "comment": comment})
	return id
}

func (f *fakeRouterOS) find(kind, dst string) []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]string
	for _, r := range f.rows[kind] {
		if r["dst-address"] == dst {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeRouterOS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != "pk" || p != "lab-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	if f.failOn != "" && strings.HasPrefix(r.Method+" "+r.URL.Path, f.failOn) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":400,"message":"Bad Request","detail":"failure to create route"}`))
		return
	}
	trim := strings.TrimPrefix(r.URL.Path, "/rest")
	kind, id := trim, ""
	if i := strings.LastIndex(trim, "/*"); i >= 0 {
		kind, id = trim[:i], trim[i+1:]
	}
	rows, ok := f.rows[kind]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	switch r.Method {
	case http.MethodGet:
		// The router filters on the query. Ignore it on purpose half of
		// the time would hide a bug, so the fake honors it fully.
		var out []map[string]string
		for _, row := range rows {
			match := true
			for k, v := range r.URL.Query() {
				if row[k] != v[0] {
					match = false
				}
			}
			if match {
				out = append(out, row)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	case http.MethodPut:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.next++
		body[".id"] = fmt.Sprintf("*%d", f.next)
		f.rows[kind] = append(rows, body)
		_ = json.NewEncoder(w).Encode(body)
	case http.MethodPatch:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, row := range rows {
			if row[".id"] == "*"+strings.TrimPrefix(id, "*") || row[".id"] == id {
				for k, v := range body {
					row[k] = v
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{})
	case http.MethodDelete:
		var keep []map[string]string
		for _, row := range rows {
			if row[".id"] != id {
				keep = append(keep, row)
			}
		}
		f.rows[kind] = keep
		w.WriteHeader(http.StatusNoContent)
	}
}

func newSteerer(t *testing.T, h http.Handler) plugin.Steerer {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return mustNew(t, "url: "+srv.URL+"\nusername_env: PK_USER\npassword_env: PK_PASS\n")
}

func mustNew(t *testing.T, y string) plugin.Steerer {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(y), &n); err != nil {
		t.Fatal(err)
	}
	env := plugin.Env{Getenv: func(k string) string { return map[string]string{"PK_USER": "pk", "PK_PASS": "lab-secret"}[k] }}
	s, err := New(plugin.NewConfig(n.Content[0]), env)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestInstallSwitchRemove(t *testing.T) {
	rt := newFakeRouterOS()
	s := newSteerer(t, rt)
	ctx := context.Background()
	r := plugin.SteerRoute{Prefix: pfx("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	if err := s.Install(ctx, r); err != nil {
		t.Fatal(err)
	}
	rows := rt.find("/ip/route", "198.51.100.0/24")
	if len(rows) != 1 || rows[0]["gateway"] != "192.0.2.1" || rows[0]["comment"] != Tag {
		t.Fatalf("route = %v", rows)
	}
	// Installing the same route again changes nothing.
	n := len(rt.calls)
	if err := s.Install(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, c := range rt.calls[n:] {
		if !strings.HasPrefix(c, "GET ") {
			t.Fatalf("a repeat install wrote: %s", c)
		}
	}
	// A new gateway updates the one route in place.
	r.NextHop = netip.MustParseAddr("198.51.100.1")
	if err := s.Install(ctx, r); err != nil {
		t.Fatal(err)
	}
	rows = rt.find("/ip/route", "198.51.100.0/24")
	if len(rows) != 1 || rows[0]["gateway"] != "198.51.100.1" {
		t.Fatalf("after switch: %v", rows)
	}
	if err := s.Remove(ctx, r.Prefix); err != nil {
		t.Fatal(err)
	}
	if rows = rt.find("/ip/route", "198.51.100.0/24"); len(rows) != 0 {
		t.Fatalf("route stayed: %v", rows)
	}
	if err := s.Remove(ctx, r.Prefix); err != nil {
		t.Fatalf("removing a route that is gone: %v", err)
	}
}

func TestIPv6UsesItsOwnRouteTable(t *testing.T) {
	rt := newFakeRouterOS()
	s := newSteerer(t, rt)
	err := s.Install(context.Background(), plugin.SteerRoute{Prefix: pfx("2001:db8:1::/48"), NextHop: netip.MustParseAddr("2001:db8:ffff::1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.find("/ipv6/route", "2001:db8:1::/48")) != 1 || len(rt.rows["/ip/route"]) != 0 {
		t.Fatalf("rows = %v", rt.rows)
	}
}

func TestInstallLeavesOneTaggedRowOnTheNewGateway(t *testing.T) {
	rt := newFakeRouterOS()
	rt.add("/ip/route", "203.0.113.0/24", "192.0.2.1", Tag)
	rt.add("/ip/route", "203.0.113.0/24", "192.0.2.1", Tag)
	s := newSteerer(t, rt)
	if err := s.Install(context.Background(), plugin.SteerRoute{Prefix: pfx("203.0.113.0/24"), NextHop: netip.MustParseAddr("198.51.100.1")}); err != nil {
		t.Fatal(err)
	}
	rows := rt.find("/ip/route", "203.0.113.0/24")
	if len(rows) != 1 || rows[0]["gateway"] != "198.51.100.1" {
		t.Fatalf("rows = %v, want one row on the new gateway", rows)
	}
}

func TestInstallRefusesAHandWrittenRoute(t *testing.T) {
	rt := newFakeRouterOS()
	rt.add("/ip/route", "203.0.113.0/24", "192.0.2.1", "operator route")
	s := newSteerer(t, rt)
	err := s.Install(context.Background(), plugin.SteerRoute{Prefix: pfx("203.0.113.0/24"), NextHop: netip.MustParseAddr("198.51.100.1")})
	if err == nil || !strings.Contains(err.Error(), "did not add") {
		t.Fatalf("err = %v", err)
	}
	rows := rt.find("/ip/route", "203.0.113.0/24")
	if len(rows) != 1 || rows[0]["gateway"] != "192.0.2.1" {
		t.Fatalf("the operator's route was changed: %v", rows)
	}
	// Remove never deletes a route without the tag either.
	if err := s.Remove(context.Background(), pfx("203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	if len(rt.find("/ip/route", "203.0.113.0/24")) != 1 {
		t.Fatal("Remove deleted a route it does not own")
	}
}

func TestOwnedListsOnlyTaggedRoutesOfBothFamilies(t *testing.T) {
	rt := newFakeRouterOS()
	rt.add("/ip/route", "198.51.100.0/24", "192.0.2.1", Tag)
	rt.add("/ip/route", "0.0.0.0/0", "192.0.2.1", "")
	rt.add("/ip/route", "203.0.113.0/24", "192.0.2.1", "someone else")
	rt.add("/ipv6/route", "2001:db8:1::/48", "2001:db8:ffff::1", Tag)
	got, err := newSteerer(t, rt).Owned(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != pfx("198.51.100.0/24") || got[1] != pfx("2001:db8:1::/48") {
		t.Fatalf("owned = %v", got)
	}
}

func TestRouterErrorsAreReportedWithoutTheLogin(t *testing.T) {
	rt := newFakeRouterOS()
	rt.failOn = "PUT"
	err := newSteerer(t, rt).Install(context.Background(), plugin.SteerRoute{Prefix: pfx("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")})
	if err == nil || !strings.Contains(err.Error(), "400 Bad Request: Bad Request (failure to create route)") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "lab-secret") {
		t.Fatal("the password is in the error")
	}
	// A wrong login is a plain status error.
	srv := httptest.NewServer(rt)
	defer srv.Close()
	s, err2 := New(func() plugin.Config {
		var n yaml.Node
		_ = yaml.Unmarshal([]byte("url: "+srv.URL+"\nusername_env: PK_USER\npassword_env: PK_PASS\n"), &n)
		return plugin.NewConfig(n.Content[0])
	}(), plugin.Env{Getenv: func(string) string { return "wrong" }})
	if err2 != nil {
		t.Fatal(err2)
	}
	if _, err := s.Owned(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a wrong login: %v", err)
	}
}

func TestConfigChecks(t *testing.T) {
	env := plugin.Env{Getenv: func(string) string { return "x" }}
	for name, y := range map[string]string{
		"plain http to a router": "url: http://192.0.2.1\nusername_env: A\npassword_env: B\n",
		"no scheme":              "url: 192.0.2.1\nusername_env: A\npassword_env: B\n",
		"credentials in url":     "url: https://u:p@192.0.2.1\nusername_env: A\npassword_env: B\n",
		"no login":               "url: https://192.0.2.1\n",
		"one half of the login":  "url: https://192.0.2.1\nusername_env: A\n",
		"bad env name":           "url: https://192.0.2.1\nusername_env: \"a b\"\npassword_env: B\n",
		"ca file not absolute":   "url: https://192.0.2.1\nusername_env: A\npassword_env: B\nca_file: ca.pem\n",
		"unknown key":            "url: https://192.0.2.1\nusername_env: A\npassword_env: B\ninsecure: true\n",
	} {
		var n yaml.Node
		if err := yaml.Unmarshal([]byte(y), &n); err != nil {
			t.Fatal(err)
		}
		if _, err := New(plugin.NewConfig(n.Content[0]), env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var n yaml.Node
	_ = yaml.Unmarshal([]byte("url: https://192.0.2.1\nusername_env: A\npassword_env: B\n"), &n)
	if _, err := New(plugin.NewConfig(n.Content[0]), plugin.Env{Getenv: func(string) string { return "" }}); err == nil {
		t.Error("an unset login variable was accepted outside a config check")
	}
	if _, err := New(plugin.NewConfig(n.Content[0]), plugin.Env{Getenv: func(string) string { return "" }, CheckOnly: true}); err != nil {
		t.Errorf("a config check needs no secrets: %v", err)
	}
	if !plugin.Steerers.Has(TypeName) {
		t.Fatal("mikrotik is not registered as a steerer")
	}
}
