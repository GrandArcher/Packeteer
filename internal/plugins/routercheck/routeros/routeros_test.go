package routeros

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/readonly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	labUser = "pk-reader"
	labPass = "lab-only-password"
)

// fakeRouter serves the REST paths the reader reads and records every
// request it gets.
type fakeRouter struct {
	mu    sync.Mutex
	items map[string][]row
	seen  []string
}

func (f *fakeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seen = append(f.seen, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != labUser || p != labPass {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/rest/redirect-me" {
		http.Redirect(w, r, "/rest/execute", http.StatusFound)
		return
	}
	items, ok := f.items[strings.TrimPrefix(r.URL.Path, "/rest")]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	_ = json.NewEncoder(w).Encode(items)
}

func (f *fakeRouter) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

func cfg(t *testing.T, y string) plugin.Config {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func labEnv(k string) string {
	return map[string]string{"PACKETEER_ROUTER_READ_USER": labUser, "PACKETEER_ROUTER_READ_PASSWORD": labPass}[k]
}

func newReader(t *testing.T, f *fakeRouter) *Reader {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	rc, err := New(cfg(t, "{url: "+srv.URL+", username_env: PACKETEER_ROUTER_READ_USER, password_env: PACKETEER_ROUTER_READ_PASSWORD}"), plugin.Env{Getenv: labEnv})
	if err != nil {
		t.Fatal(err)
	}
	return rc.(*Reader)
}

// labRouter is lab/chr/edge.rsc as RouterOS 7.23 lists it.
func labRouter() *fakeRouter {
	return &fakeRouter{items: map[string][]row{
		"/routing/bgp/connection": {
			{".id": "*1", "name": "packeteer", "remote.address": "192.0.2.10", "local.role": "ibgp", "input.filter": "packeteer-in"},
			{".id": "*2", "name": "transit-a", "remote.address": "192.0.2.1", "local.role": "ebgp", "output.filter-chain": "ebgp-out"},
			{".id": "*3", "name": "collector", "remote.address": "192.0.2.20/32", "local.role": "ebgp", "output.filter-chain": "ebgp-out"},
			{".id": "*4", "name": "untagged", "remote.address": "192.0.2.30", "local.role": "ibgp", "input.filter": "packeteer-in"},
		},
		"/routing/bgp/template": {{".id": "*0", "name": "default"}},
		"/routing/filter/rule": {
			{".id": "*5", "chain": "packeteer-in", "rule": "if (bgp-communities includes 64512:666) { accept }", "disabled": "false"},
			{".id": "*6", "chain": "packeteer-in", "rule": "reject", "disabled": "false"},
			{".id": "*7", "chain": "ebgp-out", "rule": "if (bgp-communities includes 64512:666) { reject }", "disabled": "false"},
			{".id": "*8", "chain": "ebgp-out", "rule": "accept", "disabled": "false"},
		},
	}}
}

var labQuery = plugin.FilterQuery{Community: "64512:666", Packeteer: netip.MustParseAddr("192.0.2.10")}

func TestLabRouterPassesWithGETsOnTheAllowlist(t *testing.T) {
	f := labRouter()
	got, err := newReader(t, f).CheckFilters(context.Background(), labQuery)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"Import from Packeteer 192.0.2.10 (connection packeteer): chain packeteer-in accepts only routes with 64512:666.",
		"Export to eBGP connection transit-a: chain ebgp-out rejects 64512:666 at rule 1, before any accept.",
		"Export to eBGP connection collector: chain ebgp-out rejects 64512:666 at rule 1, before any accept.",
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %+v", got)
	}
	for i, w := range want {
		if got[i].Verdict != plugin.VerdictPass || got[i].Detail != w {
			t.Errorf("finding %d = %+v, want pass %q", i, got[i], w)
		}
	}
	// No connection names a template, so templates are not read.
	if reqs := f.requests(); strings.Join(reqs, ",") != "GET /rest/routing/bgp/connection,GET /rest/routing/filter/rule" {
		t.Errorf("requests = %q", reqs)
	}
}

func TestMissingEBGPRejectFailsWithTheFix(t *testing.T) {
	f := labRouter()
	f.items["/routing/bgp/connection"][2]["output.filter-chain"] = "ebgp-open"
	f.items["/routing/filter/rule"] = append(f.items["/routing/filter/rule"], row{"chain": "ebgp-open", "rule": "accept"})
	got, err := newReader(t, f).CheckFilters(context.Background(), labQuery)
	if err != nil {
		t.Fatal(err)
	}
	c := got[2]
	if c.Verdict != plugin.VerdictFail || c.Detail != "Export to eBGP connection collector: chain ebgp-open accepts at rule 1 before 64512:666 is rejected." ||
		c.Fix != `Add the rule at the top of chain ebgp-open: /routing filter rule add chain=ebgp-open place-before=0 rule="if (bgp-communities includes 64512:666) { reject }" (Router snippets).` {
		t.Errorf("collector = %+v", c)
	}
	if got[0].Verdict != plugin.VerdictPass || got[1].Verdict != plugin.VerdictPass {
		t.Errorf("the other connections changed: %+v", got)
	}
}

// TestOnlyAllowlistedPathsAreRead proves the read-only guarantee: a path
// off the allowlist is refused before any request, and a redirect is not
// followed to a path the reader did not choose.
func TestOnlyAllowlistedPathsAreRead(t *testing.T) {
	f := labRouter()
	r := newReader(t, f)
	for _, p := range []string{
		"/execute", "/system/reboot", "/routing/filter/rule/add", "/routing/filter/rule/*5",
		"/routing/bgp/connection/set", "/routing/bgp/connection?disabled=true", "/routing/bgp/connection/",
		"routing/bgp/connection", "/routing/bgp/connection\n", "/user", "/export", "",
	} {
		var out []row
		if err := r.get(context.Background(), p, &out); !errors.Is(err, readonly.ErrRefused) {
			t.Errorf("%q = %v, want ErrRefused", p, err)
		}
	}
	if reqs := f.requests(); len(reqs) != 0 {
		t.Fatalf("refused paths reached the router: %q", reqs)
	}
	// Put the redirecting path on a copy of the allowlist for this test only.
	saved := allow
	t.Cleanup(func() { allow = saved })
	allow = readonly.NewAllowlist(`/redirect-me`)
	var out []row
	if err := r.get(context.Background(), "/redirect-me", &out); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect = %v, want the 302 as an error", err)
	}
	for _, req := range f.requests() {
		if !strings.HasPrefix(req, "GET ") || strings.Contains(req, "/execute") {
			t.Errorf("request %q", req)
		}
	}
}

func TestErrorsKeepTheLoginOut(t *testing.T) {
	f := labRouter()
	srv := httptest.NewServer(f)
	defer srv.Close()
	env := func(k string) string {
		return map[string]string{"PACKETEER_ROUTER_READ_USER": labUser, "PACKETEER_ROUTER_READ_PASSWORD": "wrong-" + labPass}[k]
	}
	rc, err := New(cfg(t, "{url: "+srv.URL+", username_env: PACKETEER_ROUTER_READ_USER, password_env: PACKETEER_ROUTER_READ_PASSWORD}"), plugin.Env{Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rc.CheckFilters(context.Background(), labQuery)
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), labPass) || strings.Contains(err.Error(), labUser) {
		t.Errorf("err = %v", err)
	}
	srv.Close()
	_, err = rc.CheckFilters(context.Background(), labQuery)
	if err == nil || strings.Contains(err.Error(), labPass) || strings.Contains(err.Error(), "Get \"") {
		t.Errorf("closed server err = %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	ok := "username_env: PACKETEER_ROUTER_READ_USER, password_env: PACKETEER_ROUTER_READ_PASSWORD"
	for y, want := range map[string]string{
		"{url: http://192.0.2.254, " + ok + "}":                                 "must be https",
		"{url: 'https://u:p@192.0.2.254', " + ok + "}":                          "without credentials",
		"{url: https://192.0.2.254, username_env: PACKETEER_ROUTER_READ_USER}":  "username_env and password_env are required",
		"{url: https://192.0.2.254, username_env: A, password_env: UNSET_PASS}": "is not set",
		"{url: https://192.0.2.254, ca_file: rel/ca.pem, " + ok + "}":           "absolute path",
		"{url: https://192.0.2.254, " + ok + ", extra: 1}":                      "extra",
	} {
		_, err := New(cfg(t, y), plugin.Env{Getenv: func(k string) string {
			if k == "A" {
				return "a"
			}
			return labEnv(k)
		}})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", y, err, want)
		}
	}
	// The config editor checks a file for a process that may not have the
	// variables yet.
	if _, err := New(cfg(t, "{url: https://192.0.2.254, username_env: X_USER, password_env: X_PASS}"), plugin.Env{CheckOnly: true}); err != nil {
		t.Errorf("check only: %v", err)
	}
}

func TestCAFileTrustsTheRouterCertificate(t *testing.T) {
	f := labRouter()
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "router-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	base := "{url: " + srv.URL + ", username_env: PACKETEER_ROUTER_READ_USER, password_env: PACKETEER_ROUTER_READ_PASSWORD"
	with, err := New(cfg(t, base+", ca_file: "+ca+"}"), plugin.Env{Getenv: labEnv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := with.CheckFilters(context.Background(), labQuery); err != nil {
		t.Errorf("with ca_file: %v", err)
	}
	without, err := New(cfg(t, base+"}"), plugin.Env{Getenv: labEnv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := without.CheckFilters(context.Background(), labQuery); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("without ca_file: %v", err)
	}
}

func rules(rs ...[2]string) []row {
	out := make([]row, len(rs))
	for i, r := range rs {
		out[i] = row{"chain": r[0], "rule": r[1]}
	}
	return out
}

func TestChecks(t *testing.T) {
	pk := row{"name": "packeteer", "remote.address": "192.0.2.10", "local.role": "ibgp", "input.filter": "packeteer-in"}
	in := [][2]string{{"packeteer-in", "if (bgp-communities includes 64512:666) { accept }"}, {"packeteer-in", "reject"}}
	ebgp := func(chain string) row {
		return row{"name": "transit-a", "remote.address": "192.0.2.1", "local.role": "ebgp-provider", "output.filter-chain": chain}
	}
	type tc struct {
		conns, tmpl, rules []row
		q                  plugin.FilterQuery
		verdicts           []plugin.Verdict
		detail             string // in the last finding
	}
	large := plugin.FilterQuery{Community: "65536:1:666", Packeteer: labQuery.Packeteer}
	pass, fail, unk := plugin.VerdictPass, plugin.VerdictFail, plugin.VerdictUnknown
	for name, c := range map[string]tc{
		"no eBGP connection": {conns: []row{pk}, rules: rules(in...), verdicts: []plugin.Verdict{pass, pass}, detail: "RouterOS has no eBGP connection."},
		"no Packeteer connection": {conns: []row{ebgp("ebgp-out")}, rules: rules(append(in, [2]string{"ebgp-out", "reject"})...),
			verdicts: []plugin.Verdict{pass, fail}, detail: "RouterOS has no BGP connection with remote.address 192.0.2.10 (Packeteer)."},
		"Packeteer is eBGP": {conns: []row{{"name": "pk", "remote.address": "192.0.2.10", "local.role": "ebgp", "input.filter": "packeteer-in"}}, rules: rules(in...),
			verdicts: []plugin.Verdict{fail, pass}, detail: "RouterOS has no eBGP connection."},
		"no input filter": {conns: []row{{"name": "packeteer", "remote.address": "192.0.2.10", "local.role": "ibgp"}},
			verdicts: []plugin.Verdict{fail, pass}},
		"input chain has no rules": {conns: []row{pk}, verdicts: []plugin.Verdict{fail, pass}},
		"import accepts everything first": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "set bgp-local-pref 250; accept"}),
			verdicts: []plugin.Verdict{fail, pass}},
		"import accepts on another condition": {conns: []row{pk}, rules: rules(append([][2]string{{"packeteer-in", "if (dst-len < 25) { accept }"}}, in...)...),
			verdicts: []plugin.Verdict{fail, pass}},
		"import never accepts": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "if (bgp-communities includes 64512:666) { reject }"}),
			verdicts: []plugin.Verdict{fail, pass}},
		"import default reject at the end": {conns: []row{pk}, rules: rules(in[0]), verdicts: []plugin.Verdict{pass, pass}},
		"import sets local-pref before accept": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "if ((bgp-communities includes 64512:666)) { set bgp-local-pref 250; accept }"}),
			verdicts: []plugin.Verdict{pass, pass}},
		"import rewrites communities": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "if (bgp-communities includes 64512:666) { set bgp-communities 64496:1; accept }"}),
			verdicts: []plugin.Verdict{unk, pass}},
		"import jumps": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "jump other"}), verdicts: []plugin.Verdict{unk, pass}},
		"import else": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "if (bgp-communities includes 64512:666) { accept } else { reject }"}),
			verdicts: []plugin.Verdict{unk, pass}},
		"import other community condition": {conns: []row{pk}, rules: rules([2]string{"packeteer-in", "if (bgp-communities includes 64512:667) { accept }"}),
			verdicts: []plugin.Verdict{unk, pass}},
		"disabled reject is skipped": {conns: []row{pk}, rules: []row{{"chain": "packeteer-in", "rule": "reject", "disabled": "true"}, {"chain": "packeteer-in", "rule": "accept"}},
			verdicts: []plugin.Verdict{fail, pass}},
		"invalid rule": {conns: []row{pk}, rules: []row{{"chain": "packeteer-in", "rule": in[0][1], "invalid": "true"}},
			verdicts: []plugin.Verdict{unk, pass}},
		"no output chain": {conns: []row{pk, {"name": "transit-a", "remote.address": "192.0.2.1", "local.role": "ebgp"}}, rules: rules(in...),
			verdicts: []plugin.Verdict{pass, fail}, detail: "Export to eBGP connection transit-a: no output.filter-chain, so routes with 64512:666 are sent."},
		"output chain has no rules": {conns: []row{pk, ebgp("ebgp-out")}, rules: rules(in...), verdicts: []plugin.Verdict{pass, fail},
			detail: "Export to eBGP connection transit-a: output.filter-chain names chain ebgp-out, which has no rules."},
		"output chain only disabled rules": {conns: []row{pk, ebgp("ebgp-out")}, rules: append(rules(in...), row{"chain": "ebgp-out", "rule": "accept", "disabled": "true"}),
			verdicts: []plugin.Verdict{pass, pass}, detail: "Export to eBGP connection transit-a: chain ebgp-out accepts nothing."},
		"export reject after another reject": {conns: []row{pk, ebgp("ebgp-out")},
			rules:    rules(append(in, [2]string{"ebgp-out", "if (dst-len > 24) { reject }"}, [2]string{"ebgp-out", "if (bgp-communities includes 64512:666) { reject }"}, [2]string{"ebgp-out", "accept"})...),
			verdicts: []plugin.Verdict{pass, pass}, detail: "Export to eBGP connection transit-a: chain ebgp-out rejects 64512:666 at rule 2, before any accept."},
		"export accepts on a community condition": {conns: []row{pk, ebgp("ebgp-out")}, rules: rules(append(in, [2]string{"ebgp-out", "if (bgp-communities includes 64496:1) { accept }"})...),
			verdicts: []plugin.Verdict{pass, unk}},
		"export rewrites communities first": {conns: []row{pk, ebgp("ebgp-out")}, rules: rules(append(in, [2]string{"ebgp-out", "delete bgp-communities 64512:666"}, [2]string{"ebgp-out", "reject"})...),
			verdicts: []plugin.Verdict{pass, unk}},
		"export rejects everything": {conns: []row{pk, ebgp("ebgp-out")}, rules: rules(append(in, [2]string{"ebgp-out", "reject"})...),
			verdicts: []plugin.Verdict{pass, pass}, detail: "Export to eBGP connection transit-a: chain ebgp-out rejects everything at rule 1."},
		"template sets the output chain": {
			conns:    []row{pk, {"name": "transit-a", "remote.address": "192.0.2.1", "templates": "other,upstream"}},
			tmpl:     []row{{"name": "upstream", "local.role": "ebgp", "output.filter-chain": "ebgp-out"}, {"name": "other"}},
			rules:    rules(append(in, [2]string{"ebgp-out", "if (bgp-communities includes 64512:666) { reject }"})...),
			verdicts: []plugin.Verdict{pass, pass}, detail: "Export to eBGP connection transit-a: chain ebgp-out rejects 64512:666 at rule 1, before any accept."},
		"connection overrides its template": {
			conns:    []row{pk, {"name": "transit-a", "remote.address": "192.0.2.1", "local.role": "ebgp", "output.filter-chain": "open", "templates": "upstream"}},
			tmpl:     []row{{"name": "upstream", "output.filter-chain": "ebgp-out"}},
			rules:    rules(append(in, [2]string{"ebgp-out", "reject"}, [2]string{"open", "accept"})...),
			verdicts: []plugin.Verdict{pass, fail}},
		"no role anywhere": {conns: []row{{"name": "packeteer", "remote.address": "192.0.2.10", "input.filter": "packeteer-in"}}, rules: rules(in...),
			verdicts: []plugin.Verdict{unk, pass}},
		"remote range holds Packeteer": {conns: []row{{"name": "lab", "remote.address": "192.0.2.0/24", "local.role": "ibgp", "input.filter": "packeteer-in"}}, rules: rules(in...),
			verdicts: []plugin.Verdict{pass, pass}},
		"large community": {conns: []row{pk, ebgp("ebgp-out")}, q: large,
			rules:    rules([2]string{"packeteer-in", "if (bgp-large-communities includes 65536:1:666) { accept }"}, [2]string{"ebgp-out", "if (bgp-large-communities includes 65536:1:666) { reject }"}, [2]string{"ebgp-out", "accept"}),
			verdicts: []plugin.Verdict{pass, pass}},
		"large community, standard match": {conns: []row{pk}, q: large, rules: rules(in...), verdicts: []plugin.Verdict{unk, pass}},
	} {
		q := c.q
		if !q.Packeteer.IsValid() {
			q = labQuery
		}
		got := check(c.conns, c.tmpl, c.rules, q)
		if len(got) != len(c.verdicts) {
			t.Errorf("%s: %+v", name, got)
			continue
		}
		for i, v := range c.verdicts {
			if got[i].Verdict != v {
				t.Errorf("%s: finding %d = %+v, want %s", name, i, got[i], v)
			}
			if v == fail && got[i].Fix == "" {
				t.Errorf("%s: fail without a fix: %+v", name, got[i])
			}
		}
		if c.detail != "" && got[len(got)-1].Detail != c.detail {
			t.Errorf("%s: detail = %q, want %q", name, got[len(got)-1].Detail, c.detail)
		}
	}
}

func TestTemplatesAreReadWhenAConnectionNamesOne(t *testing.T) {
	f := labRouter()
	f.items["/routing/bgp/connection"][1]["templates"] = "default"
	if _, err := newReader(t, f).CheckFilters(context.Background(), labQuery); err != nil {
		t.Fatal(err)
	}
	want := "GET /rest/routing/bgp/connection,GET /rest/routing/bgp/template,GET /rest/routing/filter/rule"
	if got := strings.Join(f.requests(), ","); got != want {
		t.Errorf("requests = %q, want %q", got, want)
	}
}

func TestParseRule(t *testing.T) {
	for text, want := range map[string]string{
		"if (bgp-communities includes 64512:666) { accept }":        "if[bgp-communities includes 64512:666]accept",
		"if(bgp-communities includes 64512:666){accept;}":           "if[bgp-communities includes 64512:666]accept",
		`set comment "a;b}"; reject`:                                "set,reject",
		`if (dst in 192.0.2.0/24 && comment == "x { y") { reject }`: `if[dst in 192.0.2.0/24 && comment == "x { y"]reject`,
		"if (dst-len > 24) { }":                                     "if[dst-len > 24]",
		";; accept ;":                                               "accept",
		"if bgp-communities includes 64512:666 { accept }":          "other",
		"if (dst-len > 24) accept":                                  "other",
		"if (dst-len > 24) { accept; set bgp-med 1 }":               "other",
		"if (dst-len > 24) { if (dst-len > 25) { accept } }":        "other",
		"if (dst-len > 24) { accept } else { reject }; reject":      "other,reject",
		`set comment "unterminated`:                                 "set",
		"append bgp-large-communities 65536:1:1; accept":            "other,accept",
		"return":           "other",
		"if (dst-len > 24": "other",
	} {
		var parts []string
		for _, s := range parseRule(text) {
			p := s.kind
			if s.kind == "if" {
				p = "if[" + strings.Join(s.cond, " ") + "]" + s.action
			}
			parts = append(parts, p)
		}
		if got := strings.Join(parts, ","); got != want {
			t.Errorf("%q = %q, want %q", text, got, want)
		}
	}
}
