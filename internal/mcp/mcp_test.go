package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeBackend struct {
	calls  []Call
	status int
	body   string
}

func (f *fakeBackend) Do(_ context.Context, c Call) (int, []byte, error) {
	f.calls = append(f.calls, c)
	st := f.status
	if st == 0 {
		st = 200
	}
	return st, []byte(f.body), nil
}

func rpc(t *testing.T, s *Server, a Access, msg string) map[string]any {
	t.Helper()
	raw := s.Handle(context.Background(), []byte(msg), a)
	if raw == nil {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("answer %q: %v", raw, err)
	}
	return out
}

func toolText(t *testing.T, resp map[string]any) (string, bool) {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	c := res["content"].([]any)[0].(map[string]any)
	return c["text"].(string), res["isError"].(bool)
}

func call(name, args string) string {
	return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	s := &Server{Name: "packeteer", Version: "9.9", Backend: &fakeBackend{}}
	for _, tc := range []struct{ ask, want string }{
		{"2025-03-26", "2025-03-26"},
		{"2024-11-05", "2024-11-05"},
		{"1999-01-01", "2025-06-18"},
	} {
		r := rpc(t, s, Access{}, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+tc.ask+`"}}`)
		res := r["result"].(map[string]any)
		if res["protocolVersion"] != tc.want {
			t.Errorf("ask %s: got %v, want %s", tc.ask, res["protocolVersion"], tc.want)
		}
		if info := res["serverInfo"].(map[string]any); info["name"] != "packeteer" || info["version"] != "9.9" {
			t.Errorf("serverInfo %v", info)
		}
	}
}

func TestProtocolErrors(t *testing.T) {
	s := &Server{Backend: &fakeBackend{}}
	code := func(msg string) float64 {
		r := rpc(t, s, Access{}, msg)
		return r["error"].(map[string]any)["code"].(float64)
	}
	if got := code(`{not json`); got != codeParse {
		t.Errorf("parse error code %v", got)
	}
	if got := code(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`); got != codeRequest {
		t.Errorf("batch code %v", got)
	}
	if got := code(`{"jsonrpc":"1.0","id":1,"method":"ping"}`); got != codeRequest {
		t.Errorf("bad version code %v", got)
	}
	if got := code(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`); got != codeMethod {
		t.Errorf("unknown method code %v", got)
	}
	if got := code(call("nope", `{}`)); got != codeParams {
		t.Errorf("unknown tool code %v", got)
	}
	if r := rpc(t, s, Access{}, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); r != nil {
		t.Errorf("notification answered: %v", r)
	}
	if r := rpc(t, s, Access{}, `{"jsonrpc":"2.0","id":3,"method":"ping"}`); r["id"].(float64) != 3 || r["result"] == nil {
		t.Errorf("ping: %v", r)
	}
}

func listNames(t *testing.T, s *Server, a Access) map[string]bool {
	t.Helper()
	r := rpc(t, s, a, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	names := map[string]bool{}
	for _, x := range r["result"].(map[string]any)["tools"].([]any) {
		m := x.(map[string]any)
		if m["inputSchema"].(map[string]any)["type"] != "object" {
			t.Errorf("%v: schema is not an object", m["name"])
		}
		names[m["name"].(string)] = true
	}
	return names
}

func TestListHidesWriteToolsUnlessAllowed(t *testing.T) {
	s := &Server{Backend: &fakeBackend{}}
	read := listNames(t, s, Access{})
	full := listNames(t, s, Access{Write: true})
	if read["maintenance_open"] || read["maintenance_close"] {
		t.Error("write tool listed without Write")
	}
	if !full["maintenance_open"] || !full["maintenance_close"] {
		t.Error("write tool missing with Write")
	}
	for _, name := range []string{"system_health", "link_health", "decision_explain", "search", "events", "herd_outside", "maintenance_windows"} {
		if !read[name] {
			t.Errorf("read tool %s missing", name)
		}
	}
	for _, tool := range Catalog {
		if !tool.Write && !read[tool.Name] {
			t.Errorf("read tool %s not listed", tool.Name)
		}
	}
}

func TestCatalogInvariants(t *testing.T) {
	seen := map[string]bool{}
	denied := []string{"/api/config", "/api/users", "/api/tokens", "/api/audit", "/api/upgrade", "/api/herd/preview", "/api/herd/vantages", "/api/herd/mesh", "/api/herd/search", "/api/ring_lg", "/api/atlas", "/api/troubleshoot", "/api/mitigations", "/api/whatif", "/api/federation", "/metrics"}
	for _, tool := range Catalog {
		if seen[tool.Name] {
			t.Errorf("duplicate tool %s", tool.Name)
		}
		seen[tool.Name] = true
		if tool.Write == (tool.Method == http.MethodGet) {
			t.Errorf("%s: Write=%v with method %s", tool.Name, tool.Write, tool.Method)
		}
		if tool.Write && !strings.HasPrefix(tool.Desc, "WRITE.") {
			t.Errorf("%s: a write tool's description must start with WRITE.", tool.Name)
		}
		if !tool.Write && !strings.HasPrefix(tool.Path, "/api/") {
			t.Errorf("%s: path %s", tool.Name, tool.Path)
		}
		for _, d := range denied {
			if strings.HasPrefix(tool.Path, d) {
				t.Errorf("%s reaches %s, which an assistant must not read", tool.Name, d)
			}
		}
		for _, p := range tool.Params {
			if p.In == inPath && !strings.Contains(tool.Path, "{"+p.Name+"}") {
				t.Errorf("%s: path parameter %s has no placeholder", tool.Name, p.Name)
			}
		}
		if strings.Contains(tool.Path, "{") && strings.Count(tool.Path, "{") != 1 {
			t.Errorf("%s: more than one placeholder", tool.Name)
		}
	}
}

func TestToolCallBuildsRESTCall(t *testing.T) {
	fb := &fakeBackend{body: `{"ok":true}`}
	s := &Server{Backend: fb}

	text, isErr := toolText(t, rpc(t, s, Access{}, call("decision_explain", `{"prefix":"2001:db8::/32"}`)))
	if isErr || text != `{"ok":true}` {
		t.Fatalf("decision_explain: %q %v", text, isErr)
	}
	if c := fb.calls[0]; c.Method != "GET" || c.Path != "/api/decisions/2001:db8::/32" {
		t.Errorf("call %+v", c)
	}

	toolText(t, rpc(t, s, Access{}, call("prefixes", `{"asn":64496,"differs":true,"sort":"loss","limit":5,"provider":"transit-a"}`)))
	c := fb.calls[1]
	if c.Path != "/api/prefixes" || c.Query.Get("asn") != "64496" || c.Query.Get("differs") != "true" || c.Query.Get("sort") != "loss" || c.Query.Get("limit") != "5" || c.Query.Get("provider") != "transit-a" {
		t.Errorf("prefixes call %+v", c)
	}

	toolText(t, rpc(t, s, Access{Write: true}, call("maintenance_open", `{"providers":["transit-a"],"duration":"30m","reason":"lab"}`)))
	c = fb.calls[2]
	var body map[string]any
	if err := json.Unmarshal(c.Body, &body); err != nil || c.Method != "POST" || c.Path != "/api/maintenance" ||
		body["duration"] != "30m" || body["reason"] != "lab" || body["providers"].([]any)[0] != "transit-a" {
		t.Errorf("maintenance_open call %+v %s", c, c.Body)
	}

	toolText(t, rpc(t, s, Access{Write: true}, call("maintenance_close", `{"id":"api-1"}`)))
	if c := fb.calls[3]; c.Method != "DELETE" || c.Path != "/api/maintenance/api-1" || c.Body != nil {
		t.Errorf("maintenance_close call %+v", c)
	}
}

func TestToolArgumentsAreValidated(t *testing.T) {
	fb := &fakeBackend{}
	s := &Server{Backend: fb}
	for name, tc := range map[string]struct{ tool, args, want string }{
		"missing":      {"decision_explain", `{}`, `missing argument "prefix"`},
		"unknown":      {"overview", `{"x":1}`, `unknown argument "x"`},
		"bad prefix":   {"decision_explain", `{"prefix":"198.51.100.0/24/../../api/users"}`, "CIDR"},
		"not a string": {"search", `{"q":5}`, "want a string"},
		"bad enum":     {"events", `{"severity":"loud"}`, "want one of"},
		"bad int":      {"prefixes", `{"limit":"many"}`, "want an integer"},
		"bad asn":      {"herd_outside", `{"origin_asn":0}`, "AS number"},
		"control char": {"search", `{"q":"a\nb"}`, "control"},
		"long":         {"search", `{"q":"` + strings.Repeat("a", 300) + `"}`, "at most"},
		"bad id":       {"maintenance_close", `{"id":"../x"}`, "want an id"},
		"empty list":   {"maintenance_open", `{"providers":[],"duration":"1h"}`, "1 to 32"},
	} {
		text, isErr := toolText(t, rpc(t, s, Access{Write: true}, call(tc.tool, tc.args)))
		if !isErr || !strings.Contains(text, tc.want) {
			t.Errorf("%s: %q %v, want an error holding %q", name, text, isErr, tc.want)
		}
	}
	if len(fb.calls) != 0 {
		t.Errorf("a refused argument reached the backend: %+v", fb.calls)
	}
}

func TestWriteToolDeniedWithoutAccess(t *testing.T) {
	fb := &fakeBackend{}
	s := &Server{Backend: fb}
	var denied []string
	a := Access{OnDenied: func(tool string) { denied = append(denied, tool) }}
	text, isErr := toolText(t, rpc(t, s, a, call("maintenance_open", `{"providers":["transit-a"],"duration":"1h"}`)))
	if !isErr || !strings.Contains(text, "mcp:write") {
		t.Errorf("answer %q %v", text, isErr)
	}
	if len(fb.calls) != 0 || len(denied) != 1 || denied[0] != "maintenance_open" {
		t.Errorf("backend calls %v, denied %v", fb.calls, denied)
	}
}

func TestBackendStatusAndTruncation(t *testing.T) {
	fb := &fakeBackend{status: 403, body: `{"error":"forbidden: needs role operator"}`}
	s := &Server{Backend: fb}
	text, isErr := toolText(t, rpc(t, s, Access{}, call("overview", `{}`)))
	if !isErr || !strings.HasPrefix(text, "HTTP 403: ") || !strings.Contains(text, "needs role operator") {
		t.Errorf("error answer %q %v", text, isErr)
	}

	fb.status, fb.body = 204, ""
	if text, isErr := toolText(t, rpc(t, s, Access{}, call("overview", `{}`))); isErr || text != "ok (HTTP 204)" {
		t.Errorf("empty answer %q %v", text, isErr)
	}

	fb.status, fb.body = 200, strings.Repeat("\u00e9", MaxResult)
	text, isErr = toolText(t, rpc(t, s, Access{}, call("overview", `{}`)))
	if isErr || !strings.Contains(text, "[truncated: ") || len(text) > MaxResult+64 {
		t.Errorf("long answer not cut: %d bytes %v", len(text), isErr)
	}
	if strings.Contains(text, "\ufffd") {
		t.Error("truncation split a rune")
	}
}

func TestValidateURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"http://127.0.0.1:8080/mcp":     true,
		"http://localhost:8080/mcp":     true,
		"http://[::1]:8080/mcp":         true,
		"https://packeteer.example.net": true,
		"http://192.0.2.10:8080/mcp":    false,
		"http://packeteer.example.net/": false,
		"https://user:pw@example.net/":  false,
		"ftp://127.0.0.1/":              false,
		"":                              false,
	} {
		if err := ValidateURL(raw); (err == nil) != ok {
			t.Errorf("%q: %v, want ok=%v", raw, err, ok)
		}
	}
}

func TestBridgeForwardsLines(t *testing.T) {
	var got []string
	var auth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		got = append(got, string(b))
		if strings.Contains(string(b), "notifications/") {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if strings.Contains(string(b), `"id":9`) {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}` + "\n"))
	}))
	defer ts.Close()

	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		``,
		`{"jsonrpc":"2.0","id":9,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
	}, "\n")
	var out bytes.Buffer
	b := &Bridge{URL: ts.URL, Token: "pkt_example"}
	if err := b.Run(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer pkt_example" {
		t.Errorf("Authorization %q", auth)
	}
	if len(got) != 4 {
		t.Fatalf("forwarded %d messages, want 4 (blank line skipped): %q", len(got), got)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("answers %q, want ping, an error for id 9, ping (the notification has none)", lines)
	}
	if !strings.Contains(lines[1], `"id":9`) || !strings.Contains(lines[1], "HTTP 401") {
		t.Errorf("refused request answered %q", lines[1])
	}
}

func TestBridgeUnreachableAndTooLong(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	url := ts.URL
	ts.Close()
	long := `{"jsonrpc":"2.0","id":5,"method":"` + strings.Repeat("a", MaxRequest+10) + `"}`
	in := `{"jsonrpc":"2.0","id":4,"method":"ping"}` + "\n" + long + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	var out bytes.Buffer
	b := &Bridge{URL: url, Token: "pkt_example"}
	if err := b.Run(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"id":4`) || !strings.Contains(lines[0], "unreachable") || !strings.Contains(lines[1], "too long") {
		t.Fatalf("answers %q", lines)
	}
}

func TestBridgeDoesNotFollowRedirects(t *testing.T) {
	var leaked bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization") != ""
	}))
	defer other.Close()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer ts.Close()
	var out bytes.Buffer
	b := &Bridge{URL: ts.URL, Token: "pkt_example"}
	if err := b.Run(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Error("the token was sent to the redirect target")
	}
	if !strings.Contains(out.String(), "HTTP 307") {
		t.Errorf("answer %q", out.String())
	}
}
