package invcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func env(token string) func(string) string {
	return func(string) string { return token }
}

func TestValidate(t *testing.T) {
	good := Common{BaseURL: "https://netbox.example.invalid/", Tag: "packeteer"}
	s, err := Validate(good)
	if err != nil {
		t.Fatal(err)
	}
	if s.Base.String() != "https://netbox.example.invalid" || s.Timeout != DefaultTimeout || s.Tag != "packeteer" {
		t.Fatalf("%+v", s)
	}
	if _, err := Validate(Common{BaseURL: "http://127.0.0.1:8080", Tag: "t"}); err != nil {
		t.Fatalf("loopback http: %v", err)
	}
	for name, tc := range map[string]struct {
		c    Common
		want string
	}{
		"http remote":      {Common{BaseURL: "http://netbox.example.invalid", Tag: "t"}, "must be https"},
		"no tag":           {Common{BaseURL: good.BaseURL}, "tag is required"},
		"bad tag":          {Common{BaseURL: good.BaseURL, Tag: "a b"}, "tag is required"},
		"userinfo":         {Common{BaseURL: "https://u:p@netbox.example.invalid", Tag: "t"}, "no userinfo"},
		"query":            {Common{BaseURL: "https://netbox.example.invalid/?a=b", Tag: "t"}, "no userinfo"},
		"timeout too long": {Common{BaseURL: good.BaseURL, Tag: "t", Timeout: 1 << 62}, "timeout"},
		"empty url":        {Common{Tag: "t"}, "base_url"},
	} {
		if _, err := Validate(tc.c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

func TestToken(t *testing.T) {
	s, err := Validate(Common{BaseURL: "https://netbox.example.invalid/lab-token", Tag: "t"})
	if err != nil {
		t.Fatal(err)
	}
	other, _ := Validate(Common{BaseURL: "https://netbox.example.invalid", Tag: "t"})
	if tok, err := Token(other, "TOK", env(" lab-token\n")); err != nil || tok != "lab-token" {
		t.Fatalf("token %q err %v", tok, err)
	}
	for name, tc := range map[string]struct {
		s     Settings
		token string
		want  string
	}{
		"missing":      {other, "", "set TOK"},
		"space":        {other, "a b", "invalid character"},
		"non ascii":    {other, "t\u00f6ken", "invalid character"},
		"too long":     {other, strings.Repeat("a", maxTokenLen+1), "too long"},
		"token in url": {s, "lab-token", "must not contain the API token"},
	} {
		if _, err := Token(tc.s, "TOK", env(tc.token)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Transit A":         "transit-a",
		"  AS64496 -- Foo":  "as64496-foo",
		"---":               "",
		"\u00dcn\u00ef Net": "n-net",
	} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Slug(strings.Repeat("ab-", 40)); len(got) > 64 || strings.HasSuffix(got, "-") {
		t.Errorf("long slug %q", got)
	}
}

func TestProvider(t *testing.T) {
	p, err := Provider("transit-a", 64496, map[string]any{
		"type": "transit", "source_ip": "192.0.2.10", "next_hop": " 192.0.2.1 ",
		"communities": "64496:100, 64496:200 64496:100;64496:1:2",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := plugin.InventoryProvider{Name: "transit-a", ASN: 64496, Type: "transit", SourceIP: "192.0.2.10", NextHop: "192.0.2.1",
		Communities: []string{"64496:100", "64496:200", "64496:1:2"}}
	if p.Name != want.Name || p.ASN != want.ASN || p.Type != want.Type || p.SourceIP != want.SourceIP || p.NextHop != want.NextHop || !slices.Equal(p.Communities, want.Communities) {
		t.Fatalf("%+v", p)
	}
	l, err := Provider("x", 0, map[string]any{"communities": []any{"64496:7"}})
	if err != nil || !slices.Equal(l.Communities, []string{"64496:7"}) {
		t.Fatalf("list form: %+v %v", l, err)
	}
	empty, err := Provider("x", 0, nil)
	if err != nil || empty.NextHop != "" || empty.Communities != nil {
		t.Fatalf("empty bag: %+v %v", empty, err)
	}
	for name, bag := range map[string]map[string]any{
		"type":       {"type": "upstream"},
		"next hop":   {"next_hop": "not-an-ip"},
		"source ip":  {"source_ip": 5},
		"community":  {"communities": "64496"},
		"large":      {"communities": "1:2:3:4"},
		"list shape": {"communities": []any{1}},
		"shape":      {"communities": 7},
	} {
		if _, err := Provider("x", 0, bag); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResultSkipsSharedNames(t *testing.T) {
	r := Result([]plugin.InventoryProvider{{Name: "b"}, {Name: "a"}, {Name: "b"}, {Name: "c"}}, []plugin.InventorySkip{{Name: "z", Reason: "bad"}})
	var names []string
	for _, p := range r.Providers {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"a", "c"}) {
		t.Fatalf("providers %v", names)
	}
	if len(r.Skipped) != 2 || r.Skipped[0].Name != "b" || r.Skipped[1].Name != "z" {
		t.Fatalf("skipped %+v", r.Skipped)
	}
}

func listServer(t *testing.T, total int, check func(*http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		end := min(offset+limit, total)
		var rows []map[string]int
		for i := offset; i < end; i++ {
			rows = append(rows, map[string]int{"id": i})
		}
		resp := map[string]any{"count": total, "results": rows, "next": nil}
		if end < total {
			resp["next"] = "http://elsewhere.invalid/next"
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func client(t *testing.T, srv *httptest.Server, token string) *Client {
	t.Helper()
	s, err := Validate(Common{BaseURL: srv.URL, Tag: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return NewClient(s, "Token", token)
}

func TestGetAllPagesByOffsetAndSendsOnlyGET(t *testing.T) {
	var requests int
	srv := listServer(t, 450, func(r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Token lab-token" || r.URL.Path != "/api/x/" || r.URL.Query().Get("tag") != "t" {
			t.Errorf("request %s %s auth %q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
	})
	defer srv.Close()
	seen := map[int]bool{}
	err := client(t, srv, "lab-token").GetAll(context.Background(), "/api/x/", map[string][]string{"tag": {"t"}}, func(raw json.RawMessage) error {
		var row struct{ ID int }
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		seen[row.ID] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 450 || requests != 3 {
		t.Fatalf("rows %d requests %d", len(seen), requests)
	}
}

func TestGetAllErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "http://elsewhere.invalid/", http.StatusFound)
		case "/denied":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "body that must not be echoed lab-token")
		case "/big":
			fmt.Fprint(w, strings.Repeat("x", maxBody+10))
		default:
			fmt.Fprint(w, "not json")
		}
	}))
	defer bad.Close()
	c := client(t, bad, "lab-token")
	for path, want := range map[string]string{
		"/redirect": "redirects are not followed",
		"/denied":   "HTTP 403",
		"/big":      "over",
		"/junk":     "not a list response",
	} {
		err := c.GetAll(context.Background(), path, nil, func(json.RawMessage) error { return nil })
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "lab-token") {
			t.Errorf("%s: err %v, want %q", path, err, want)
		}
	}
	endless := listServer(t, 1<<30, nil)
	defer endless.Close()
	err := client(t, endless, "lab-token").GetAll(context.Background(), "/p", nil, func(json.RawMessage) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("endless list: %v", err)
	}
}
