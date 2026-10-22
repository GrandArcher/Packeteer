package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/outside"
)

// boardHerd answers the dashboard views and records the raw query. The
// other HerdSource methods are never called by these tests.
type boardHerd struct {
	HerdSource
	raw string
	err error
}

func (b *boardHerd) Overview(context.Context) (herd.Overview, error) {
	return herd.Overview{Enabled: true, Members: []herd.MemberRow{{Member: "local", Local: true, ASN: 64501}}, Countries: []string{"US"}}, b.err
}

func (b *boardHerd) Events(_ context.Context, raw string) (herd.Events, error) {
	b.raw = raw
	return herd.Events{Enabled: true, Basis: herd.Basis, Events: []herd.EventRow{{Target: herd.Target{Kind: "origin_asn", Value: "64510"}, Reporting: 4, Degraded: 3}}}, b.err
}

func (b *boardHerd) Mesh(_ context.Context, raw string) (herd.Mesh, error) {
	b.raw = raw
	return herd.Mesh{Enabled: true}, b.err
}

func (b *boardHerd) Monitor(_ context.Context, raw string) (herd.Monitor, error) {
	b.raw = raw
	return herd.Monitor{Enabled: true}, b.err
}

func (b *boardHerd) Map(_ context.Context, raw string) (herd.Map, error) {
	b.raw = raw
	return herd.Map{Enabled: true, Countries: []herd.Country{{Country: "DE", Condition: "degraded"}}}, b.err
}

func (b *boardHerd) Search(_ context.Context, raw string) (herd.Search, error) {
	b.raw = raw
	return herd.Search{Enabled: true}, b.err
}

func getJSON(t *testing.T, s *Server, path string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: %v: %s", path, err, rec.Body)
	}
	return rec.Code, body
}

var boardPaths = []string{"/api/herd/overview", "/api/herd/events", "/api/herd/mesh", "/api/herd/monitor", "/api/herd/map", "/api/herd/search"}

func TestHerdBoardOffReportsEmptyViews(t *testing.T) {
	s := newIXPServer(t)
	for _, p := range boardPaths {
		code, body := getJSON(t, s, p)
		if code != http.StatusOK || body["enabled"] != false {
			t.Errorf("%s with herd off = %d %v", p, code, body)
		}
	}
	for path, key := range map[string]string{
		"/api/herd/overview": "members", "/api/herd/events": "events", "/api/herd/mesh": "rows",
		"/api/herd/monitor": "series", "/api/herd/map": "countries", "/api/herd/search": "hits",
	} {
		_, body := getJSON(t, s, path)
		if l, ok := body[key].([]any); !ok || len(l) != 0 {
			t.Errorf("%s: %s = %#v, want an empty list", path, key, body[key])
		}
	}
}

func TestHerdBoardPassesTheQueryAndMapsErrors(t *testing.T) {
	s := newIXPServer(t)
	h := &boardHerd{}
	s.SetHerd(h)

	code, body := getJSON(t, s, "/api/herd/events?window=1h&loss=10")
	events, _ := body["events"].([]any)
	if code != http.StatusOK || h.raw != "window=1h&loss=10" || body["basis"] != "pinned_key" || len(events) != 1 {
		t.Errorf("events = %d %v (query %q)", code, body, h.raw)
	}
	for _, p := range boardPaths {
		if code, _ := getJSON(t, s, p+"?x=1"); code != http.StatusOK {
			t.Errorf("%s = %d", p, code)
		}
	}
	if _, body := getJSON(t, s, "/api/herd/map"); body["enabled"] != true {
		t.Errorf("map = %v", body)
	}

	h.err = herd.QueryError{Msg: `unknown parameter "bogus"`}
	if code, body := getJSON(t, s, "/api/herd/events?bogus=1"); code != http.StatusBadRequest || body["error"] != `unknown parameter "bogus"` {
		t.Errorf("query error = %d %v", code, body)
	}
	h.err = errors.New("sqlite: disk I/O error at /var/lib/packeteer/x.db")
	code, body = getJSON(t, s, "/api/herd/search?origin_asn=64510")
	if code != http.StatusInternalServerError || body["error"] != "herd store unavailable" || strings.Contains(body["error"].(string), "sqlite") {
		t.Errorf("store error = %d %v, want a generic message", code, body)
	}
}

// stubOutside records the target it was asked about.
type stubOutside struct {
	got outside.Target
}

func (s *stubOutside) IDs() []string { return []string{"links"} }

func (s *stubOutside) Sections(t outside.Target, _ time.Time) []outside.Section {
	s.got = t
	return []outside.Section{{ID: "links", Source: "link-outs"}}
}

func TestHerdOutsideEndpoint(t *testing.T) {
	s := newIXPServer(t)
	code, body := getJSON(t, s, "/api/herd/outside?origin_asn=64510")
	if l, ok := body["sections"].([]any); code != http.StatusOK || !ok || len(l) != 0 {
		t.Fatalf("no sources: %d %v", code, body)
	}
	if l, ok := body["sources"].([]any); !ok || len(l) != 0 {
		t.Errorf("sources = %#v, want an empty list", body["sources"])
	}

	st := &stubOutside{}
	s.SetHerdOutside(st)
	code, body = getJSON(t, s, "/api/herd/outside?prefix=198.51.100.0/24&origin_asn=64510")
	secs, _ := body["sections"].([]any)
	if code != http.StatusOK || len(secs) != 1 || st.got.Prefix.String() != "198.51.100.0/24" || st.got.ASN != 64510 {
		t.Fatalf("with a source: %d %v, asked %+v", code, body, st.got)
	}
	if srcs, _ := body["sources"].([]any); len(srcs) != 1 || srcs[0] != "links" {
		t.Errorf("sources = %v", body["sources"])
	}
	for _, q := range []string{"prefix=198.51.100.7/24", "prefix=x", "origin_asn=0", "origin_asn=abc", "origin_asn=99999999999", "bogus=1"} {
		if code, _ := getJSON(t, s, "/api/herd/outside?"+q); code != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
}

func TestHerdPageIsServed(t *testing.T) {
	s := newIXPServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/herd.html", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-page="herd"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
