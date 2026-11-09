package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type leakFeed struct {
	plugin.Base
	sink func(plugin.LeakSighting)
}

func (f *leakFeed) SetLeakSink(fn func(plugin.LeakSighting)) { f.sink = fn }
func (f *leakFeed) Healthy() bool                            { return true }

func leakServer(t *testing.T, lc LeakControl, user string) http.Handler {
	t.Helper()
	pass := ""
	if user != "" {
		pass = "secret"
	}
	s, err := New(Options{User: user, Password: pass, Leaks: lc, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func TestLeakEndpointsAndMetrics(t *testing.T) {
	off := leakServer(t, nil, "ops")
	rec := mdo(off, http.MethodGet, "/api/leaks", "", "", true)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"leaks":[]`) {
		t.Fatalf("not enabled: %d %s", rec.Code, rec.Body)
	}
	if rec := mdo(off, http.MethodPost, "/api/leaks/clear", "application/json", `{"prefix":"203.0.113.0/24"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("clear without leak_watch: %d", rec.Code)
	}
	if strings.Contains(mdo(off, http.MethodGet, "/metrics", "", "", true).Body.String(), "packeteer_leak") {
		t.Fatal("leak metrics without leak_watch")
	}

	feed := &leakFeed{}
	p := netip.MustParsePrefix("203.0.113.0/24")
	w := leakwatch.New(leakwatch.Config{
		ASN: 64500, Community: 64500<<16 | 666, Injected: func(netip.Prefix) bool { return false },
		Withdraw: func(context.Context, netip.Prefix) error { return nil }, Log: slog.New(slog.DiscardHandler),
	}, []leakwatch.Source{{Name: "ris", Type: "rislive", Plugin: feed}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	feed.sink(plugin.LeakSighting{Prefix: p, Communities: []uint32{64500<<16 | 666}, Seen: "rrc00/192.0.2.9"})
	for end := time.Now().Add(5 * time.Second); !w.Held(p); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the sighting was not evaluated")
		}
	}
	cleared := 0
	on := leakServer(t, countingClear{w, &cleared}, "ops")

	var body struct {
		Enabled  bool `json:"enabled"`
		Writable bool `json:"writable"`
		Leaks    []struct {
			Prefix string `json:"prefix"`
			Reason string `json:"reason"`
			Action string `json:"action"`
		} `json:"leaks"`
	}
	rec = mdo(on, http.MethodGet, "/api/leaks", "", "", true)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || !body.Writable || len(body.Leaks) != 1 || body.Leaks[0].Prefix != "203.0.113.0/24" || body.Leaks[0].Reason != "community" || body.Leaks[0].Action != "held" {
		t.Fatalf("body %s", rec.Body)
	}
	m := mdo(on, http.MethodGet, "/metrics", "", "", true).Body.String()
	for _, want := range []string{"packeteer_leaks_held 1", `packeteer_leak_source_up{source="ris"}`, "packeteer_leak_sightings_dropped 0"} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics lack %q:\n%s", want, m)
		}
	}

	// Clearing needs auth, JSON, and a valid held prefix.
	if rec := mdo(on, http.MethodPost, "/api/leaks/clear", "application/json", `{"prefix":"203.0.113.0/24"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: %d", rec.Code)
	}
	if rec := mdo(on, http.MethodPost, "/api/leaks/clear", "text/plain", `{"prefix":"203.0.113.0/24"}`, true); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", rec.Code)
	}
	if rec := mdo(on, http.MethodPost, "/api/leaks/clear", "application/json", `{"prefix":"nope"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad prefix: %d", rec.Code)
	}
	if rec := mdo(on, http.MethodPost, "/api/leaks/clear", "application/json", `{"prefix":"198.51.100.0/24"}`, true); rec.Code != http.StatusNotFound || cleared != 0 {
		t.Fatalf("not held: %d", rec.Code)
	}
	if !w.Held(p) {
		t.Fatal("a refused clear released the prefix")
	}
	if rec := mdo(on, http.MethodPost, "/api/leaks/clear", "application/json", `{"prefix":"203.0.113.0/24"}`, true); rec.Code != http.StatusNoContent || w.Held(p) || cleared != 1 {
		t.Fatalf("clear: %d held=%v", rec.Code, w.Held(p))
	}
}

// countingClear counts the clears that released a prefix.
type countingClear struct {
	*leakwatch.Watcher
	n *int
}

func (c countingClear) Clear(p netip.Prefix) bool {
	ok := c.Watcher.Clear(p)
	if ok {
		*c.n++
	}
	return ok
}

func TestLeakClearAuditsOnlyAReleasedHold(t *testing.T) {
	e := newRBAC(t, nil)
	feed := &leakFeed{}
	p := netip.MustParsePrefix("203.0.113.0/24")
	w := leakwatch.New(leakwatch.Config{
		Community: 64500<<16 | 666, Injected: func(netip.Prefix) bool { return false },
		Withdraw: func(context.Context, netip.Prefix) error { return nil }, Log: slog.New(slog.DiscardHandler),
	}, []leakwatch.Source{{Name: "ris", Type: "rislive", Plugin: feed}})
	e.srv.leaks = w
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	feed.sink(plugin.LeakSighting{Prefix: p, Communities: []uint32{64500<<16 | 666}})
	for end := time.Now().Add(5 * time.Second); !w.Held(p); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the sighting was not evaluated")
		}
	}
	clear := func(prefix string) (int, plugin.AuditRecord) {
		t.Helper()
		rec := e.do(http.MethodPost, "/api/leaks/clear", e.tokens[plugin.RoleOperator], `{"prefix":"`+prefix+`"}`, func(r *http.Request) {
			r.Header.Set("Content-Type", "application/json")
		})
		recs := e.store.Records()
		return rec.Code, recs[len(recs)-1]
	}
	if code, a := clear("198.51.100.0/24"); code != http.StatusNotFound || a.Detail == "leak hold cleared" {
		t.Fatalf("not held: %d, audited %+v", code, a)
	}
	if code, a := clear("203.0.113.0/24"); code != http.StatusNoContent || a.Detail != "leak hold cleared" || a.Target != "203.0.113.0/24" {
		t.Fatalf("cleared: %d, audited %+v", code, a)
	}
}
