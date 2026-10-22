package outside

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func TestEmptySetShowsNothing(t *testing.T) {
	var nilSet *Set
	for _, s := range []*Set{nilSet, NewSet()} {
		if ids := s.IDs(); ids == nil || len(ids) != 0 {
			t.Errorf("IDs = %#v, want an empty list", ids)
		}
		if secs := s.Sections(Target{ASN: 64510}, now); secs == nil || len(secs) != 0 {
			t.Errorf("Sections = %#v, want an empty list", secs)
		}
	}
}

func TestSetKeepsOrderAndAsksEachSource(t *testing.T) {
	s := NewSet(Links{Set: linkout.New(linkout.Config{})}, RPKI{Validate: func(netip.Prefix, uint32) plugin.RPKIValidity { return plugin.RPKIValid }, Updated: func() time.Time { return now }})
	if ids := strings.Join(s.IDs(), ","); ids != "links,rpki" {
		t.Errorf("ids = %s", ids)
	}
	secs := s.Sections(Target{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64510}, now)
	if len(secs) != 2 || secs[0].ID != "links" || secs[1].ID != "rpki" {
		t.Fatalf("sections = %+v", secs)
	}
}

func TestRPKISection(t *testing.T) {
	var asked []string
	r := RPKI{
		Validate: func(p netip.Prefix, a uint32) plugin.RPKIValidity {
			asked = append(asked, fmt.Sprint(p, a))
			if a == 64510 {
				return plugin.RPKIValid
			}
			return plugin.RPKIInvalid
		},
		Updated: func() time.Time { return now.Add(-90 * time.Second) },
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	sec := r.Section(Target{Prefix: p, ASN: 64511}, now)
	if len(sec.Rows) != 1 || sec.Rows[0][2] != "invalid" || sec.Rows[0][1] != "AS64511" || sec.AgeSeconds == nil || *sec.AgeSeconds != 90 {
		t.Errorf("section = %+v", sec)
	}
	if sec.Source == "" {
		t.Error("section has no source label")
	}
	for _, tg := range []Target{{ASN: 64510}, {Prefix: p}, {}} {
		sec := r.Section(tg, now)
		if len(sec.Rows) != 0 || !strings.Contains(sec.Note, "prefix and its origin ASN") {
			t.Errorf("%+v: section = %+v", tg, sec)
		}
	}
	if len(asked) != 1 {
		t.Errorf("validated %v, want only the complete target", asked)
	}
}

func TestLinksSection(t *testing.T) {
	l := Links{Set: linkout.New(linkout.Config{Enabled: []string{"ripestat", "cloudflare_radar"}})}
	sec := l.Section(Target{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASN: 64510}, now)
	var urls []string
	for _, k := range sec.Links {
		urls = append(urls, k.URL)
	}
	if strings.Join(urls, " ") != "https://stat.ripe.net/app/launchpad/198.51.100.0/24 https://stat.ripe.net/app/launchpad/AS64510 https://radar.cloudflare.com/routing/as64510" {
		t.Errorf("links = %v", urls)
	}
	if sec.AsOf != nil {
		t.Error("link-outs carry no data age")
	}
	if sec := l.Section(Target{}, now); len(sec.Links) != 0 || sec.Note == "" {
		t.Errorf("no target: %+v", sec)
	}
}

func TestRISShowsOnlyRISLiveSightings(t *testing.T) {
	seen := now.Add(-5 * time.Minute)
	st := leakwatch.Status{
		State:   "watching",
		Sources: []leakwatch.SourceStatus{{Name: "ris", Type: "rislive", Healthy: true}, {Name: "other", Type: "exec", Healthy: true}},
		Leaks: []leakwatch.Leak{
			{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Reason: "community", Source: "ris", Seen: "route collector", ASPath: []uint32{64496, 64501, 64510}, LastSeen: seen},
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Reason: "community", Source: "other", LastSeen: now},
		},
	}
	r := RIS{Status: func() leakwatch.Status { return st }}
	sec := r.Section(Target{}, now)
	if len(sec.Rows) != 1 || sec.Rows[0][0] != "198.51.100.0/24" || sec.Rows[0][2] != "64496 64501 64510" {
		t.Fatalf("rows = %v", sec.Rows)
	}
	if sec.AgeSeconds == nil || *sec.AgeSeconds != 300 || sec.Note != "" || !strings.Contains(sec.Source, "RIS Live") {
		t.Errorf("section = %+v", sec)
	}

	st.Leaks = nil
	if sec := r.Section(Target{}, now); !strings.Contains(sec.Note, "No route of this AS") || sec.AsOf != nil {
		t.Errorf("quiet: %+v", sec)
	}
	st.Sources[0].Healthy = false
	if sec := r.Section(Target{}, now); !strings.Contains(sec.Note, "not proof") {
		t.Errorf("down stream must not read as clean: %+v", sec)
	}
}

// atlasServer answers the three Atlas paths and counts requests.
func atlasServer(t *testing.T, fail *atomic.Bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var reqs atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/measurements/1001/latest/", func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		var b strings.Builder
		b.WriteString(`[{"type":"traceroute","msm_id":1001,"prb_id":1,"sent":3},`)
		b.WriteString(`{"type":"ping","msm_id":1001,"prb_id":7,"sent":3,"rcvd":3,"avg":12.34,"timestamp":1792709104,"src_addr":"10.0.0.1","from":"203.0.113.9"},`)
		b.WriteString(`{"type":"ping","msm_id":1001,"prb_id":8,"sent":3,"rcvd":0,"timestamp":1792709105}`)
		for i := range 30 {
			fmt.Fprintf(&b, `,{"type":"ping","msm_id":1001,"prb_id":%d,"sent":4,"rcvd":4,"avg":5,"timestamp":1792709100}`, 100+i)
		}
		b.WriteString(`]`)
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/probes/6001/", func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		_, _ = w.Write([]byte(`{"id":6001,"country_code":"NL","is_anchor":true,"address_v4":"192.0.2.9","status":{"id":1,"name":"Connected","since":"2026-10-01T00:00:00Z"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &reqs
}

func TestAtlasReadsPublicResultsAndKeepsThemOnFailure(t *testing.T) {
	var fail atomic.Bool
	srv, reqs := atlasServer(t, &fail)
	clock := now
	a := NewAtlas(AtlasOptions{BaseURL: srv.URL, Measurements: []int{1001}, Probes: []int{6001}, Refresh: time.Hour, Now: func() time.Time { return clock }})

	if sec := a.Section(Target{}, now); sec.AsOf != nil || sec.Note != "Not read yet." || len(sec.Rows) != 0 {
		t.Errorf("before the first read: %+v", sec)
	}
	a.refresh(context.Background())
	sec := a.Section(Target{ASN: 64510}, now.Add(2*time.Minute))
	if reqs.Load() != 2 {
		t.Errorf("requests = %d, want one per measurement and probe", reqs.Load())
	}
	if sec.AgeSeconds == nil || *sec.AgeSeconds != 120 || sec.Error != "" || !strings.Contains(sec.Source, "RIPE Atlas") {
		t.Errorf("label = %+v", sec)
	}
	// 25 ping rows (the cap) plus the own probe. The worst probe is first.
	if len(sec.Rows) != atlasRows+1 {
		t.Fatalf("rows = %d", len(sec.Rows))
	}
	if r := sec.Rows[0]; r[0] != "mesh measurement 1001, probe 8" || r[2] != "100.0 %" || r[3] != "" {
		t.Errorf("worst row = %v", r)
	}
	if r := sec.Rows[atlasRows]; r[0] != "own anchor 6001 (NL)" || r[1] != "Connected" || r[4] != "2026-10-01T00:00:00Z" {
		t.Errorf("probe row = %v", r)
	}
	if !strings.Contains(sec.Note, "1 results of other types") {
		t.Errorf("note = %q", sec.Note)
	}
	for _, r := range sec.Rows {
		for _, c := range r {
			if strings.Contains(c, "203.0.113.9") || strings.Contains(c, "10.0.0.1") || strings.Contains(c, "192.0.2.9") {
				t.Errorf("an address leaked into the row %v", r)
			}
		}
	}

	fail.Store(true)
	clock = now.Add(time.Hour)
	a.refresh(context.Background())
	after := a.Section(Target{}, now.Add(time.Hour))
	if after.Error == "" || len(after.Rows) != atlasRows+1 || after.AgeSeconds == nil || *after.AgeSeconds != 3600 {
		t.Errorf("a failed read must keep the last rows, show the error, and keep their age: %+v", after)
	}
}

func TestAtlasRefusesOversizedAndBadResponses(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[` + strings.Repeat(" ", atlasMaxBody+10) + `]`))
	}))
	defer big.Close()
	a := NewAtlas(AtlasOptions{BaseURL: big.URL, Measurements: []int{1}, Refresh: time.Hour})
	a.refresh(context.Background())
	if sec := a.Section(Target{}, now); !strings.Contains(sec.Error, "response over") || len(sec.Rows) != 0 {
		t.Errorf("oversized: %+v", sec)
	}
	junk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"not":"a list"}`)) }))
	defer junk.Close()
	a = NewAtlas(AtlasOptions{BaseURL: junk.URL, Measurements: []int{1}, Refresh: time.Hour})
	a.refresh(context.Background())
	if sec := a.Section(Target{}, now); sec.Error == "" {
		t.Errorf("junk body: %+v", sec)
	}
}

func TestAtlasDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer srv.Close()
	a := NewAtlas(AtlasOptions{BaseURL: srv.URL, Probes: []int{6001}, Refresh: time.Hour})
	a.refresh(context.Background())
	if sec := a.Section(Target{}, now); !strings.Contains(sec.Error, "302") || elsewhere.Load() != 0 {
		t.Errorf("error %q, followed %d requests", sec.Error, elsewhere.Load())
	}
}

func TestAtlasRunStopsWithContext(t *testing.T) {
	var fail atomic.Bool
	srv, reqs := atlasServer(t, &fail)
	a := NewAtlas(AtlasOptions{BaseURL: srv.URL, Probes: []int{6001}, Refresh: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for reqs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if reqs.Load() != 1 {
		t.Errorf("requests = %d, want the first read only", reqs.Load())
	}
}

// Outside data is display only: nothing but the daemon wiring and the ops
// API may import this package, so no decision, scorer, planner, or
// announcer can read it.
func TestOnlyTheDaemonAndTheOpsAPIImportOutside(t *testing.T) {
	allowed := map[string]bool{"cmd/controller": true, "internal/httpapi": true}
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(root, filepath.Dir(path))
		rel = filepath.ToSlash(rel)
		if rel == "internal/outside" || allowed[rel] {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			if strings.HasSuffix(imp.Path.Value, `/internal/outside"`) {
				t.Errorf("%s imports internal/outside: outside data must stay out of decisions and announcing", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
