package file

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newFeed(t *testing.T, path string) *Feed {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML("path: " + path + "\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "radar-export"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	return p.(*Feed)
}

// #401: the feed answers incidents that overlap the asked prefix, from a
// recorded file, and nothing else.
func TestIncidentsOverlap(t *testing.T) {
	f := newFeed(t, "testdata/incidents.json")
	got, err := f.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Origin != 64511 || got[0].Detail != "possible origin hijack, expected AS64500" {
		t.Fatalf("exact prefix: %+v", got)
	}
	got, _ = f.Incidents(t.Context(), netip.MustParsePrefix("203.0.113.0/24"))
	if len(got) != 1 || got[0].Prefix != netip.MustParsePrefix("203.0.113.128/25") || got[0].Origin != 0 {
		t.Fatalf("covered more-specific: %+v", got)
	}
	got, _ = f.Incidents(t.Context(), netip.MustParsePrefix("192.0.2.0/24"))
	if len(got) != 0 {
		t.Fatalf("unrelated prefix: %+v", got)
	}
}

// #401: a missing or broken file is an error, never an empty answer, so
// it is not read as "no incident"; a good list survives a later broken
// write but not the file's removal.
func TestIncidentsErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incidents.json")
	f := newFeed(t, path)
	if _, err := f.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatal("missing file answered")
	}
	if err := os.WriteFile(path, []byte(`{"incidents":[{"prefix":"198.51.100.0/24"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24")); err != nil || len(got) != 1 {
		t.Fatalf("after write: %v %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"incidents":[{"prefix":"not a prefix"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24")); err != nil || len(got) != 1 {
		t.Fatalf("broken rewrite must keep the last good list: %v %v", got, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatalf("a removed file still answered %v", got)
	}
	if err := os.WriteFile(path, []byte(`{"incidents":[{"prefix":"not a prefix"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatalf("a file broken after a removal answered the list from before it: %v", got)
	}
	broken := newFeed(t, path)
	if _, err := broken.Incidents(t.Context(), netip.MustParsePrefix("198.51.100.0/24")); err == nil {
		t.Fatal("a broken file with no good read answered")
	}
}

func TestNewNeedsPath(t *testing.T) {
	cfg, _ := plugin.ConfigFromYAML("path: ' '\n")
	if _, err := New(cfg, plugin.Env{}); err == nil {
		t.Fatal("empty path accepted")
	}
}
