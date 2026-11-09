package ripestat

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fixtureServer answers the rpki-validation data call from testdata by
// the queried origin and prefix, and counts calls.
func fixtureServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	files := map[string]string{
		"AS64496 192.0.2.0/24":   "unknown.json",
		"AS64496 203.0.113.0/24": "valid.json",
		"AS64511 203.0.113.0/24": "invalid_asn.json",
		"AS64496 203.0.113.0/25": "invalid_length.json",
	}
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if r.URL.Path != "/data/rpki-validation/data.json" || q.Get("sourceapp") != "packeteer" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		name, ok := files[q.Get("resource")+" "+q.Get("prefix")]
		if !ok {
			http.Error(w, "no fixture", http.StatusInternalServerError)
			return
		}
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func newClient(t *testing.T, yaml, base string) *Client {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "ripestat"})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	c.base = base
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Stop(t.Context()) })
	return c
}

func waitAnswer(t *testing.T, c *Client, prefix string, origin uint32) plugin.RPKIAnswer {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if a := c.Answer(p, origin); a.State != plugin.RPKIUnknown {
			return a
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s AS%d never answered", prefix, origin)
	return plugin.RPKIAnswer{}
}

// #200: a miss is unknown and queued; the answer then carries the source
// name and the lookup time. RIPEstat's unknown is RFC 6811 not found, and
// both invalid kinds are invalid.
func TestLookupStates(t *testing.T) {
	srv, _ := fixtureServer(t)
	c := newClient(t, "rate_per_minute: 60\n", srv.URL)
	if a := c.Answer(netip.MustParsePrefix("192.0.2.0/24"), 64496); a.State != plugin.RPKIUnknown || a.Source != "" {
		t.Fatalf("first lookup = %+v, want unknown while queued", a)
	}
	before := time.Now()
	for _, tc := range []struct {
		prefix string
		origin uint32
		want   plugin.RPKIValidity
	}{
		{"192.0.2.0/24", 64496, plugin.RPKINotFound},
		{"203.0.113.0/24", 64496, plugin.RPKIValid},
		{"203.0.113.0/24", 64511, plugin.RPKIInvalid},
		{"203.0.113.0/25", 64496, plugin.RPKIInvalid},
	} {
		a := waitAnswer(t, c, tc.prefix, tc.origin)
		if a.State != tc.want || a.Source != "ripestat" || a.Updated.Before(before) {
			t.Fatalf("%s AS%d = %+v, want %q from ripestat", tc.prefix, tc.origin, a, tc.want)
		}
	}
	if st := c.Status(); !st.Up || st.VRPs != 4 || st.Error != "" {
		t.Fatalf("status = %+v", st)
	}
}

// Lookups wait on rate_per_minute: with 1 per minute, only the first of
// three queued misses is sent, and a cached answer sends nothing.
func TestRateLimit(t *testing.T) {
	srv, calls := fixtureServer(t)
	c := newClient(t, "rate_per_minute: 1\n", srv.URL)
	c.Answer(netip.MustParsePrefix("192.0.2.0/24"), 64496)
	waitAnswer(t, c, "192.0.2.0/24", 64496)
	c.Answer(netip.MustParsePrefix("203.0.113.0/24"), 64496)
	c.Answer(netip.MustParsePrefix("203.0.113.0/24"), 64511)
	time.Sleep(300 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Fatalf("calls = %d, want 1 within the rate", n)
	}
}

// An answer older than ttl is not shown and is looked up again.
func TestTTL(t *testing.T) {
	srv, calls := fixtureServer(t)
	c := newClient(t, "rate_per_minute: 60\nttl: 1m\n", srv.URL)
	waitAnswer(t, c, "203.0.113.0/24", 64496)
	k := key{prefix: netip.MustParsePrefix("203.0.113.0/24"), origin: 64496}
	c.mu.Lock()
	e := c.cache[k]
	e.at = time.Now().Add(-2 * time.Minute)
	c.cache[k] = e
	c.mu.Unlock()
	if a := c.Answer(k.prefix, k.origin); a.State != plugin.RPKIUnknown {
		t.Fatalf("expired answer shown: %+v", a)
	}
	waitAnswer(t, c, "203.0.113.0/24", 64496)
	if n := calls.Load(); n != 2 {
		t.Fatalf("calls = %d, want a second lookup after ttl", n)
	}
}

// A failed lookup reports the error and caches nothing.
func TestLookupError(t *testing.T) {
	srv, _ := fixtureServer(t)
	c := newClient(t, "rate_per_minute: 60\n", srv.URL)
	c.Answer(netip.MustParsePrefix("198.51.100.0/24"), 64499)
	deadline := time.Now().Add(5 * time.Second)
	for c.Status().Error == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := c.Status(); st.Up || !strings.Contains(st.Error, "500") || st.VRPs != 0 {
		t.Fatalf("status = %+v, want the error and no cached answer", st)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, y := range []string{"rate_per_minute: 61\n", "rate_per_minute: -1\n", "ttl: 1s\n", "ttl: 48h\n"} {
		cfg, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg, plugin.Env{}); err == nil {
			t.Errorf("New accepted %q", y)
		}
	}
	p, err := New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if c := p.(*Client); c.cfg.RatePerMinute != DefaultRatePerMinute || c.cfg.TTL != DefaultTTL || c.base != "https://stat.ripe.net" {
		t.Fatalf("defaults = %+v %s", c.cfg, c.base)
	}
}
