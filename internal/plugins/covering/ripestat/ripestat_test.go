package ripestat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func cfgOf(t *testing.T, y string) plugin.Config {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(y), &n); err != nil {
		t.Fatal(err)
	}
	if len(n.Content) == 0 {
		return plugin.Config{}
	}
	return plugin.NewConfig(n.Content[0])
}

func newClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	p, err := New(cfgOf(t, ""), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	c.base = srv.URL
	c.limit = rate.NewLimiter(rate.Inf, 1)
	return c
}

func TestCoveringReadsTheAnnouncedPrefix(t *testing.T) {
	var gotPath, gotResource string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotResource = r.URL.Path, r.URL.Query().Get("resource")
		_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["64496"],"prefix":"198.51.100.0/23"}}`))
	}))
	defer srv.Close()
	got, err := newClient(t, srv).Covering(context.Background(), netip.MustParseAddr("198.51.100.0"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != netip.MustParsePrefix("198.51.100.0/23") || got.Origin != 64496 {
		t.Fatalf("answer = %+v", got)
	}
	if gotPath != "/data/network-info/data.json" || gotResource != "198.51.100.0" {
		t.Fatalf("asked %s resource %q", gotPath, gotResource)
	}
}

func TestSeveralOriginsNameNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"asns":["64496","64497"],"prefix":"192.0.2.0/24"}}`))
	}))
	defer srv.Close()
	got, err := newClient(t, srv).Covering(context.Background(), netip.MustParseAddr("192.0.2.0"))
	if err != nil || got.Prefix != netip.MustParsePrefix("192.0.2.0/24") || got.Origin != 0 {
		t.Fatalf("answer = %+v, %v", got, err)
	}
}

func TestCoveringRefusesBadAnswers(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"http error":  {http.StatusTooManyRequests, `{}`, "429"},
		"no prefix":   {200, `{"data":{"asns":[]}}`, "no announced prefix"},
		"bad prefix":  {200, `{"data":{"prefix":"not-a-prefix"}}`, "prefix"},
		"not json":    {200, `<html>`, "ripestat"},
		"host bits":   {200, `{"data":{"prefix":"2001:db8:1::5/48"}}`, ""},
		"empty reply": {200, ``, "ripestat"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		got, err := newClient(t, srv).Covering(context.Background(), netip.MustParseAddr("2001:db8:1::"))
		srv.Close()
		if tc.want == "" {
			if err != nil || got.Prefix != netip.MustParsePrefix("2001:db8:1::/48") || got.Origin != 0 {
				t.Errorf("%s: got %s, %v; want the masked prefix", name, got.Prefix, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

func TestCoveringWaitsForTheRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write([]byte(`{"data":{"prefix":"192.0.2.0/24"}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	c.limit = rate.NewLimiter(rate.Every(time.Hour), 1)
	if _, err := c.Covering(context.Background(), netip.MustParseAddr("192.0.2.0")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Covering(ctx, netip.MustParseAddr("192.0.2.0")); err == nil {
		t.Fatal("a second lookup inside the limit was sent")
	}
	if calls != 1 {
		t.Fatalf("server saw %d requests, want 1", calls)
	}
}

func TestConfigBounds(t *testing.T) {
	for _, y := range []string{"rate_per_minute: 61", "rate_per_minute: -1", "unknown_key: 1"} {
		if _, err := New(cfgOf(t, y), plugin.Env{}); err == nil {
			t.Errorf("%q accepted", y)
		}
	}
	if _, err := New(cfgOf(t, "rate_per_minute: 60"), plugin.Env{}); err != nil {
		t.Fatal(err)
	}
	if !plugin.Coverings.Has(TypeName) {
		t.Fatal("ripestat is not registered as a covering plugin")
	}
}
