package ringlg

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixture is a synthetic answer in the shape of RING's /api/prefix, with
// documentation prefixes and documentation ASNs.
const fixture = `{
  "query_id": "q1",
  "prefix": "198.51.100.0/24",
  "routes": {
    "198.51.100.0/24": [
      {"peer": "peer-one (AS64496)", "aspath": [["64496", "Example One"], ["64500", "Example Two"]],
       "ovs": "Valid", "last_update_at": "2026-01-01 00:00:00 UTC", "communities": [["64496:1", "x"]]},
      {"peer": "peer-two (AS64497)", "aspath": [["64497", "Example Three"], ["64500", "Example Two"]],
       "ovs": "NotFound", "last_update_at": "2026-01-02 00:00:00 UTC"}
    ]
  },
  "warnings": ["Not showing more specific routes"]
}`

type stub struct {
	*httptest.Server
	calls atomic.Int32
	mu    sync.Mutex
	last  *http.Request
	h     http.HandlerFunc
}

func newStub(t *testing.T, h http.HandlerFunc) *stub {
	t.Helper()
	s := &stub{h: h}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls.Add(1)
		s.mu.Lock()
		s.last = r
		s.mu.Unlock()
		s.h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func ok(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, fixture) }

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func client(t *testing.T, s *stub, cfg Config) (*Client, *clock) {
	t.Helper()
	cfg.Enabled = true
	c := New(cfg, "9.9.9")
	c.base = s.URL + "/api/prefix"
	clk := &clock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	c.now = clk.now
	return c, clk
}

var doc = netip.MustParsePrefix("198.51.100.0/24")

func TestOffMakesNoRequest(t *testing.T) {
	s := newStub(t, ok)
	c := New(Config{}, "9.9.9")
	c.base = s.URL
	if r := c.Lookup(context.Background(), doc); r.State != StateOff {
		t.Fatalf("state = %q, want off", r.State)
	}
	var nilClient *Client
	if r := nilClient.Lookup(context.Background(), doc); r.State != StateOff || nilClient.Enabled() {
		t.Fatalf("nil client = %+v", r)
	}
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("%d requests with ring_lg off", n)
	}
}

func TestDefaultEndpointIsPublicRING(t *testing.T) {
	if got := New(Config{Enabled: true}, "9.9.9").base; got != "https://lg.ring.nlnog.net/api/prefix" {
		t.Fatalf("endpoint = %q", got)
	}
}

func TestLookupSummarizesAndSendsIdentifyingRequest(t *testing.T) {
	s := newStub(t, ok)
	c, _ := client(t, s, Config{})
	r := c.Lookup(context.Background(), netip.MustParsePrefix("198.51.100.77/24"))
	if r.State != StateOK || r.Prefix != "198.51.100.0/24" || r.Cached || r.FetchedAt.IsZero() {
		t.Fatalf("result = %+v", r)
	}
	if len(r.Routes) != 2 {
		t.Fatalf("routes = %+v", r.Routes)
	}
	got := r.Routes[0]
	if got.Peer != "peer-one (AS64496)" || strings.Join(got.ASPath, " ") != "64496 64500" || got.Origin != "64500" || got.RPKI != "Valid" || got.LastUpdate != "2026-01-01 00:00:00 UTC" {
		t.Errorf("route[0] = %+v", got)
	}
	if r.Routes[1].RPKI != "NotFound" || len(r.Warnings) != 1 {
		t.Errorf("route[1] = %+v warnings %v", r.Routes[1], r.Warnings)
	}
	req := s.last
	if ua := req.Header.Get("User-Agent"); ua != "Packeteer/9.9.9 (+https://github.com/GrandArcher/Packeteer)" {
		t.Errorf("User-Agent = %q", ua)
	}
	if q := req.URL.Query(); q.Get("q") != "198.51.100.0/24" || q.Get("match") != "exact" || q.Get("all") != "" || len(q["peer"]) != 0 {
		t.Errorf("query = %v", q)
	}
	if req.Method != http.MethodGet || req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
		t.Errorf("method %s, credentials sent: %v", req.Method, req.Header)
	}
}

func TestCacheServesRepeatsUntilTTL(t *testing.T) {
	s := newStub(t, ok)
	c, clk := client(t, s, Config{CacheTTL: 5 * time.Minute, RequestsPerMinute: 30})
	first := c.Lookup(context.Background(), doc)
	clk.t = clk.t.Add(4 * time.Minute)
	again := c.Lookup(context.Background(), doc)
	if s.calls.Load() != 1 {
		t.Fatalf("%d calls inside the TTL, want 1", s.calls.Load())
	}
	if !again.Cached || first.Cached || !again.FetchedAt.Equal(first.FetchedAt) || len(again.Routes) != 2 {
		t.Fatalf("first %+v again %+v", first, again)
	}
	clk.t = clk.t.Add(2 * time.Minute)
	if r := c.Lookup(context.Background(), doc); r.Cached || s.calls.Load() != 2 {
		t.Fatalf("after the TTL: cached %v, calls %d", r.Cached, s.calls.Load())
	}
}

func TestConcurrentViewsOfOneColdPrefixCallOnce(t *testing.T) {
	s := newStub(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		ok(w, r)
	})
	c, _ := client(t, s, Config{RequestsPerMinute: 30})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := c.Lookup(context.Background(), doc); r.State != StateOK {
				t.Errorf("state = %q", r.State)
			}
		}()
	}
	wg.Wait()
	if n := s.calls.Load(); n != 1 {
		t.Fatalf("%d calls, want 1", n)
	}
}

func TestRateCapIsGlobalAndSlides(t *testing.T) {
	s := newStub(t, ok)
	c, clk := client(t, s, Config{RequestsPerMinute: 2})
	for i, p := range []string{"192.0.2.0/24", "198.51.100.0/24"} {
		if r := c.Lookup(context.Background(), netip.MustParsePrefix(p)); r.State != StateOK {
			t.Fatalf("call %d: %+v", i, r)
		}
	}
	third := netip.MustParsePrefix("203.0.113.0/24")
	r := c.Lookup(context.Background(), third)
	if r.State != StateUnavailable || !strings.Contains(r.Message, "at most 2 requests a minute") || s.calls.Load() != 2 {
		t.Fatalf("over the cap: %+v, calls %d", r, s.calls.Load())
	}
	// A prefix already cached is still served while the cap is spent.
	if r := c.Lookup(context.Background(), doc); !r.Cached {
		t.Fatalf("cached prefix during the cap: %+v", r)
	}
	clk.t = clk.t.Add(61 * time.Second)
	if r := c.Lookup(context.Background(), third); r.State != StateOK || s.calls.Load() != 3 {
		t.Fatalf("after a minute: %+v, calls %d", r, s.calls.Load())
	}
}

func TestFailuresAreUnavailableAndBackOff(t *testing.T) {
	cases := []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"5xx", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusServiceUnavailable) }, "HTTP 503"},
		{"429", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "slow down", http.StatusTooManyRequests) }, "429"},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.net/", http.StatusFound)
		}, "HTTP 302"},
		{"not json", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "<html>") }, "unreadable"},
		{"timeout", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}, "timed out"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub(t, tc.h)
			c, clk := client(t, s, Config{Timeout: 100 * time.Millisecond, RequestsPerMinute: 30})
			r := c.Lookup(context.Background(), doc)
			if r.State != StateUnavailable || !strings.Contains(r.Message, tc.want) || !strings.Contains(r.Message, "NLNOG RING services may be unavailable.") || len(r.Routes) != 0 {
				t.Fatalf("result = %+v", r)
			}
			if again := c.Lookup(context.Background(), doc); again.State != StateUnavailable || s.calls.Load() != 1 {
				t.Fatalf("inside the back-off: %+v, calls %d", again, s.calls.Load())
			}
			clk.t = clk.t.Add(failureTTL + time.Second)
			c.Lookup(context.Background(), doc)
			if s.calls.Load() != 2 {
				t.Fatalf("calls after the back-off = %d, want 2", s.calls.Load())
			}
		})
	}
}

func TestPrivatePrefixesAreNeverSent(t *testing.T) {
	s := newStub(t, ok)
	c, _ := client(t, s, Config{RequestsPerMinute: 30})
	for _, p := range []string{"10.1.0.0/16", "192.168.1.0/24", "172.16.0.0/12", "fd00::/8", "127.0.0.0/8", "169.254.0.0/16", "fe80::/10"} {
		r := c.Lookup(context.Background(), netip.MustParsePrefix(p))
		if r.State != StateUnavailable || !strings.Contains(r.Message, "never sent") {
			t.Errorf("%s: %+v", p, r)
		}
	}
	if n := s.calls.Load(); n != 0 {
		t.Fatalf("%d requests for private prefixes", n)
	}
	if r := c.Lookup(context.Background(), netip.MustParsePrefix("2001:db8::/32")); r.State != StateOK {
		t.Fatalf("documentation prefix: %+v", r)
	}
}

func TestRowsAndTextAreBounded(t *testing.T) {
	long := strings.Repeat("x", 500)
	s := newStub(t, func(w http.ResponseWriter, _ *http.Request) {
		var rows []string
		for range MaxRoutes + 5 {
			rows = append(rows, fmt.Sprintf(`{"peer": %q, "aspath": [["64496"]]}`, long))
		}
		fmt.Fprintf(w, `{"routes": {"198.51.100.0/24": [%s]}}`, strings.Join(rows, ","))
	})
	c, _ := client(t, s, Config{})
	r := c.Lookup(context.Background(), doc)
	if len(r.Routes) != MaxRoutes || !r.Truncated || len(r.Routes[0].Peer) != 120 {
		t.Fatalf("rows %d truncated %v peer %d", len(r.Routes), r.Truncated, len(r.Routes[0].Peer))
	}
}

func TestCacheIsBounded(t *testing.T) {
	s := newStub(t, ok)
	c, _ := client(t, s, Config{})
	for i := range maxCache + 10 {
		c.store(fmt.Sprintf("k%d", i), Result{State: StateOK}, c.now().Add(time.Hour))
	}
	if len(c.cache) != maxCache || len(c.order) != maxCache {
		t.Fatalf("cache %d order %d, want %d", len(c.cache), len(c.order), maxCache)
	}
	if _, ok := c.cache["k0"]; ok {
		t.Fatal("the oldest entry was kept")
	}
}

func TestValidate(t *testing.T) {
	var got []string
	add := func(f string, a ...any) { got = append(got, fmt.Sprintf(f, a...)) }
	Config{Enabled: true}.Validate(add)
	Config{RequestsPerMinute: 6, CacheTTL: 10 * time.Minute, Timeout: 5 * time.Second}.Validate(add)
	if len(got) != 0 {
		t.Fatalf("valid blocks reported %v", got)
	}
	for _, c := range []struct {
		cfg  Config
		want string
	}{
		{Config{RequestsPerMinute: -1}, "ring_lg.requests_per_minute"},
		{Config{RequestsPerMinute: MaxRequestsPerMinute + 1}, "ring_lg.requests_per_minute"},
		{Config{CacheTTL: 30 * time.Second}, "ring_lg.cache_ttl"},
		{Config{CacheTTL: 48 * time.Hour}, "ring_lg.cache_ttl"},
		{Config{Timeout: time.Minute}, "ring_lg.timeout"},
	} {
		got = nil
		c.cfg.Validate(add)
		if len(got) != 1 || !strings.Contains(got[0], c.want) {
			t.Errorf("%+v: %v", c.cfg, got)
		}
	}
	d := Config{}.WithDefaults()
	if d.RequestsPerMinute != 6 || d.CacheTTL != 10*time.Minute || d.Timeout != 10*time.Second || d.Enabled {
		t.Errorf("defaults = %+v", d)
	}
}
