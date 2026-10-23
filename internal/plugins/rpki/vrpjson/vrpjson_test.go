package vrpjson

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// dated returns a recorded document with its generation time set to at,
// in the document's own field and format.
func dated(t *testing.T, name string, at time.Time) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	s = regexp.MustCompile(`"generated": \d+`).ReplaceAllString(s, `"generated": `+strconv.FormatInt(at.Unix(), 10))
	s = regexp.MustCompile(`"buildtime": "[^"]*"`).ReplaceAllString(s, `"buildtime": "`+at.UTC().Format(time.RFC3339)+`"`)
	return s
}

func newClient(t *testing.T, url string) *Client {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML("url: " + url + "\n")
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, plugin.Env{Name: "routinator-json"})
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Client)
}

// #200: the source reads the VRP JSON recorded from Routinator's /json
// (string ASNs, metadata.generated) and from rpki-client -j (numeric ASNs,
// metadata.buildtime), and dates the data by the document, not the fetch.
func TestRecordedDocuments(t *testing.T) {
	for _, name := range []string{"routinator.json", "rpki-client.json"} {
		t.Run(name, func(t *testing.T) {
			gen := time.Now().Add(-time.Minute).Truncate(time.Second)
			body := dated(t, name, gen)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c := newClient(t, srv.URL+"/json")
			c.poll(t.Context())
			st := c.Status()
			if !st.Up || st.Stale || st.VRPs != 3 || !st.Updated.Equal(gen) || st.Source != "routinator-json" {
				t.Fatalf("status = %+v, want up with 3 VRPs dated %s", st, gen)
			}
			for _, tc := range []struct {
				prefix string
				origin uint32
				want   plugin.RPKIValidity
			}{
				{"192.0.2.0/24", 64496, plugin.RPKIValid},
				{"192.0.2.0/24", 64511, plugin.RPKIInvalid},
				{"203.0.113.128/25", 64497, plugin.RPKIValid},
				{"203.0.113.0/26", 64497, plugin.RPKIInvalid},
				{"198.51.100.0/24", 64499, plugin.RPKINotFound},
				{"2001:db8:1::/48", 64498, plugin.RPKIValid},
			} {
				if got := c.Validate(netip.MustParsePrefix(tc.prefix), tc.origin); got != tc.want {
					t.Errorf("%s AS%d = %q, want %q", tc.prefix, tc.origin, got, tc.want)
				}
			}
		})
	}
}

// A cache that keeps serving an old document is stale even though every
// fetch succeeds: lookups are unknown (fail open).
func TestOldDocumentIsStale(t *testing.T) {
	body := dated(t, "routinator.json", time.Now().Add(-3*time.Hour))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	c.poll(t.Context())
	if st := c.Status(); !st.Up || !st.Stale {
		t.Fatalf("status = %+v, want up and stale", st)
	}
	if got := c.Validate(netip.MustParsePrefix("192.0.2.0/24"), 64511); got != plugin.RPKIUnknown {
		t.Fatalf("stale lookup = %q, want unknown", got)
	}
}

// A failed fetch or a broken document keeps the last good cache serving
// until staleness and reports the error.
func TestFailedFetchKeepsCache(t *testing.T) {
	good := dated(t, "rpki-client.json", time.Now())
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch calls.Add(1) {
		case 1:
			_, _ = w.Write([]byte(good))
		case 2:
			http.Error(w, "down", http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte(`{"roas": [{"asn": 64496, "prefix": "192.0.2.0/24", "maxLength": 16}]}`))
		}
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	c.poll(t.Context())
	for _, want := range []string{"503", "maxLength 16 does not fit"} {
		c.poll(t.Context())
		st := c.Status()
		if st.Up || !strings.Contains(st.Error, want) || st.VRPs != 3 || st.Stale {
			t.Fatalf("status = %+v, want down with %q and the last cache", st, want)
		}
		if got := c.Validate(netip.MustParsePrefix("192.0.2.0/24"), 64511); got != plugin.RPKIInvalid {
			t.Fatalf("lookup after a failed fetch = %q, want the cached invalid", got)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"refresh: 1m\n", "must be an http or https URL"},
		{"url: rsync://192.0.2.1/json\n", "must be an http or https URL"},
		{"url: http://user:secret@192.0.2.1:8323/json\n", "credentials"},
		{"url: http://192.0.2.1:8323/json\nrefresh: 10m\nstaleness: 1m\n", "staleness"},
		// The data time is the publisher's, so staleness equal to refresh
		// reads a Routinator document (10m cycle) as stale on every fetch.
		{"url: http://192.0.2.1:8323/json\nrefresh: 5m\nstaleness: 5m\n", "at least 1h5m0s"},
		{"url: http://192.0.2.1:8323/json\nrefresh: 5m\nstaleness: 1h\n", "at least 1h5m0s"},
	} {
		cfg, err := plugin.ConfigFromYAML(tc.yaml)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(cfg, plugin.Env{}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
}

// The default staleness covers an hourly publisher on top of refresh, and
// the floor is refresh plus that cycle.
func TestStalenessCoversPublisherCycle(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want time.Duration
	}{
		{"", 2 * time.Hour},
		{"refresh: 2h\n", 3 * time.Hour},
		{"refresh: 5m\nstaleness: 1h5m\n", time.Hour + 5*time.Minute},
	} {
		cfg, err := plugin.ConfigFromYAML("url: http://192.0.2.1:8323/json\n" + tc.yaml)
		if err != nil {
			t.Fatal(err)
		}
		p, err := New(cfg, plugin.Env{})
		if err != nil {
			t.Fatalf("%q: %v", tc.yaml, err)
		}
		if got := p.(*Client).cfg.Staleness; got != tc.want {
			t.Errorf("%q: staleness = %s, want %s", tc.yaml, got, tc.want)
		}
	}
}

// A fetched document that will be stale before the next poll is logged
// once per episode, so an operator sees a publisher slower than staleness
// allows instead of only rpki.stale/rpki.fresh flaps.
func TestLateDocumentWarnsOnce(t *testing.T) {
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	cfg, err := plugin.ConfigFromYAML("url: " + srv.URL + "\n")
	if err != nil {
		t.Fatal(err)
	}
	var logs strings.Builder
	p, err := New(cfg, plugin.Env{Name: "rpki-client", Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	warnings := func() int { return strings.Count(logs.String(), "goes stale before the next poll") }
	for _, step := range []struct {
		age  time.Duration
		want int
	}{
		{time.Hour + 50*time.Minute, 0}, // 1h50m + 5m refresh is inside 2h
		{time.Hour + 58*time.Minute, 1},
		{time.Hour + 59*time.Minute, 1},
		{time.Minute, 1},
		{time.Hour + 58*time.Minute, 2},
	} {
		body.Store(dated(t, "rpki-client.json", time.Now().Add(-step.age)))
		c.poll(t.Context())
		if st := c.Status(); !st.Up || st.Stale {
			t.Fatalf("age %s: status = %+v, want up and fresh", step.age, st)
		}
		if got := warnings(); got != step.want {
			t.Fatalf("age %s: %d warnings, want %d\n%s", step.age, got, step.want, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "source=rpki-client") || !strings.Contains(logs.String(), "staleness=2h0m0s") {
		t.Fatalf("warning lacks the source or staleness: %s", logs.String())
	}
}

// Start fetches at once and Stop ends the poll loop.
func TestStartStop(t *testing.T) {
	body := dated(t, "routinator.json", time.Now())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !c.Status().Up && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !c.Status().Up {
		t.Fatal("never fetched")
	}
	if err := c.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}
