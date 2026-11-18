package httpjson

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
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
	return plugin.NewConfig(n.Content[0])
}

func newClient(t *testing.T, url string) *Client {
	t.Helper()
	p, err := New(cfgOf(t, "url: "+url+"\n"), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	c := p.(*Client)
	c.limit = rate.NewLimiter(rate.Inf, 1)
	return c
}

var pfx = netip.MustParsePrefix("198.51.100.0/24")

// #671: a lookup is one GET with the prefix as a query parameter, and the
// origins in the answer come back as they are.
func TestOriginsAsksForTheExactPrefix(t *testing.T) {
	var gotPath, gotPrefix, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotPrefix = r.Method, r.URL.Path, r.URL.Query().Get("prefix")
		_, _ = w.Write([]byte(`{"prefix":"198.51.100.0/24","origins":[64500,64510]}`))
	}))
	defer srv.Close()
	got, err := newClient(t, srv.URL+"/ris").Origins(context.Background(), pfx)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []uint32{64500, 64510}) {
		t.Fatalf("origins = %v", got)
	}
	if gotMethod != http.MethodGet || gotPath != "/ris" || gotPrefix != "198.51.100.0/24" {
		t.Fatalf("asked %s %s prefix=%q", gotMethod, gotPath, gotPrefix)
	}
}

// #671: a collector that saw nothing is an empty answer, not an error.
func TestEmptyAnswer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefix":"198.51.100.0/24","origins":[]}`))
	}))
	defer srv.Close()
	got, err := newClient(t, srv.URL).Origins(context.Background(), pfx)
	if err != nil || len(got) != 0 {
		t.Fatalf("origins = %v, %v", got, err)
	}
}

// Anything that is not a clean answer for exactly the prefix asked is an
// error, so it is never read as agreement or as "seen nothing".
func TestBadAnswersAreErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"server error":          {http.StatusInternalServerError, ``, "500"},
		"not json":              {http.StatusOK, `<html>`, "collector:"},
		"covering prefix":       {http.StatusOK, `{"prefix":"198.51.100.0/22","origins":[64500]}`, "not 198.51.100.0/24"},
		"missing prefix":        {http.StatusOK, `{"origins":[64500]}`, "not 198.51.100.0/24"},
		"asn out of range":      {http.StatusOK, `{"prefix":"198.51.100.0/24","origins":[99999999999]}`, "collector:"},
		"more than the maximum": {http.StatusOK, `{"prefix":"198.51.100.0/24","origins":[` + strings.Repeat("64500,", maxOrigins) + `64500]}`, "more than"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			got, err := newClient(t, srv.URL).Origins(context.Background(), pfx)
			if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("origins = %v, err = %v, want an error containing %q", got, err, tc.want)
			}
		})
	}
}

// A collector that is down is an error.
func TestDownIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if got, err := newClient(t, url).Origins(context.Background(), pfx); err == nil || got != nil {
		t.Fatalf("origins = %v, err = %v", got, err)
	}
}

func TestConfigValidation(t *testing.T) {
	for y, want := range map[string]string{
		"{}":                                `url "" must be an http or https URL`,
		"url: ftp://192.0.2.50/x":           "must be an http or https URL",
		"url: http://user:pw@192.0.2.50/x":  "must not carry credentials",
		"url: http://192.0.2.50/x?prefix=1": "must not carry a query",
		"{url: \"http://192.0.2.50/x\", rate_per_minute: 601}": "rate_per_minute 601 must be between 1 and 600",
		"{url: \"http://192.0.2.50/x\", rate_per_minute: -1}":  "rate_per_minute -1 must be between 1 and 600",
		"{url: \"http://192.0.2.50/x\", bogus: 1}":             "bogus",
	} {
		if _, err := New(cfgOf(t, y), plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", y, err, want)
		}
	}
	p, err := New(cfgOf(t, "url: http://192.0.2.50/x\n"), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.(*Client).limit.Limit(); got != rate.Limit(float64(DefaultRatePerMinute)/60) {
		t.Fatalf("default rate = %v", got)
	}
}

// The rate limit holds lookups back and a cancelled wait is an error.
func TestRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"prefix":"198.51.100.0/24","origins":[64500]}`))
	}))
	defer srv.Close()
	c := newClient(t, srv.URL)
	c.limit = rate.NewLimiter(rate.Every(time.Hour), 1)
	if _, err := c.Origins(context.Background(), pfx); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got, err := c.Origins(ctx, pfx); err == nil || got != nil {
		t.Fatalf("second lookup inside the limit: %v, %v", got, err)
	}
}

func TestRegistered(t *testing.T) {
	if !slices.Contains(plugin.OriginCollectors.Types(), TypeName) {
		t.Fatalf("types = %v", plugin.OriginCollectors.Types())
	}
}
