package httpfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newFeed(t *testing.T, yaml string, env map[string]string) (plugin.ThreatFeed, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	return New(c, plugin.Env{Getenv: func(k string) string { return env[k] }})
}

func prefixes(es []plugin.ThreatEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Prefix.String()+"|"+e.Comment)
	}
	return out
}

func TestParseCIDR(t *testing.T) {
	got, err := ParseCIDR([]byte("; Spamhaus-style header\n\n198.51.100.0/24 ; SBL1\r\n192.0.2.7\n  2001:db8::/48 # lab\n198.51.100.0/24\n203.0.113.0/24 ; \x07bellé\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.0/24|SBL1", "192.0.2.7/32|", "2001:db8::/48|lab", "203.0.113.0/24|bell"}
	if strings.Join(prefixes(got), " ") != strings.Join(want, " ") {
		t.Fatalf("got %v want %v", prefixes(got), want)
	}
	for _, bad := range []struct{ body, want string }{
		{"198.51.100.1/24\n", "line 1: 198.51.100.1/24 has host bits set"},
		{"192.0.2.0/24\n0.0.0.0/0\n", "line 2: 0.0.0.0/0 would match every"},
		{"<html>\n", `line 1: "<html>" is not a CIDR`},
		{"::ffff:192.0.2.1\n", "IPv4-mapped"},
		{"fe80::1%eth0\n", "is not a CIDR"},
	} {
		if _, err := ParseCIDR([]byte(bad.body)); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%q: %v, want %q", bad.body, err, bad.want)
		}
	}
	var big strings.Builder
	for i := range MaxEntries + 1 {
		big.WriteString(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String() + "\n")
	}
	if _, err := ParseCIDR([]byte(big.String())); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("too many entries: %v", err)
	}
}

func TestParseJSON(t *testing.T) {
	got, err := ParseJSON([]byte(`{"generated":"x","entries":[{"prefix":"198.51.100.0/24","comment":"c2","score":9},{"prefix":" 192.0.2.9 "}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(prefixes(got), " ") != "198.51.100.0/24|c2 192.0.2.9/32|" {
		t.Fatalf("got %v", prefixes(got))
	}
	if got, err := ParseJSON([]byte(`{"entries":[]}`)); err != nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	for _, bad := range []struct{ body, want string }{
		{`[]`, "json"},
		{`{"items":[]}`, `no "entries"`},
		{`{"entries":[{"prefix":"198.51.100.1/24"}]}`, "entries[0]: 198.51.100.1/24 has host bits set"},
	} {
		if _, err := ParseJSON([]byte(bad.body)); err == nil || !strings.Contains(err.Error(), bad.want) {
			t.Errorf("%s: %v, want %q", bad.body, err, bad.want)
		}
	}
}

// Fetch sends the bearer token from the environment, parses the format,
// and fails on a non-2xx answer or an oversized body.
func TestFetch(t *testing.T) {
	var auth string
	status, body := http.StatusOK, `{"entries":[{"prefix":"198.51.100.0/24"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	f, err := newFeed(t, "url: "+srv.URL+"/list.json\nformat: JSON\ntoken_env: LAB_FEED_TOKEN\n", map[string]string{"LAB_FEED_TOKEN": "lab-only-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Stop(context.Background())
	got, err := f.Fetch(context.Background())
	if err != nil || len(got) != 1 || got[0].Prefix != netip.MustParsePrefix("198.51.100.0/24") || auth != "Bearer lab-only-token" {
		t.Fatalf("fetch: %v %v auth=%q", got, err, auth)
	}
	status = http.StatusForbidden
	if _, err := f.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403: %v", err)
	}
	status, body = http.StatusOK, strings.Repeat("#", MaxBody+1)
	if _, err := f.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized: %v", err)
	}

	// cidr is the default format; no token_env sends no Authorization.
	body = "192.0.2.0/24\n"
	f, err = newFeed(t, "url: "+srv.URL+"/drop.txt\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.Fetch(context.Background()); err != nil || len(got) != 1 || auth != "" {
		t.Fatalf("cidr: %v %v auth=%q", got, err, auth)
	}
}

func TestNewRefuses(t *testing.T) {
	for _, c := range []struct{ yaml, want string }{
		{"url: ftp://feeds.example.net/x\n", "url must be an absolute http(s) URL"},
		{"url: https://user:pw@feeds.example.net/x\n", "without credentials"},
		{"url: https://feeds.example.net/x?key=1\n", "without credentials or query"},
		{"url: https://feeds.example.net/x\nformat: csv\n", `format "csv" is invalid`},
		{"url: https://feeds.example.net/x\ntoken_env: LAB_FEED_TOKEN\n", "LAB_FEED_TOKEN is not set"},
		{"url: https://feeds.example.net/x\ntoken: secret\n", "token"},
	} {
		if _, err := newFeed(t, c.yaml, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.yaml, err, c.want)
		}
	}
	if !plugin.ThreatFeeds.Has(TypeName) {
		t.Fatal("http is not registered")
	}
}
