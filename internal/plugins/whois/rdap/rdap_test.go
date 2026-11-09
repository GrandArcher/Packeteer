package rdap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string) (plugin.Whois, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return New(c, plugin.Env{})
}

func TestParseQuery(t *testing.T) {
	for q, want := range map[string]string{
		"AS64496":         "autnum/64496",
		"as64511":         "autnum/64511",
		"64500":           "autnum/64500",
		"192.0.2.0/24":    "ip/192.0.2.0/24",
		"198.51.100.7/24": "ip/198.51.100.0/24",
		"203.0.113.9":     "ip/203.0.113.9",
		"2001:db8::/32":   "ip/2001:db8::/32",
	} {
		got, _, err := ParseQuery(q)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", q, got, err, want)
		}
	}
	for _, q := range []string{"", "AS", "example.com", "192.0.2.0/33", "AS99999999999", "../../etc"} {
		if _, _, err := ParseQuery(q); err == nil {
			t.Errorf("%q: expected error", q)
		}
	}
}

func TestLookupFakeServer(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/rdap+json")
		switch r.URL.Path {
		case "/rdap/ip/192.0.2.0/24":
			_, _ = w.Write([]byte(`{"objectClassName":"ip network","handle":"NET-192-0-2-0-1","name":"TEST-NET-1","country":"ZZ","startAddress":"192.0.2.0","endAddress":"192.0.2.255","remarks":[{"title":"Documentation","description":["RFC 5737"]}]}`))
		case "/rdap/autnum/64496":
			_, _ = w.Write([]byte(`{"objectClassName":"autnum","handle":"AS64496","name":"DOC-ASN","startAutnum":64496,"endAutnum":64511}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errorCode":404,"title":"Not Found"}`))
		}
	}))
	defer srv.Close()
	w, err := build(t, "base_url: "+srv.URL+"/rdap/\n")
	if err != nil {
		t.Fatal(err)
	}
	r, err := w.Lookup(context.Background(), "192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "ip" || r.Name != "TEST-NET-1" || r.Range != "192.0.2.0 - 192.0.2.255" || len(r.Remarks) != 1 || !strings.HasPrefix(r.Remarks[0], "Documentation") {
		t.Fatalf("ip result: %+v", r)
	}
	r, err = w.Lookup(context.Background(), "AS64496")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "asn" || r.Handle != "AS64496" || r.Range != "AS64496 - AS64511" {
		t.Fatalf("asn result: %+v", r)
	}
	if _, err := w.Lookup(context.Background(), "198.51.100.0/24"); err == nil || !strings.Contains(err.Error(), "Not Found") {
		t.Fatalf("404: %v", err)
	}
	if _, err := w.Lookup(context.Background(), "not a query"); err == nil {
		t.Fatal("bad query reached the server")
	}
	if len(paths) != 3 {
		t.Fatalf("paths: %v", paths)
	}
}

func TestLookupSizeCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"` + strings.Repeat("x", 4096) + `"}`))
	}))
	defer srv.Close()
	w, err := build(t, "base_url: "+srv.URL+"\nmax_bytes: 1024\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Lookup(context.Background(), "AS64496"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("want size error, got %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	for _, y := range []string{
		"base_url: ftp://example.com\n",
		"base_url: https://user:pw@rdap.example\n",
		"base_url: https://rdap.example/?q=1\n",
		"timeout: -1s\n",
		"max_bytes: 10\n",
		"bogus: 1\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%q: expected error", y)
		}
	}
	if _, err := build(t, "{}\n"); err != nil {
		t.Errorf("defaults: %v", err)
	}
}
