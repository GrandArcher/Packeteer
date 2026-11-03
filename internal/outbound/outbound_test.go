package outbound

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestExpandOnlyPrefixedNames(t *testing.T) {
	getenv := env(map[string]string{
		"PACKETEER_WEBHOOK_TOKEN":  "hook-token",
		"PACKETEER_ADMIN_PASSWORD": "admin-secret",
		"HOOK_TOKEN":               "other-secret",
	})
	got, err := Expand("https://hooks.example.net/x?t=${PACKETEER_WEBHOOK_TOKEN}&u=$PACKETEER_WEBHOOK_TOKEN", "PACKETEER_WEBHOOK_", getenv)
	if err != nil || got != "https://hooks.example.net/x?t=hook-token&u=hook-token" {
		t.Fatalf("allowed name: %q %v", got, err)
	}
	if got, err := Expand("no variables, a $ sign", "PACKETEER_WEBHOOK_", getenv); err != nil || got != "no variables, a $ sign" {
		t.Fatalf("plain text: %q %v", got, err)
	}
	for _, s := range []string{
		"https://hooks.example.net/?x=${PACKETEER_ADMIN_PASSWORD}",
		"Bearer ${HOOK_TOKEN}",
		"Bearer $HOOK_TOKEN",
		"${PACKETEER_WEBHOOK_}",
		"${PACKETEER_WEBHOOK_TOKEN}${PACKETEER_ADMIN_PASSWORD}",
	} {
		got, err := Expand(s, "PACKETEER_WEBHOOK_", getenv)
		if err == nil || got != "" {
			t.Errorf("%q: expanded to %q", s, got)
			continue
		}
		if strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "only PACKETEER_WEBHOOK_* variables expand") {
			t.Errorf("%q: error %q", s, err)
		}
	}
	if _, err := Expand("${PACKETEER_WEBHOOK_UNSET}", "PACKETEER_WEBHOOK_", getenv); err == nil || err.Error() != "PACKETEER_WEBHOOK_UNSET is not set" {
		t.Fatalf("unset: %v", err)
	}
}

// redirectServer answers /start with a redirect to target and /end with
// the X-Token header it received.
func redirectServer(t *testing.T, target func() string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, target(), http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			_, _ = w.Write([]byte("token=" + r.Header.Get("X-Token") + " accept=" + r.Header.Get("Accept")))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, c *http.Client, u string) (string, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("X-Token", "custom-secret")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

func TestSameHostRefusesAnotherHost(t *testing.T) {
	other := redirectServer(t, func() string { return "" })
	target := other.URL + "/end"
	self := redirectServer(t, func() string { return target })
	c := &http.Client{CheckRedirect: SameHost}

	if _, err := get(t, c, self.URL+"/start"); err == nil || !strings.Contains(err.Error(), "refusing a redirect to another host") {
		t.Fatalf("cross-host redirect followed: %v", err)
	}
	// 127.0.0.1 and localhost on the same port are different hosts.
	target = strings.Replace(self.URL, "127.0.0.1", "localhost", 1) + "/end"
	if _, err := get(t, c, self.URL+"/start"); err == nil {
		t.Fatal("redirect to another host name followed")
	}
	target = self.URL + "/end"
	body, err := get(t, c, self.URL+"/start")
	if err != nil || body != "token=custom-secret accept=application/json" {
		t.Fatalf("same-host redirect: %q %v", body, err)
	}
	if _, err := get(t, c, self.URL+"/loop"); err == nil || !strings.Contains(err.Error(), "stopped after 3 redirects") {
		t.Fatalf("redirect loop: %v", err)
	}
}

func TestAnyHTTPSHostDropsHeadersOnAHostChange(t *testing.T) {
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("token=" + r.Header.Get("X-Token") + " accept=" + r.Header.Get("Accept")))
	}))
	t.Cleanup(other.Close)
	self := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			// example.com is a name the test certificate holds.
			http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "example.com", 1)+"/end", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, "http://localhost:1/end", http.StatusFound)
		}
	}))
	t.Cleanup(self.Close)
	c := self.Client()
	c.CheckRedirect = AnyHTTPSHost
	tr := c.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.Replace(addr, "example.com", "127.0.0.1", 1))
	}

	body, err := get(t, c, self.URL+"/start")
	if err != nil || body != "token= accept=application/json" {
		t.Fatalf("https hop to another host: %q %v", body, err)
	}
	if _, err := get(t, c, self.URL+"/plain"); err == nil || !strings.Contains(err.Error(), "refusing a redirect to http on another host") {
		t.Fatalf("hop to plain http followed: %v", err)
	}
}
