package https

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var lo = netip.MustParseAddr("127.0.0.1")

func newProber(t *testing.T, y string) plugin.Prober {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	p, err := plugin.Probers.New(TypeName, c, plugin.Env{})
	if err != nil {
		t.Fatalf("config %q: %v", y, err)
	}
	return p
}

// seen is what the test server received.
type seen struct {
	mu    sync.Mutex
	reqs  []*http.Request
	delay time.Duration
	code  int
}

func (s *seen) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, r.Clone(context.Background()))
	delay, code := s.delay, s.code
	s.mu.Unlock()
	time.Sleep(delay)
	if code != 0 {
		w.WriteHeader(code)
	}
}

func (s *seen) last(t *testing.T) *http.Request {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.reqs) == 0 {
		t.Fatal("server saw no request")
	}
	return s.reqs[len(s.reqs)-1]
}

// server starts a TLS server on 127.0.0.1 and returns it, its handler, the
// port, and a CA file that trusts it. Its certificate names 127.0.0.1 and
// example.com.
func server(t *testing.T) (*seen, int, string) {
	t.Helper()
	h := &seen{}
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(ca, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return h, srv.Listener.Addr().(*net.TCPAddr).Port, ca
}

func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func probe(t *testing.T, p plugin.Prober, count int) plugin.ProbeResult {
	t.Helper()
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Count: count, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestProbeTimesThePhases(t *testing.T) {
	h, port, ca := server(t)
	h.delay = 40 * time.Millisecond
	p := newProber(t, fmt.Sprintf("port: %d\nca_file: %s\nserver_name: example.com\npath: /health?x=1\npacket_interval: 1ms", port, ca))
	res := probe(t, p, 3)
	if res.Sent != 3 || len(res.RTTs) != 3 || len(res.Phases) != 3 {
		t.Fatalf("res = %+v", res)
	}
	for i, ph := range res.Phases {
		if ph.Connect <= 0 || ph.Handshake <= 0 {
			t.Errorf("phases[%d] = %+v, want connect and handshake timed", i, ph)
		}
		if ph.TTFB < 40*time.Millisecond {
			t.Errorf("phases[%d].TTFB = %v, want at least the 40ms the handler waited", i, ph.TTFB)
		}
		if res.RTTs[i] != ph.Connect+ph.Handshake+ph.TTFB {
			t.Errorf("RTT %v is not the phase sum %+v", res.RTTs[i], ph)
		}
	}
	r := h.last(t)
	if r.Method != http.MethodGet || r.Host != "example.com" || r.URL.RequestURI() != "/health?x=1" || r.Header.Get("User-Agent") != "Packeteer-probe" {
		t.Fatalf("request = %s host %q uri %q ua %q", r.Method, r.Host, r.URL.RequestURI(), r.Header.Get("User-Agent"))
	}
}

func TestProbeHead(t *testing.T) {
	h, port, ca := server(t)
	p := newProber(t, fmt.Sprintf("port: %d\nca_file: %s\nmethod: head", port, ca))
	if res := probe(t, p, 1); len(res.RTTs) != 1 {
		t.Fatalf("res = %+v", res)
	}
	if m := h.last(t).Method; m != http.MethodHead {
		t.Fatalf("method = %s", m)
	}
}

func TestStatusAssertion(t *testing.T) {
	h, port, ca := server(t)
	base := fmt.Sprintf("port: %d\nca_file: %s\npacket_interval: 1ms\n", port, ca)
	for _, tt := range []struct {
		code int
		cfg  string
		ok   bool
	}{
		{200, "", true},
		{302, "", true},
		{399, "", true},
		{404, "", false},
		{500, "", false},
		{199, "", false},
		{503, "status_min: 503\nstatus_max: 503", true},
		{200, "status_min: 503\nstatus_max: 503", false},
	} {
		h.mu.Lock()
		h.code = tt.code
		h.mu.Unlock()
		res := probe(t, newProber(t, base+tt.cfg), 2)
		want := 0
		if tt.ok {
			want = 2
		}
		if res.Sent != 2 || len(res.RTTs) != want || len(res.Phases) != want {
			t.Errorf("status %d with %q: res = %+v, want %d replies", tt.code, tt.cfg, res, want)
		}
	}
}

func TestVerificationIsOnByDefault(t *testing.T) {
	_, port, ca := server(t)
	// No trusted CA: the test server's certificate does not verify.
	if res := probe(t, newProber(t, fmt.Sprintf("port: %d", port)), 1); res.Sent != 1 || len(res.RTTs) != 0 {
		t.Fatalf("unverifiable certificate answered: %+v", res)
	}
	// A trusted CA but the wrong name.
	p := newProber(t, fmt.Sprintf("port: %d\nca_file: %s\nserver_name: other.example.invalid", port, ca))
	if res := probe(t, p, 1); len(res.RTTs) != 0 {
		t.Fatalf("certificate for another name answered: %+v", res)
	}
	// The right name verifies.
	p = newProber(t, fmt.Sprintf("port: %d\nca_file: %s\nserver_name: example.com", port, ca))
	if res := probe(t, p, 1); len(res.RTTs) != 1 {
		t.Fatalf("verified probe failed: %+v", res)
	}
}

func TestInsecureSkipVerifyIsPerTarget(t *testing.T) {
	h, port, _ := server(t)
	y := fmt.Sprintf("port: %d\ntargets:\n  - address: 127.0.0.1\n    insecure_skip_verify: true\n    server_name: skip.example.invalid\n    path: /skip\n  - address: 192.0.2.77\n", port)
	p := newProber(t, y)
	res := probe(t, p, 1)
	if len(res.RTTs) != 1 {
		t.Fatalf("target with insecure_skip_verify failed: %+v", res)
	}
	if r := h.last(t); r.Host != "skip.example.invalid" || r.URL.Path != "/skip" {
		t.Fatalf("target override not used: host %q path %q", r.Host, r.URL.Path)
	}
	// 127.0.0.1 is the only probe address that skips; with the entry for
	// another address the same server does not verify.
	other := newProber(t, fmt.Sprintf("port: %d\ntargets:\n  - address: 192.0.2.77\n    insecure_skip_verify: true\n", port))
	if res := probe(t, other, 1); len(res.RTTs) != 0 {
		t.Fatalf("skip leaked to an address it was not set for: %+v", res)
	}
}

func TestTargetInheritsDefaults(t *testing.T) {
	h, port, ca := server(t)
	y := fmt.Sprintf("port: %d\nca_file: %s\nserver_name: example.com\npath: /base\ntargets:\n  - address: 127.0.0.1\n", port, ca)
	if res := probe(t, newProber(t, y), 1); len(res.RTTs) != 1 {
		t.Fatalf("res = %+v", res)
	}
	if r := h.last(t); r.Host != "example.com" || r.URL.Path != "/base" {
		t.Fatalf("host %q path %q", r.Host, r.URL.Path)
	}
}

func TestRefusedAndSilentAreLoss(t *testing.T) {
	ln := listen(t, "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	p := newProber(t, fmt.Sprintf("port: %d\npacket_interval: 1ms", port))
	if res := probe(t, p, 2); res.Sent != 2 || len(res.RTTs) != 0 {
		t.Fatalf("refused connection counted as a reply: %+v", res)
	}

	// Accepts the connection and never answers the handshake.
	silent := listen(t, "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	p = newProber(t, fmt.Sprintf("port: %d", silent.Addr().(*net.TCPAddr).Port))
	start := time.Now()
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: lo, Count: 1, Timeout: 200 * time.Millisecond})
	if err != nil || res.Sent != 1 || len(res.RTTs) != 0 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("handshake stall took %v, timeout was 200ms", d)
	}
}

func TestContextCancelStopsAStalledProbe(t *testing.T) {
	silent := listen(t, "127.0.0.1:0")
	defer silent.Close()
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	p := newProber(t, fmt.Sprintf("port: %d", silent.Addr().(*net.TCPAddr).Port))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := p.Probe(ctx, plugin.ProbeRequest{Source: lo, Target: lo, Count: 1, Timeout: 10 * time.Second})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestIPv6TargetHostHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback")
	}
	ln.Close()
	h := &seen{}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = listen(t, "[::1]:0")
	srv.StartTLS()
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newProber(t, fmt.Sprintf("port: %d\nca_file: %s", srv.Listener.Addr().(*net.TCPAddr).Port, ca))
	l6 := netip.MustParseAddr("::1")
	res, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: l6, Target: l6, Count: 1, Timeout: 2 * time.Second})
	if err != nil || len(res.RTTs) != 1 {
		t.Fatalf("res = %+v err = %v", res, err)
	}
	if r := h.last(t); r.Host != "[::1]" {
		t.Fatalf("Host = %q, want [::1]", r.Host)
	}
}

func TestSourceUnavailable(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: netip.MustParseAddr("192.0.2.99"),
		Target: netip.MustParseAddr("192.0.2.1"), Count: 1, Timeout: 200 * time.Millisecond})
	if !errors.Is(err, plugin.ErrSourceUnavailable) {
		t.Fatalf("err = %v, want ErrSourceUnavailable", err)
	}
}

func TestFamilyMismatch(t *testing.T) {
	p := newProber(t, "")
	_, err := p.Probe(context.Background(), plugin.ProbeRequest{Source: lo, Target: netip.MustParseAddr("::1"), Count: 1, Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "address family") {
		t.Fatalf("err = %v", err)
	}
}

func TestConfig(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for y, want := range map[string]string{
		"port: 70000":                                              "between 1 and 65535",
		"packet_interval: -1s":                                     "must not be negative",
		"method: POST":                                             "must be GET or HEAD",
		"path: health":                                             "must start with /",
		"path: \"/a b\"":                                           "must start with /",
		"server_name: a/b":                                         "not a host name",
		"status_max: 99":                                           "100 <= min <= max <= 599",
		"status_min: 400":                                          "100 <= min <= max <= 599",
		"status_min: 99\nstatus_max: 200":                          "100 <= min <= max <= 599",
		"status_min: 300\nstatus_max: 200":                         "100 <= min <= max <= 599",
		"status_min: 200\nstatus_max: 600":                         "100 <= min <= max <= 599",
		"insecure_skip_verify: true":                               "field insecure_skip_verify not found",
		"ca_file: /nonexistent/ca.pem":                             "ca_file",
		"ca_file: " + empty:                                        "holds no PEM certificate",
		"targets:\n  - address: example.com":                       "not an IP address",
		"targets:\n  - address: 192.0.2.1\n    path: x":            "must start with /",
		"targets:\n  - address: 192.0.2.1\n    server_name: a b":   "not a host name",
		"targets:\n  - address: 192.0.2.1\n  - address: 192.0.2.1": "listed twice",
		"targets:\n  - address: 192.0.2.1\n    port: 8443":         "field port not found",
	} {
		c, _ := plugin.ConfigFromYAML(y)
		if _, err := plugin.Probers.New(TypeName, c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}

func TestOneStatusBoundKeepsTheOtherDefault(t *testing.T) {
	h, port, ca := server(t)
	h.mu.Lock()
	h.code = 302
	h.mu.Unlock()
	p := newProber(t, fmt.Sprintf("port: %d\nca_file: %s\nstatus_max: 299", port, ca))
	if res := probe(t, p, 1); len(res.RTTs) != 0 {
		t.Fatalf("302 answered with status_max 299: %+v", res)
	}
	h.mu.Lock()
	h.code = 204
	h.mu.Unlock()
	if res := probe(t, p, 1); len(res.RTTs) != 1 {
		t.Fatalf("204 lost with status_max 299: %+v", res)
	}
}

func TestShortDeadlineKeepsMeasuredReplies(t *testing.T) {
	_, port, ca := server(t)
	p := newProber(t, fmt.Sprintf("port: %d\nca_file: %s\npacket_interval: 5s", port, ca))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	res, err := p.Probe(ctx, plugin.ProbeRequest{Source: lo, Target: lo, Count: 3, Timeout: time.Second})
	if err != nil || res.Sent != 1 || len(res.RTTs) != 1 {
		t.Fatalf("res = %+v err = %v, want the first reply kept", res, err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("waited %v for a spacing the deadline cannot fit", time.Since(start))
	}
}

func TestLostRequestIsLogged(t *testing.T) {
	h, port, ca := server(t)
	h.mu.Lock()
	h.code = 404
	h.mu.Unlock()
	var buf bytes.Buffer
	c, _ := plugin.ConfigFromYAML(fmt.Sprintf("port: %d\nca_file: %s", port, ca))
	env := plugin.Env{Logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	p, err := plugin.Probers.New(TypeName, c, env)
	if err != nil {
		t.Fatal(err)
	}
	if res := probe(t, p, 1); len(res.RTTs) != 0 {
		t.Fatalf("404 answered: %+v", res)
	}
	if out := buf.String(); !strings.Contains(out, "https probe lost") || !strings.Contains(out, "status 404") {
		t.Fatalf("log = %q", out)
	}
}
