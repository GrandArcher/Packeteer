package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/agentwire"
	"github.com/GrandArcher/Packeteer/internal/agentwire/pkitest"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type countProber struct {
	plugin.Base
	calls atomic.Int32
}

func (c *countProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	c.calls.Add(1)
	return plugin.ProbeResult{Sent: req.Count}, nil
}

func testConfig(t *testing.T, url string) Config {
	t.Helper()
	ca := pkitest.New(t)
	leaf := ca.Issue(t, "agent-a")
	return Config{ControllerURL: url, CertFile: leaf.CertFile, KeyFile: leaf.KeyFile, CAFile: ca.CAFile, Site: "site-a",
		Providers: []Provider{{Name: "carrier-a", SourceIP: "192.0.2.11", FwMark: 7, DSCP: 10}}}
}

func TestNewRejectsBadConfig(t *testing.T) {
	good := testConfig(t, "https://127.0.0.1:9444")
	if _, err := New(good, &countProber{}, nil); err != nil {
		t.Fatalf("good config: %v", err)
	}
	for name, tc := range map[string]struct {
		edit func(*Config)
		want string
	}{
		"site":          {func(c *Config) { c.Site = "bad site" }, "site"},
		"http url":      {func(c *Config) { c.ControllerURL = "http://127.0.0.1:9444" }, "https"},
		"url path":      {func(c *Config) { c.ControllerURL = "https://127.0.0.1:9444/x" }, "https"},
		"no providers":  {func(c *Config) { c.Providers = nil }, "providers"},
		"source":        {func(c *Config) { c.Providers[0].SourceIP = "nope" }, "source_ip"},
		"dscp":          {func(c *Config) { c.Providers[0].DSCP = 64 }, "dscp"},
		"duplicate":     {func(c *Config) { c.Providers = append(c.Providers, c.Providers[0]) }, "duplicate"},
		"concurrency":   {func(c *Config) { c.MaxConcurrent = 1000 }, "max_concurrent"},
		"no cert":       {func(c *Config) { c.CertFile = "" }, "mutual TLS"},
		"unknown probe": {func(c *Config) { c.Prober.Type = "nope" }, "unknown prober"},
	} {
		c := good
		c.Providers = append([]Provider(nil), good.Providers...)
		tc.edit(&c)
		var p plugin.Prober = &countProber{}
		if name == "unknown probe" {
			p = nil
		}
		if _, err := New(c, p, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestLoadIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("site: a\nbogus: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("err = %v, want the unknown field named", err)
	}
}

func TestRequestUsesTheDeclaredSourceAndRefusesTheRest(t *testing.T) {
	a, err := New(testConfig(t, "https://127.0.0.1:9444"), &countProber{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := a.request(agentwire.Task{ID: 1, Provider: "carrier-a", Target: "198.51.100.7", Count: 3, TimeoutMS: 200})
	if err != nil {
		t.Fatal(err)
	}
	if r.Source != netip.MustParseAddr("192.0.2.11") || r.Mark != 7 || r.DSCP != 10 || r.Count != 3 || r.Timeout != 200*time.Millisecond {
		t.Fatalf("request = %+v", r)
	}
	for name, task := range map[string]agentwire.Task{
		"undeclared provider": {Provider: "carrier-x", Target: "198.51.100.7", Count: 3, TimeoutMS: 200},
		"bad target":          {Provider: "carrier-a", Target: "host", Count: 3, TimeoutMS: 200},
		"too many packets":    {Provider: "carrier-a", Target: "198.51.100.7", Count: agentwire.MaxCount + 1, TimeoutMS: 200},
		"long timeout":        {Provider: "carrier-a", Target: "198.51.100.7", Count: 3, TimeoutMS: agentwire.MaxTimeoutMS + 1},
		"other family":        {Provider: "carrier-a", Target: "2001:db8::7", Count: 3, TimeoutMS: 200},
		"zero packets":        {Provider: "carrier-a", Target: "198.51.100.7", TimeoutMS: 200},
	} {
		if _, err := a.request(task); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// With nothing to talk to, the agent sends no probe and stops when told.
func TestAgentRunsNothingWithoutAController(t *testing.T) {
	p := &countProber{}
	a, err := New(testConfig(t, "https://127.0.0.1:1"), p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if n := p.calls.Load(); n != 0 {
		t.Fatalf("%d probes ran with no controller", n)
	}
}

// tlsController serves h over mutual TLS and returns the agent config
// that trusts it.
func tlsController(t *testing.T, h http.Handler) Config {
	t.Helper()
	ca := pkitest.New(t)
	srvLeaf := ca.Issue(t, "controller")
	agentLeaf := ca.Issue(t, "agent-a")
	srv := httptest.NewUnstartedServer(h)
	cert, err := tls.LoadX509KeyPair(srvLeaf.CertFile, srvLeaf.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(ca.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cfg := testConfig(t, srv.URL)
	cfg.CertFile, cfg.KeyFile, cfg.CAFile, cfg.ServerName = agentLeaf.CertFile, agentLeaf.KeyFile, ca.CAFile, "controller"
	return cfg
}

// A connection that goes silent, such as a dropped NAT mapping, does not
// hang the agent: the poll times out and is tried again.
func TestPollTimesOutOnASilentController(t *testing.T) {
	var polls atomic.Int32
	release := make(chan struct{})
	cfg := tlsController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	a, err := New(cfg, &countProber{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	a.pollTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	_ = a.Run(ctx)
	if n := polls.Load(); n < 2 {
		t.Fatalf("%d polls reached the silent controller, want a retry after the timeout", n)
	}
}

// The controller refuses a poll that offers more slots than one poll may
// return, so an agent with a larger max_concurrent offers only that many.
func TestPollOffersAtMostOnePollsWorth(t *testing.T) {
	var free atomic.Int32
	cfg := tlsController(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req agentwire.PollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		free.Store(int32(req.Free))
		_ = json.NewEncoder(w).Encode(agentwire.PollResponse{})
	}))
	cfg.MaxConcurrent = 200
	a, err := New(cfg, &countProber{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = a.Run(ctx)
	if got := free.Load(); got != agentwire.MaxTasksPerPoll {
		t.Fatalf("poll offered %d free slots, want %d", got, agentwire.MaxTasksPerPoll)
	}
}
