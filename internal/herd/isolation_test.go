package herd

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

// tlsPeer is a pinned peer with a misbehaving handler.
func tlsPeer(t *testing.T, h http.HandlerFunc) config.HerdPeer {
	t.Helper()
	n := testNode(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{n.cert}, MinVersion: tls.VersionTLS13, ClientAuth: tls.RequestClientCert})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return config.HerdPeer{URL: "https://" + ln.Addr().String(), Key: n.PublicKey()}
}

// TestBadPeersDoNotSlowTheProbeLoopOrStop proves herd's side of the
// isolation rule: with peers that are dead, silent, slow, and flooding,
// the hand-off from the probe loop stays instant, no peer fills the store,
// every failure is visible, and Stop returns while pulls are in flight.
func TestBadPeersDoNotSlowTheProbeLoopOrStop(t *testing.T) {
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPeer := config.HerdPeer{URL: "https://" + dead.Addr().String(), Key: testNode(t).PublicKey()}
	_ = dead.Close()

	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	silentPeer := config.HerdPeer{URL: "https://" + silent.Addr().String(), Key: testNode(t).PublicKey()}

	slow := tlsPeer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(time.Minute):
		}
	})
	flood := tlsPeer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := make([]byte, 64<<10)
		for range 1000 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})

	cfg := testCfg(t, func(c *config.Herd) {
		c.Peers = []config.HerdPeer{deadPeer, silentPeer, slow, flood}
		c.KeyFile = filepath.Join(t.TempDir(), "node.key")
		c.Limits.MaxPulls = 4
		c.Limits.PullTimeout = time.Second
		c.Limits.PullBytes = 4096
		c.Limits.Queue = 4
	})
	h, err := New(Options{
		Cfg: cfg, ASN: 64496, Store: testStore(t), RIB: &fakeRIB{ready: true}, Rules: defaultRules(),
		Methods: map[string]string{"icmp-main": "icmp"}, FirstMethod: "icmp",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}

	batch := []probe.Result{result("198.51.100.0/24", []string{"main-static"}, ms(10)...)}
	start := time.Now()
	for range 20000 {
		h.Offer(batch)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("20000 hand-offs took %v while pulls were stuck", d)
	}

	waitFor(t, func() bool {
		for _, p := range h.Status(context.Background()).Peers {
			if p.Failures == 0 {
				return false
			}
		}
		return true
	})
	st := h.Status(context.Background())
	if st.Store.PulledRecords != 0 {
		t.Errorf("pulled %d records from bad peers", st.Store.PulledRecords)
	}
	if st.Queue.Dropped == 0 {
		t.Error("a full queue dropped nothing and counted nothing")
	}
	for _, p := range st.Peers {
		if p.LastError == "" || p.RetryAt.IsZero() {
			t.Errorf("peer %s: no error or backoff recorded: %+v", p.URL, p)
		}
	}

	stopped := make(chan struct{})
	go func() { h.Stop(context.Background()); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return")
	}
}
