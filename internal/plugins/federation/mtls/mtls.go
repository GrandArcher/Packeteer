// Package mtls is the built-in federation transport (#30). Each instance
// serves its published snapshot over HTTPS with mutual TLS and polls its
// peers' snapshots the same way. Both sides present a certificate signed
// by the configured CA, and a caller whose certificate names no allowed
// client is refused. Certificates and keys are mounted files; nothing is
// generated or stored by the plugin.
//
// The plugin is transport only. It does not announce and does not decide:
// the controller reads Peers and applies its own allowlist, learned RIB,
// community, cap, and withdraw rules.
package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "mtls"

// SnapshotPath is where an instance serves its snapshot.
const SnapshotPath = "/v1/snapshot"

// Defaults and limits.
const (
	DefaultPollInterval = 2 * time.Second
	DefaultMaxBytes     = 16 << 20
	maxPeers            = 64
)

func init() { plugin.Federations.Register(TypeName, New) }

// Config is the mtls plugin's config block.
type Config struct {
	// Listen is the mTLS server address. Empty serves nothing (a
	// central-view instance that only polls).
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CAFile   string `yaml:"ca_file"`
	Peers    []Peer `yaml:"peers"`
	// AllowClients lists the certificate names (CN or DNS SAN) allowed to
	// read this instance's snapshot. Default: the peer names.
	AllowClients []string `yaml:"allow_clients"`
	// PollInterval is how often each peer is fetched (default 2s).
	PollInterval time.Duration `yaml:"poll_interval"`
	// Timeout bounds one fetch (default: PollInterval).
	Timeout time.Duration `yaml:"timeout"`
	// MaxAge is how long a peer's last good snapshot stays usable
	// (default 3x PollInterval). After that the peer is stale and the
	// controller acts as if it ran standalone.
	MaxAge time.Duration `yaml:"max_age"`
	// MaxBytes caps a fetched snapshot (default 16 MiB).
	MaxBytes int64 `yaml:"max_bytes"`
}

// Peer is one other instance.
type Peer struct {
	// Name is the peer's instance name. Its snapshot must carry it, and
	// its server certificate must be valid for it (or ServerName).
	Name string `yaml:"name"`
	// URL is the peer's https base URL, e.g. https://192.0.2.20:9443.
	URL string `yaml:"url"`
	// ServerName overrides the name checked on the peer's certificate.
	ServerName string `yaml:"server_name"`
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type peerState struct {
	cfg      Peer
	url      string
	lastSeen time.Time
	err      string
	snap     plugin.InstanceSnapshot
}

// Federation is the mtls transport.
type Federation struct {
	cfg   Config
	log   *slog.Logger
	cert  tls.Certificate
	pool  *x509.CertPool
	allow map[string]bool

	mu    sync.Mutex
	local []byte // published snapshot, JSON
	peers []*peerState

	srv    *http.Server
	ln     net.Listener
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New is the plugin factory. It reads the certificate files but does not
// touch the network.
func New(c plugin.Config, env plugin.Env) (plugin.Federation, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.PollInterval < 100*time.Millisecond || cfg.PollInterval > time.Minute {
		return nil, fmt.Errorf("poll_interval %s must be between 100ms and 1m", cfg.PollInterval)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = cfg.PollInterval
	}
	if cfg.Timeout < 0 || cfg.Timeout > cfg.PollInterval {
		return nil, fmt.Errorf("timeout %s must be positive and at most poll_interval", cfg.Timeout)
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 3 * cfg.PollInterval
	}
	if cfg.MaxAge < cfg.PollInterval || cfg.MaxAge > 10*time.Minute {
		return nil, fmt.Errorf("max_age %s must be between poll_interval and 10m", cfg.MaxAge)
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxBytes < 1024 || cfg.MaxBytes > 1<<30 {
		return nil, fmt.Errorf("max_bytes %d must be between 1024 and 1073741824", cfg.MaxBytes)
	}
	if cfg.Listen != "" {
		if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
			return nil, fmt.Errorf("listen %q: %w", cfg.Listen, err)
		}
	}
	if cfg.Listen == "" && len(cfg.Peers) == 0 {
		return nil, errors.New("need listen, peers, or both")
	}
	if len(cfg.Peers) > maxPeers {
		return nil, fmt.Errorf("at most %d peers", maxPeers)
	}
	if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" {
		return nil, errors.New("cert_file, key_file, and ca_file are required (mutual TLS)")
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("cert_file/key_file: %w", err)
	}
	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ca_file %s: no PEM certificates", cfg.CAFile)
	}
	f := &Federation{cfg: cfg, log: env.Logger, cert: cert, pool: pool, allow: map[string]bool{}}
	if f.log == nil {
		f.log = slog.Default()
	}
	seen := map[string]bool{}
	for i, p := range cfg.Peers {
		if !nameRE.MatchString(p.Name) {
			return nil, fmt.Errorf("peers[%d]: name %q must be 1-64 characters of letters, digits, '_', '.' or '-'", i, p.Name)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("peers[%d]: duplicate name %q", i, p.Name)
		}
		seen[p.Name] = true
		u, err := url.Parse(p.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			return nil, fmt.Errorf("peers[%d] (%s): url %q must be https://host:port", i, p.Name, p.URL)
		}
		f.peers = append(f.peers, &peerState{cfg: p, url: "https://" + u.Host + SnapshotPath})
	}
	allow := cfg.AllowClients
	if len(allow) == 0 {
		for _, p := range cfg.Peers {
			allow = append(allow, p.Name)
		}
	}
	for i, n := range allow {
		if !nameRE.MatchString(n) {
			return nil, fmt.Errorf("allow_clients[%d]: %q is not a valid name", i, n)
		}
		f.allow[n] = true
	}
	if cfg.Listen != "" && len(f.allow) == 0 {
		return nil, errors.New("listen needs allow_clients or peers: nobody could read the snapshot")
	}
	return f, nil
}

func (f *Federation) clientTLS(serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{f.cert},
		RootCAs:      f.pool,
		ServerName:   serverName,
	}
}

// Start listens (when configured) and begins polling peers.
func (f *Federation) Start(context.Context) error {
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	if f.cfg.Listen != "" {
		ln, err := net.Listen("tcp", f.cfg.Listen)
		if err != nil {
			cancel()
			return fmt.Errorf("federation listen %s: %w", f.cfg.Listen, err)
		}
		f.ln = ln
		mux := http.NewServeMux()
		mux.HandleFunc("GET "+SnapshotPath, f.serveSnapshot)
		f.srv = &http.Server{
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			ErrorLog:          slog.NewLogLogger(f.log.Handler(), slog.LevelDebug),
			TLSConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{f.cert},
				ClientCAs:    f.pool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
			},
		}
		tln := tls.NewListener(ln, f.srv.TLSConfig)
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			if err := f.srv.Serve(tln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				f.log.Error("federation server", "err", err)
			}
		}()
		f.log.Info("federation listening (mutual TLS)", "addr", ln.Addr().String())
	}
	for _, p := range f.peers {
		f.wg.Add(1)
		go f.poll(ctx, p)
	}
	return nil
}

// Addr is the bound listen address (tests use port 0). Nil before Start.
func (f *Federation) Addr() net.Addr {
	if f.ln == nil {
		return nil
	}
	return f.ln.Addr()
}

// Stop ends polling and closes the server.
func (f *Federation) Stop(ctx context.Context) error {
	if f.cancel != nil {
		f.cancel()
	}
	var err error
	if f.srv != nil {
		err = f.srv.Shutdown(ctx)
		if err != nil {
			_ = f.srv.Close()
		}
	}
	done := make(chan struct{})
	go func() { f.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return err
}

// Publish replaces the snapshot served to peers.
func (f *Federation) Publish(s plugin.InstanceSnapshot) {
	b, err := json.Marshal(s)
	if err != nil {
		f.log.Error("federation publish", "err", err)
		return
	}
	f.mu.Lock()
	f.local = b
	f.mu.Unlock()
}

// Peers returns every peer's latest state.
func (f *Federation) Peers(now time.Time) []plugin.PeerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]plugin.PeerState, 0, len(f.peers))
	for _, p := range f.peers {
		fresh := !p.lastSeen.IsZero() && now.Sub(p.lastSeen) <= f.cfg.MaxAge
		out = append(out, plugin.PeerState{
			Name: p.cfg.Name, URL: p.url, Fresh: fresh, LastSeen: p.lastSeen, Error: p.err, Snapshot: p.snap,
		})
	}
	return out
}

func (f *Federation) serveSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || !f.allowed(r.TLS.PeerCertificates[0]) {
		http.Error(w, "client certificate not allowed", http.StatusForbidden)
		return
	}
	f.mu.Lock()
	b := f.local
	f.mu.Unlock()
	if b == nil {
		http.Error(w, "no snapshot yet", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func (f *Federation) allowed(c *x509.Certificate) bool {
	if f.allow[c.Subject.CommonName] {
		return true
	}
	return slices.ContainsFunc(c.DNSNames, func(n string) bool { return f.allow[n] })
}

func (f *Federation) poll(ctx context.Context, p *peerState) {
	defer f.wg.Done()
	sn := p.cfg.ServerName
	if sn == "" {
		sn = p.cfg.Name
	}
	// No proxy from the environment: peers are reached directly.
	tr := &http.Transport{
		TLSClientConfig:     f.clientTLS(sn),
		MaxIdleConnsPerHost: 1,
		TLSHandshakeTimeout: f.cfg.Timeout,
	}
	client := &http.Client{
		Timeout:       f.cfg.Timeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	t := time.NewTicker(f.cfg.PollInterval)
	defer t.Stop()
	for {
		snap, err := f.fetch(ctx, client, p)
		now := time.Now()
		f.mu.Lock()
		if err != nil {
			if p.err != err.Error() {
				f.log.Warn("federation peer fetch failed", "peer", p.cfg.Name, "err", err)
			}
			p.err = err.Error()
		} else {
			if p.lastSeen.IsZero() || p.err != "" {
				f.log.Info("federation peer up", "peer", p.cfg.Name, "domain", snap.Domain)
			}
			p.snap = plugin.ShiftSnapshot(snap, now)
			p.lastSeen, p.err = now, ""
		}
		f.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (f *Federation) fetch(ctx context.Context, client *http.Client, p *peerState) (plugin.InstanceSnapshot, error) {
	var snap plugin.InstanceSnapshot
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return snap, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return snap, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return snap, fmt.Errorf("%s: %s", p.url, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, f.cfg.MaxBytes+1))
	if err != nil {
		return snap, err
	}
	if int64(len(body)) > f.cfg.MaxBytes {
		return snap, fmt.Errorf("%s: snapshot larger than max_bytes %d", p.url, f.cfg.MaxBytes)
	}
	if err := json.Unmarshal(body, &snap); err != nil {
		return snap, fmt.Errorf("%s: %w", p.url, err)
	}
	if snap.Instance != p.cfg.Name {
		return plugin.InstanceSnapshot{}, fmt.Errorf("%s: snapshot is from instance %q, want %q", p.url, snap.Instance, p.cfg.Name)
	}
	if snap.Time.IsZero() || snap.Domain == "" {
		return plugin.InstanceSnapshot{}, fmt.Errorf("%s: snapshot has no time or domain", p.url)
	}
	return snap, nil
}
