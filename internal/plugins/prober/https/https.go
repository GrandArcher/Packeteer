// Package https implements the "https" prober: it times a full HTTPS request
// to the probe host from the provider's source address, in three parts: TCP
// connect, TLS handshake, and time to the first response byte. A reply is a
// response whose status is inside the configured range; any other outcome
// (connect or handshake failure, certificate error, timeout, a status outside
// the range) is loss. Redirects are not followed.
//
// The connection always goes to the address the engine chose; the request
// carries the configured server name, so a host that serves one name per
// address can be checked. TLS verification is on. It can be turned off only
// for a named target.
package https

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/GrandArcher/Packeteer/internal/sockmark"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "https"

// Defaults.
const (
	DefaultPort           = 443
	DefaultPath           = "/"
	DefaultPacketInterval = 500 * time.Millisecond
	DefaultStatusMin      = 200
	DefaultStatusMax      = 399
)

func init() { plugin.Probers.Register(TypeName, New) }

// Config is the https prober's config block.
type Config struct {
	Port int `yaml:"port"`
	// Method is GET (default) or HEAD.
	Method         string        `yaml:"method"`
	Path           string        `yaml:"path"`
	ServerName     string        `yaml:"server_name"`
	StatusMin      int           `yaml:"status_min"`
	StatusMax      int           `yaml:"status_max"`
	CAFile         string        `yaml:"ca_file"`
	PacketInterval time.Duration `yaml:"packet_interval"`
	Targets        []TargetCfg   `yaml:"targets"`
}

// TargetCfg overrides the request for one probe address.
type TargetCfg struct {
	Address            string `yaml:"address"`
	ServerName         string `yaml:"server_name"`
	Path               string `yaml:"path"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

type request struct {
	serverName string
	path       string
	insecure   bool
}

// Prober measures HTTPS request timing.
type Prober struct {
	plugin.Base
	port      uint16
	method    string
	statusMin int
	statusMax int
	interval  time.Duration
	roots     *x509.CertPool
	def       request
	targets   map[netip.Addr]request
}

// New is the plugin factory.
func New(c plugin.Config, env plugin.Env) (plugin.Prober, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("port %d must be between 1 and 65535", cfg.Port)
	}
	cfg.Method = strings.ToUpper(cfg.Method)
	switch cfg.Method {
	case "":
		cfg.Method = http.MethodGet
	case http.MethodGet, http.MethodHead:
	default:
		return nil, fmt.Errorf("method %q must be GET or HEAD", cfg.Method)
	}
	if cfg.Path == "" {
		cfg.Path = DefaultPath
	}
	if err := checkPath(cfg.Path); err != nil {
		return nil, err
	}
	if err := checkServerName(cfg.ServerName); err != nil {
		return nil, err
	}
	if cfg.StatusMin == 0 && cfg.StatusMax == 0 {
		cfg.StatusMin, cfg.StatusMax = DefaultStatusMin, DefaultStatusMax
	}
	if cfg.StatusMin < 100 || cfg.StatusMax > 599 || cfg.StatusMin > cfg.StatusMax {
		return nil, fmt.Errorf("status_min %d and status_max %d must satisfy 100 <= min <= max <= 599", cfg.StatusMin, cfg.StatusMax)
	}
	if cfg.PacketInterval < 0 {
		return nil, fmt.Errorf("packet_interval %s must not be negative", cfg.PacketInterval)
	}
	if cfg.PacketInterval == 0 {
		cfg.PacketInterval = DefaultPacketInterval
	}
	p := &Prober{
		port: uint16(cfg.Port), method: cfg.Method, interval: cfg.PacketInterval,
		statusMin: cfg.StatusMin, statusMax: cfg.StatusMax,
		def:     request{serverName: cfg.ServerName, path: cfg.Path},
		targets: make(map[netip.Addr]request, len(cfg.Targets)),
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ca_file: %w", err)
		}
		p.roots = x509.NewCertPool()
		if !p.roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s holds no PEM certificate", cfg.CAFile)
		}
	}
	for i, t := range cfg.Targets {
		a, err := netip.ParseAddr(t.Address)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: address %q is not an IP address", i, t.Address)
		}
		a = a.Unmap()
		if _, dup := p.targets[a]; dup {
			return nil, fmt.Errorf("targets[%d]: address %s is listed twice", i, a)
		}
		r := p.def
		if t.ServerName != "" {
			if err := checkServerName(t.ServerName); err != nil {
				return nil, fmt.Errorf("targets[%d]: %w", i, err)
			}
			r.serverName = t.ServerName
		}
		if t.Path != "" {
			if err := checkPath(t.Path); err != nil {
				return nil, fmt.Errorf("targets[%d]: %w", i, err)
			}
			r.path = t.Path
		}
		r.insecure = t.InsecureSkipVerify
		if r.insecure && env.Logger != nil {
			env.Logger.Warn("https prober: certificate verification is off for a target", "address", a)
		}
		p.targets[a] = r
	}
	return p, nil
}

func checkPath(path string) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \r\n") {
		return fmt.Errorf("path %q must start with / and hold no spaces or line breaks", path)
	}
	return nil
}

func checkServerName(n string) error {
	if strings.ContainsAny(n, " /\r\n") {
		return fmt.Errorf("server_name %q is not a host name", n)
	}
	return nil
}

// Probe implements plugin.Prober.
func (p *Prober) Probe(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	if req.Source.Is4() != req.Target.Is4() {
		return plugin.ProbeResult{}, fmt.Errorf("source %s and target %s differ in address family", req.Source, req.Target)
	}
	port := p.port
	if req.Port != 0 {
		port = req.Port
	}
	rq, ok := p.targets[req.Target.Unmap()]
	if !ok {
		rq = p.def
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: req.Source.AsSlice()}, Timeout: req.Timeout,
		Control: sockmark.Control(sockmark.Marking{Mark: req.Mark, DSCP: req.DSCP})}
	addr := netip.AddrPortFrom(req.Target, port).String()
	res := plugin.ProbeResult{}
	for i := 0; i < req.Count; i++ {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		start := time.Now()
		res.Sent++
		ph, err := p.once(ctx, &d, addr, req, rq)
		switch {
		case err == nil:
			res.RTTs = append(res.RTTs, ph.Connect+ph.Handshake+ph.TTFB)
			res.Phases = append(res.Phases, ph)
		case errors.Is(err, syscall.EADDRNOTAVAIL), errors.Is(err, sockmark.ErrTag):
			return res, fmt.Errorf("%w: %s: %v", plugin.ErrSourceUnavailable, req.Source, err)
		case ctx.Err() != nil:
			return res, ctx.Err()
		}
		if i < req.Count-1 {
			if wait := p.interval - time.Since(start); wait > 0 {
				select {
				case <-time.After(wait):
				case <-ctx.Done():
					return res, ctx.Err()
				}
			}
		}
	}
	return res, nil
}

// once makes one request on a fresh connection. A non-nil error is a lost
// probe.
func (p *Prober) once(ctx context.Context, d *net.Dialer, addr string, req plugin.ProbeRequest, rq request) (plugin.Phases, error) {
	var ph plugin.Phases
	t0 := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ph, err
	}
	defer func() {
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // RST instead of FIN: no TIME_WAIT buildup
		}
		_ = conn.Close()
	}()
	ph.Connect = time.Since(t0)
	if req.Timeout > 0 {
		_ = conn.SetDeadline(t0.Add(req.Timeout))
	}
	// A cancelled context must break a blocked handshake or read.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	name := rq.serverName
	if name == "" {
		name = req.Target.String()
	}
	tc := tls.Client(conn, &tls.Config{ServerName: name, RootCAs: p.roots, InsecureSkipVerify: rq.insecure, MinVersion: tls.VersionTLS12}) // #nosec G402 -- opt-in per target, off by default
	t1 := time.Now()
	if err := tc.HandshakeContext(ctx); err != nil {
		return ph, err
	}
	ph.Handshake = time.Since(t1)

	host := name
	if a, err := netip.ParseAddr(name); err == nil && a.Is6() {
		host = "[" + name + "]"
	}
	hr, err := http.NewRequestWithContext(ctx, p.method, "https://"+host+rq.path, nil)
	if err != nil {
		return ph, err
	}
	hr.Header.Set("User-Agent", "Packeteer-probe")
	hr.Close = true
	t2 := time.Now()
	if err := hr.Write(tc); err != nil {
		return ph, err
	}
	br := bufio.NewReader(tc)
	if _, err := br.Peek(1); err != nil {
		return ph, err
	}
	ph.TTFB = time.Since(t2)
	resp, err := http.ReadResponse(br, hr)
	if err != nil {
		return ph, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < p.statusMin || resp.StatusCode > p.statusMax {
		return ph, fmt.Errorf("status %d outside %d-%d", resp.StatusCode, p.statusMin, p.statusMax)
	}
	return ph, nil
}
