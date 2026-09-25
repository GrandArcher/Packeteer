// Package flow implements the "flow" target source.
//
// It listens for NetFlow v5, NetFlow v9, IPFIX, and sFlow v5, sums destination
// bytes over a sliding window, and returns the busiest prefixes. Each
// destination is mapped through SetPrefixLookup when that returns a covering
// prefix; otherwise it is aggregated to aggregate_v4 or aggregate_v6. Raw flow
// records are not stored: only per-bucket counters and the templates needed to
// decode NetFlow v9 and IPFIX.
package flow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"gopkg.in/yaml.v3"
)

// TypeName is the plugin type used in config.
const TypeName = "flow"

// Defaults and bounds.
const (
	defaultWindow   = 5 * time.Minute
	defaultTopN     = 100
	defaultAgg4     = 24
	defaultAgg6     = 48
	maxTopN         = 10000
	maxWindow       = 24 * time.Hour
	minWindow       = time.Second
	maxPrefixes     = 20000
	udpReadBuffer   = 4 << 20
	udpReadTimeout  = time.Second
	udpPayloadBytes = 65535
)

func init() { plugin.Sources.Register(TypeName, New) }

// Source implements VolumeSource so commit control can read per-prefix rates.
var _ plugin.VolumeSource = (*Source)(nil)

// Config is the flow source's config block.
type Config struct {
	Listen      listenList    `yaml:"listen"`
	Window      time.Duration `yaml:"window"`
	TopN        int           `yaml:"top_n"`
	MinBytes    uint64        `yaml:"min_bytes"`
	AggregateV4 int           `yaml:"aggregate_v4"`
	AggregateV6 int           `yaml:"aggregate_v6"`
	Exclude     []string      `yaml:"exclude"`
}

// listenList accepts either a single "host:port" or a list of them.
type listenList []string

// UnmarshalYAML accepts a string or a sequence.
func (l *listenList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var s string
		if err := n.Decode(&s); err != nil {
			return err
		}
		*l = []string{s}
		return nil
	case yaml.SequenceNode:
		var ss []string
		if err := n.Decode(&ss); err != nil {
			return err
		}
		*l = ss
		return nil
	default:
		return fmt.Errorf("listen must be a host:port string or a list of them")
	}
}

// Source collects flow exports and turns them into probe targets.
type Source struct {
	plugin.Base
	log      *slog.Logger
	listen   []string
	window   time.Duration
	topN     int
	minBytes uint64
	agg4     int
	agg6     int
	exclude  []netip.Prefix
	now      func() time.Time

	mu     sync.RWMutex
	lookup func(netip.Addr) (netip.Prefix, bool)

	dec *decoder
	win *slide

	conns     []*net.UDPConn
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// New is the plugin factory. It does not open sockets.
func New(c plugin.Config, env plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if len(cfg.Listen) == 0 {
		return nil, fmt.Errorf("listen is required (omit the flow source to disable collection)")
	}
	seen := map[string]bool{}
	var listen []string
	for i, raw := range cfg.Listen {
		norm, err := normalizeListen(raw)
		if err != nil {
			return nil, fmt.Errorf("listen[%d]: %w", i, err)
		}
		if seen[norm] {
			return nil, fmt.Errorf("listen[%d]: duplicate %s", i, norm)
		}
		seen[norm] = true
		listen = append(listen, norm)
	}
	if cfg.Window == 0 {
		cfg.Window = defaultWindow
	}
	if cfg.Window < minWindow || cfg.Window > maxWindow {
		return nil, fmt.Errorf("window %s must be between %s and %s", cfg.Window, minWindow, maxWindow)
	}
	if cfg.TopN == 0 {
		cfg.TopN = defaultTopN
	}
	if cfg.TopN < 1 || cfg.TopN > maxTopN {
		return nil, fmt.Errorf("top_n %d must be between 1 and %d", cfg.TopN, maxTopN)
	}
	if cfg.AggregateV4 == 0 {
		cfg.AggregateV4 = defaultAgg4
	}
	if cfg.AggregateV4 < 1 || cfg.AggregateV4 > 32 {
		return nil, fmt.Errorf("aggregate_v4 %d must be between 1 and 32", cfg.AggregateV4)
	}
	if cfg.AggregateV6 == 0 {
		cfg.AggregateV6 = defaultAgg6
	}
	if cfg.AggregateV6 < 1 || cfg.AggregateV6 > 128 {
		return nil, fmt.Errorf("aggregate_v6 %d must be between 1 and 128", cfg.AggregateV6)
	}
	excl, err := parseExclude(cfg.Exclude)
	if err != nil {
		return nil, err
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	return &Source{
		log:      env.Logger,
		listen:   listen,
		window:   cfg.Window,
		topN:     cfg.TopN,
		minBytes: cfg.MinBytes,
		agg4:     cfg.AggregateV4,
		agg6:     cfg.AggregateV6,
		exclude:  excl,
		now:      time.Now,
		dec:      &decoder{},
		win:      newSlide(cfg.Window, maxPrefixes),
	}, nil
}

func normalizeListen(s string) (string, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("%q is not host:port", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return "", fmt.Errorf("port %q is invalid", portStr)
	}
	if host != "" {
		a, err := netip.ParseAddr(host)
		if err != nil {
			return "", fmt.Errorf("host %q must be an IP address", host)
		}
		host = a.String()
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func parseExclude(in []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	seen := map[netip.Prefix]bool{}
	for i, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("exclude[%d]: %q is not a valid CIDR", i, s)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("exclude[%d]: %q has host bits set (did you mean %s?)", i, s, p.Masked())
		}
		if seen[p] {
			return nil, fmt.Errorf("exclude[%d]: duplicate prefix %s", i, p)
		}
		seen[p] = true
		out = append(out, p)
	}
	return out, nil
}

// SetPrefixLookup attaches the RIB view. fn may be nil. When fn returns a
// prefix, destinations it contains are counted under that prefix instead of
// the aggregate length. The callback must return ok=false for a default route
// and whenever the view is not ready.
func (s *Source) SetPrefixLookup(fn func(netip.Addr) (netip.Prefix, bool)) {
	s.mu.Lock()
	s.lookup = fn
	s.mu.Unlock()
}

// Start binds every listen address. The factory does not bind, so -check
// validates the config without taking the ports.
func (s *Source) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var conns []*net.UDPConn
	for _, addr := range s.listen {
		ua, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			closeAll(conns)
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		c, err := net.ListenUDP("udp", ua)
		if err != nil {
			closeAll(conns)
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		_ = c.SetReadBuffer(udpReadBuffer)
		conns = append(conns, c)
	}
	s.conns = conns
	for _, c := range conns {
		s.log.Info("flow listening", "addr", c.LocalAddr().String())
		s.wg.Add(1)
		go s.readLoop(ctx, c)
	}
	go func() {
		<-ctx.Done()
		s.closeConns()
	}()
	return nil
}

// Stop closes the listeners and waits for the read loops.
func (s *Source) Stop(ctx context.Context) error {
	s.closeConns()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Source) closeConns() {
	s.closeOnce.Do(func() { closeAll(s.conns) })
}

func closeAll(conns []*net.UDPConn) {
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *Source) readLoop(ctx context.Context, c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, udpPayloadBytes)
	for {
		_ = c.SetReadDeadline(time.Now().Add(udpReadTimeout))
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || isClosed(err) {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.log.Debug("flow read", "err", err)
			continue
		}
		if n == 0 || addr == nil {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		s.ingest(s.now(), udpAddr(addr), payload)
	}
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

func udpAddr(a *net.UDPAddr) netip.Addr {
	if a == nil || a.IP == nil {
		return netip.Addr{}
	}
	ip, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// Volumes implements plugin.VolumeSource. Mbps is bytes over the configured
// window. The list is not limited to top_n. It does not announce.
func (s *Source) Volumes(context.Context) ([]plugin.PrefixVolume, error) {
	rows := s.win.totals(s.now(), maxPrefixes)
	out := make([]plugin.PrefixVolume, 0, len(rows))
	for _, r := range rows {
		if r.bytes == 0 {
			continue
		}
		out = append(out, plugin.PrefixVolume{Prefix: r.prefix, Bytes: r.bytes, Window: s.window})
	}
	return out, nil
}

// Targets returns the current top prefixes. An idle collector returns an
// empty slice, not an error, so other sources keep working.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	ranked := s.win.top(s.now(), s.topN, s.minBytes)
	out := make([]plugin.Target, 0, len(ranked))
	for _, r := range ranked {
		t := plugin.Target{Prefix: r.prefix, Weight: float64(r.bytes)}
		if r.host.IsValid() && r.prefix.Contains(r.host) {
			t.Host = r.host
		}
		out = append(out, t)
	}
	return out, nil
}

func (s *Source) ingest(at time.Time, exporter netip.Addr, payload []byte) {
	obs, err := s.dec.decode(exporter, payload)
	if err != nil {
		s.log.Debug("flow decode", "exporter", exporter.String(), "err", err)
	}
	for _, o := range obs {
		dst := o.dst.Unmap()
		if !s.keep(dst) {
			continue
		}
		p := s.prefixFor(dst)
		if !p.IsValid() || !p.Contains(dst) {
			continue
		}
		s.win.add(at, p, dst, o.bytes)
	}
}

// keep drops addresses that are not useful probe targets: non-unicast,
// loopback, link-local, multicast, and private/ULA. RFC 1918 and ULA traffic
// on a router is usually internal and would otherwise fill top-N.
func (s *Source) keep(dst netip.Addr) bool {
	if !dst.IsValid() || !dst.IsGlobalUnicast() || dst.IsPrivate() {
		return false
	}
	for _, p := range s.exclude {
		if p.Contains(dst) {
			return false
		}
	}
	return true
}

func (s *Source) prefixFor(dst netip.Addr) netip.Prefix {
	s.mu.RLock()
	fn := s.lookup
	s.mu.RUnlock()
	if fn != nil {
		if p, ok := fn(dst); ok && p.IsValid() && p.Bits() > 0 && p.Contains(dst) {
			return p.Masked()
		}
	}
	bits := s.agg4
	if dst.Is6() {
		bits = s.agg6
	}
	p, err := dst.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p.Masked()
}
