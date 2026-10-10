// Package flow implements the "flow" target source.
//
// It listens for NetFlow v5, NetFlow v9, IPFIX, and sFlow v5, sums destination
// bytes over a sliding window, and returns the busiest prefixes. Each
// destination is mapped through SetPrefixLookup when that returns a covering
// prefix; otherwise it is aggregated to aggregate_v4 or aggregate_v6. A
// destination inside an exchange peering LAN is not a probe target and is
// not aggregated (#145): BGP sessions and IXP services on that LAN must
// not be probed when no learned route covers them. Up to three of the
// busiest destinations are probe candidates, not pins. A prefix stays on
// the list when it clears min_bytes or min_pct (#118). top_n of that list
// are probed every round; the rest, up to max_targets, carry tail_interval.
// Raw flow records are not stored: only per-bucket counters and the
// templates needed to decode NetFlow v9 and IPFIX.
//
// With a problems block it also scores remote prefixes by TCP flags on
// unsampled NetFlow v5, v9, and IPFIX records (internal/passive): outbound
// connection attempts that never got past SYN, and resets from the remote
// side. Problem prefixes are listed ahead of the busiest ones.
//
// With a transit block it also classifies traffic (#29): bytes whose source
// is in transit.customers transit the network (customer-originated), the
// rest are local. A prefix whose transit share reaches transit.share_pct is
// a transit prefix. The class reaches the policy chain so transit and local
// prefixes can have separate policies (rules with traffic: transit|local).
// Classification never announces and never adds a target.
//
// With a subranges block it also counts bytes per sub-range (#121), for
// example per /24 inside a learned /16, and each target wider than the
// sub-range length carries its busiest sub-ranges, each with its own
// busiest destination. The probe engine scores each one and the prefix
// score is their traffic-weighted aggregate. Sub-ranges are measured,
// never announced.
package flow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/passive"
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
	minTailInterval = time.Second
	maxPrefixes     = 20000
	// minPctScale turns a percent (1 means 1%) into millionths of the
	// window. 1% is 10_000, 100% is 1_000_000, and the step is 0.0001
	// percentage points.
	minPctScale     = 10_000
	udpReadBuffer   = 4 << 20
	udpReadTimeout  = time.Second
	udpPayloadBytes = 65535

	defaultProblemFailurePct = 20
	defaultProblemMinFlows   = 10
	defaultProblemMaxTargets = 100

	defaultTransitSharePct = 50
	maxTransitCustomers    = 10000

	defaultSubBitsV4     = 24
	defaultSubBitsV6     = 48
	defaultMaxSubranges  = 4
	defaultSubMaxTotal   = 1000
	minMaxSubranges      = 2
	subTrackPerSubrange  = 2
	maxSubTrackPerBucket = 2 * plugin.MaxSubranges

	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

func init() { plugin.Sources.Register(TypeName, New) }

// Source implements VolumeSource so commit control can read per-prefix rates,
// TrafficClassifier so policies can match transit traffic, and
// FlowCounterSource so the anomaly detector (#33) can baseline traffic per
// prefix and protocol.
var (
	_ plugin.VolumeSource      = (*Source)(nil)
	_ plugin.TrafficClassifier = (*Source)(nil)
	_ plugin.FlowCounterSource = (*Source)(nil)
)

// Config is the flow source's config block.
type Config struct {
	Listen       listenList    `yaml:"listen"`
	Window       time.Duration `yaml:"window"`
	TopN         int           `yaml:"top_n"`
	MaxTargets   int           `yaml:"max_targets"`
	MinBytes     uint64        `yaml:"min_bytes"`
	MinPct       float64       `yaml:"min_pct"`
	TailInterval time.Duration `yaml:"tail_interval"`
	AggregateV4  int           `yaml:"aggregate_v4"`
	AggregateV6  int           `yaml:"aggregate_v6"`
	Exclude      []string      `yaml:"exclude"`
	// Problems turns on passive problem detection from TCP flags. Off
	// when omitted.
	Problems *ProblemsConfig `yaml:"problems"`
	// Transit turns on transit traffic classification. Off when omitted.
	Transit *TransitConfig `yaml:"transit"`
	// Subranges turns on sub-range measurement inside wide prefixes
	// (#121). Off when omitted.
	Subranges *SubrangesConfig `yaml:"subranges"`
}

// SubrangesConfig is the flow source's sub-range measurement block (#121).
type SubrangesConfig struct {
	// BitsV4 and BitsV6 are the sub-range lengths. A prefix as long as
	// that, or longer, is not split. Defaults 24 and 48.
	BitsV4 int `yaml:"bits_v4"`
	BitsV6 int `yaml:"bits_v6"`
	// MaxSubranges is how many of a prefix's busiest sub-ranges are
	// measured. Default 4, 2 to 16.
	MaxSubranges int `yaml:"max_subranges"`
	// MaxTotal caps sub-ranges across every target in one list, busiest
	// prefixes first. Default 1000, at most 10000.
	MaxTotal int `yaml:"max_total"`
}

// subranges is the validated SubrangesConfig.
type subranges struct {
	bits4, bits6 int
	maxPer       int
	maxTotal     int
}

// TransitConfig is the flow source's transit classification block.
type TransitConfig struct {
	// Customers lists the source networks whose traffic transits: the
	// customer (downstream) prefixes behind this edge. Traffic from any
	// other source is local.
	Customers []string `yaml:"customers"`
	// SharePct is the transit share of a prefix's classified bytes at or
	// above which the prefix is a transit prefix. Default 50.
	SharePct float64 `yaml:"share_pct"`
}

// transit is the validated TransitConfig.
type transit struct {
	customers []netip.Prefix
	sharePct  float64
}

// ProblemsConfig is the flow source's passive problem detection block.
type ProblemsConfig struct {
	// Local lists your own networks, so a record's remote side is known.
	Local      []string `yaml:"local"`
	FailurePct float64  `yaml:"failure_pct"`
	MinFlows   uint64   `yaml:"min_flows"`
	MaxTargets int      `yaml:"max_targets"`
}

// problems is the validated ProblemsConfig plus its window.
type problems struct {
	local      []netip.Prefix
	th         passive.Thresholds
	maxTargets int
	win        *passive.Window
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
	log          *slog.Logger
	listen       []string
	window       time.Duration
	topN         int
	maxTargets   int
	minBytes     uint64
	minPctPPM    uint64
	tailInterval time.Duration
	agg4         int
	agg6         int
	exclude      []netip.Prefix
	now          func() time.Time

	mu     sync.RWMutex
	lookup func(netip.Addr) (netip.Prefix, bool)
	lans   []netip.Prefix

	dropMu  sync.Mutex
	dropped map[netip.Prefix]struct{}

	dec  *decoder
	win  *slide
	prob *problems
	tr   *transit
	sub  *subranges
	ctr  *counters

	// connMu guards conns and gen. Start after Stop binds again: a reload
	// can replace a flow source that keeps the same listen address.
	connMu sync.Mutex
	conns  []*net.UDPConn
	gen    uint64
	wg     sync.WaitGroup
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
	ppm, err := minPctMillionths(cfg.MinPct)
	if err != nil {
		return nil, err
	}
	if cfg.MaxTargets < 0 || cfg.MaxTargets > maxTopN {
		return nil, fmt.Errorf("max_targets %d must be between 1 and %d, or 0 to match top_n", cfg.MaxTargets, maxTopN)
	}
	if cfg.MaxTargets == 0 {
		cfg.MaxTargets = cfg.TopN
	}
	if cfg.MaxTargets < cfg.TopN {
		return nil, fmt.Errorf("max_targets %d is below top_n %d", cfg.MaxTargets, cfg.TopN)
	}
	if cfg.MaxTargets > cfg.TopN && cfg.TailInterval <= 0 {
		return nil, fmt.Errorf("tail_interval is required when max_targets (%d) is greater than top_n (%d)", cfg.MaxTargets, cfg.TopN)
	}
	if cfg.TailInterval < 0 || (cfg.TailInterval > 0 && (cfg.TailInterval < minTailInterval || cfg.TailInterval > maxWindow)) {
		return nil, fmt.Errorf("tail_interval %s must be between %s and %s", cfg.TailInterval, minTailInterval, maxWindow)
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
	prob, err := newProblems(cfg.Problems, cfg.Window)
	if err != nil {
		return nil, err
	}
	tr, err := newTransit(cfg.Transit)
	if err != nil {
		return nil, err
	}
	sub, err := newSubranges(cfg.Subranges)
	if err != nil {
		return nil, err
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	win := newSlide(cfg.Window, maxPrefixes)
	if sub != nil {
		win.subCap = min(sub.maxPer*subTrackPerSubrange, maxSubTrackPerBucket)
	}
	return &Source{
		prob:         prob,
		tr:           tr,
		sub:          sub,
		log:          env.Logger,
		listen:       listen,
		window:       cfg.Window,
		topN:         cfg.TopN,
		maxTargets:   cfg.MaxTargets,
		minBytes:     cfg.MinBytes,
		minPctPPM:    ppm,
		tailInterval: cfg.TailInterval,
		agg4:         cfg.AggregateV4,
		agg6:         cfg.AggregateV6,
		exclude:      excl,
		now:          time.Now,
		dec:          &decoder{},
		win:          win,
		ctr:          newCounters(maxPrefixes),
	}, nil
}

func newProblems(c *ProblemsConfig, window time.Duration) (*problems, error) {
	if c == nil {
		return nil, nil
	}
	local, err := passive.ParseNets("problems.local", c.Local)
	if err != nil {
		return nil, err
	}
	if len(local) == 0 {
		return nil, fmt.Errorf("problems.local is required: the prefixes of your own networks")
	}
	for i, p := range local {
		if p.Bits() == 0 {
			return nil, fmt.Errorf("problems.local[%d]: a default route cannot be local", i)
		}
	}
	if c.FailurePct == 0 {
		c.FailurePct = defaultProblemFailurePct
	}
	if c.MinFlows == 0 {
		c.MinFlows = defaultProblemMinFlows
	}
	if c.MaxTargets == 0 {
		c.MaxTargets = defaultProblemMaxTargets
	}
	if c.MaxTargets < 1 || c.MaxTargets > maxTopN {
		return nil, fmt.Errorf("problems.max_targets %d must be between 1 and %d", c.MaxTargets, maxTopN)
	}
	th := passive.Thresholds{FailurePct: c.FailurePct, MinFlows: c.MinFlows}
	if err := th.Validate(); err != nil {
		return nil, fmt.Errorf("problems: %w", err)
	}
	return &problems{local: local, th: th, maxTargets: c.MaxTargets, win: passive.NewWindow(window, maxPrefixes)}, nil
}

func newSubranges(c *SubrangesConfig) (*subranges, error) {
	if c == nil {
		return nil, nil
	}
	if c.BitsV4 == 0 {
		c.BitsV4 = defaultSubBitsV4
	}
	if c.BitsV4 < 1 || c.BitsV4 > 32 {
		return nil, fmt.Errorf("subranges.bits_v4 %d must be between 1 and 32", c.BitsV4)
	}
	if c.BitsV6 == 0 {
		c.BitsV6 = defaultSubBitsV6
	}
	if c.BitsV6 < 1 || c.BitsV6 > 128 {
		return nil, fmt.Errorf("subranges.bits_v6 %d must be between 1 and 128", c.BitsV6)
	}
	if c.MaxSubranges == 0 {
		c.MaxSubranges = defaultMaxSubranges
	}
	if c.MaxSubranges < minMaxSubranges || c.MaxSubranges > plugin.MaxSubranges {
		return nil, fmt.Errorf("subranges.max_subranges %d must be between %d and %d", c.MaxSubranges, minMaxSubranges, plugin.MaxSubranges)
	}
	if c.MaxTotal == 0 {
		c.MaxTotal = defaultSubMaxTotal
	}
	if c.MaxTotal < minMaxSubranges || c.MaxTotal > maxTopN {
		return nil, fmt.Errorf("subranges.max_total %d must be between %d and %d", c.MaxTotal, minMaxSubranges, maxTopN)
	}
	return &subranges{bits4: c.BitsV4, bits6: c.BitsV6, maxPer: c.MaxSubranges, maxTotal: c.MaxTotal}, nil
}

// of returns dst's sub-range inside p, or an invalid prefix when
// sub-ranges are off or p is not wider than the sub-range length.
func (c *subranges) of(p netip.Prefix, dst netip.Addr) netip.Prefix {
	if c == nil || !p.IsValid() {
		return netip.Prefix{}
	}
	bits := c.bits4
	if dst.Is6() {
		bits = c.bits6
	}
	if p.Bits() >= bits {
		return netip.Prefix{}
	}
	sp, err := dst.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return sp.Masked()
}

func newTransit(c *TransitConfig) (*transit, error) {
	if c == nil {
		return nil, nil
	}
	if len(c.Customers) == 0 {
		return nil, fmt.Errorf("transit.customers is required: the source prefixes of the customer networks whose traffic transits (omit transit to disable classification)")
	}
	if len(c.Customers) > maxTransitCustomers {
		return nil, fmt.Errorf("transit.customers: at most %d prefixes", maxTransitCustomers)
	}
	customers, err := passive.ParseNets("transit.customers", c.Customers)
	if err != nil {
		return nil, err
	}
	for i, p := range customers {
		if p.Bits() == 0 {
			return nil, fmt.Errorf("transit.customers[%d]: a default route cannot be a customer network", i)
		}
	}
	if c.SharePct == 0 {
		c.SharePct = defaultTransitSharePct
	}
	if c.SharePct != c.SharePct || c.SharePct <= 0 || c.SharePct > 100 {
		return nil, fmt.Errorf("transit.share_pct %v must be above 0 and at most 100", c.SharePct)
	}
	return &transit{customers: customers, sharePct: c.SharePct}, nil
}

// classify returns the traffic class of a record's source. Without a
// transit block, or without a source address, it is unknown.
func (t *transit) classify(src netip.Addr) traffic {
	if t == nil || !src.IsValid() || src.IsUnspecified() {
		return trafficUnknown
	}
	if passive.Contains(t.customers, src.Unmap()) {
		return trafficTransit
	}
	return trafficLocal
}

// class is the prefix's class from its classified bytes, or "" when none
// were classified.
func (t *transit) class(local, tr uint64) string {
	m := plugin.TrafficMix{LocalBytes: local, TransitBytes: tr}
	switch {
	case local+tr == 0:
		return ""
	case m.TransitPct() >= t.sharePct:
		return plugin.TrafficTransit
	default:
		return plugin.TrafficLocal
	}
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

// SetExchangeLANs installs the peering LANs (#145). A destination inside
// one is not counted and cannot become a probe target, including when no
// learned route covers it and it would otherwise fall back to the
// aggregate length. The controller calls this before Start.
func (s *Source) SetExchangeLANs(lans []netip.Prefix) {
	cp := append([]netip.Prefix(nil), lans...)
	s.mu.Lock()
	s.lans = cp
	s.mu.Unlock()
}

func (s *Source) lansSnapshot() []netip.Prefix {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lans
}

func (s *Source) noteLAN(p netip.Prefix) {
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	if s.dropped == nil {
		s.dropped = map[netip.Prefix]struct{}{}
	}
	s.dropped[p] = struct{}{}
}

func (s *Source) takeLANDrops() int {
	s.dropMu.Lock()
	defer s.dropMu.Unlock()
	n := len(s.dropped)
	s.dropped = nil
	return n
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
// validates the config without taking the ports. Stop then Start binds
// again, so an online reload can replace the source on the same port.
func (s *Source) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.connMu.Lock()
	if len(s.conns) > 0 {
		s.connMu.Unlock()
		return errors.New("flow source already started")
	}
	s.connMu.Unlock()
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
	s.connMu.Lock()
	if len(s.conns) > 0 {
		s.connMu.Unlock()
		closeAll(conns)
		return errors.New("flow source already started")
	}
	s.conns = conns
	s.gen++
	gen := s.gen
	s.connMu.Unlock()
	for _, c := range conns {
		s.log.Info("flow listening", "addr", c.LocalAddr().String())
		s.wg.Add(1)
		go s.readLoop(ctx, c)
	}
	go func() {
		<-ctx.Done()
		s.closeGen(gen)
	}()
	return nil
}

// Stop closes the listeners and waits for the read loops. A later Start
// binds the same addresses again.
func (s *Source) Stop(ctx context.Context) error {
	s.connMu.Lock()
	gen := s.gen
	s.connMu.Unlock()
	s.closeGen(gen)
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

// closeGen closes the listeners from gen. A newer Start is left alone,
// and a second close of the same generation is a no-op.
func (s *Source) closeGen(gen uint64) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if gen == 0 || s.gen != gen || len(s.conns) == 0 {
		return
	}
	closeAll(s.conns)
	s.conns = nil
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
		// Decode before the next read. ingest does not keep the
		// payload, so the read buffer is reused instead of copied.
		s.ingest(s.now(), udpAddr(addr), buf[:n])
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

// TailInterval is the cadence for prefixes past top_n. It is zero when
// the probed set is only the priority tier (max_targets equals top_n),
// including the default. The controller rejects a non-zero value that is
// not longer than probe.interval and shorter than the staleness window.
func (s *Source) TailInterval() time.Duration {
	if s == nil || s.maxTargets <= s.topN {
		return 0
	}
	return s.tailInterval
}

// minPctMillionths converts a percent of window bytes to millionths.
// Zero disables the percent floor. The step is 0.0001 percentage points.
func minPctMillionths(pct float64) (uint64, error) {
	if pct == 0 {
		return 0, nil
	}
	if math.IsNaN(pct) || math.IsInf(pct, 0) || pct < 0 || pct > 100 {
		return 0, fmt.Errorf("min_pct %v must be between 0 and 100", pct)
	}
	scaled := math.Round(pct * minPctScale)
	if scaled < 1 || scaled > 1_000_000 {
		return 0, fmt.Errorf("min_pct %v must be between 0.0001 and 100", pct)
	}
	return uint64(scaled), nil
}

// passesFloor reports whether a prefix with bytes in a window of total
// stays eligible. A min_bytes of 0 leaves the absolute bar off. A
// minPctPPM of 0 leaves the percent bar off. When both are off, every
// prefix with bytes is eligible (the previous behavior). When both are
// on, either bar is enough. overflow means the window sum did not fit in
// a uint64; the percent bar then fails closed.
func passesFloor(bytes, total uint64, overflow bool, minBytes, minPctPPM uint64) bool {
	if bytes == 0 {
		return false
	}
	byteOn := minBytes > 0
	pctOn := minPctPPM > 0 && !overflow
	if !byteOn && !pctOn {
		return minPctPPM == 0
	}
	if byteOn && bytes >= minBytes {
		return true
	}
	return pctOn && shareAtLeast(bytes, total, minPctPPM)
}

// shareAtLeast reports bytes/total >= ppm/1_000_000. ppm is millionths
// of the window, so 10_000 is one percent.
func shareAtLeast(bytes, total, ppm uint64) bool {
	if bytes == 0 || total == 0 || ppm == 0 {
		return false
	}
	if bytes >= total {
		return true
	}
	if ppm >= 1_000_000 {
		return false
	}
	hi, lo := bits.Mul64(bytes, 1_000_000)
	phi, plo := bits.Mul64(ppm, total)
	if hi != phi {
		return hi > phi
	}
	return lo >= plo
}

// Volumes implements plugin.VolumeSource. Mbps is bytes over the configured
// window. The list is not limited to top_n. It does not announce.
func (s *Source) Volumes(ctx context.Context) ([]plugin.PrefixVolume, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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

// FlowCounters implements plugin.FlowCounterSource: bytes per destination
// prefix and IP protocol since the source started, mapped the same way as
// Targets and Volumes. It does not announce.
func (s *Source) FlowCounters(ctx context.Context) ([]plugin.FlowCounter, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.ctr.snapshot(s.now()), nil
}

// TrafficMix implements plugin.TrafficClassifier. It lists every prefix in
// the window with classified bytes, largest first. Without a transit block
// it returns nothing. It does not announce.
func (s *Source) TrafficMix(ctx context.Context) ([]plugin.TrafficMix, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.tr == nil {
		return nil, nil
	}
	rows := s.win.totals(s.now(), maxPrefixes)
	out := make([]plugin.TrafficMix, 0, len(rows))
	for _, r := range rows {
		c := s.tr.class(r.local, r.transit)
		if c == "" {
			continue
		}
		out = append(out, plugin.TrafficMix{Prefix: r.prefix, LocalBytes: r.local, TransitBytes: r.transit, Class: c})
	}
	return out, nil
}

// Targets returns the current top prefixes. With a problems block, problem
// prefixes come first (weight is the problem score, capped at
// problems.max_targets), then the busiest prefixes not already listed. An
// idle collector returns an empty slice, not an error, so other sources
// keep working. Each target carries up to three destination addresses,
// busiest first. A problem prefix puts the failure address first.
//
// Volume prefixes are the ones that clear an enabled floor, largest
// first, prefix text breaking a tie (#118). The first top_n keep the
// engine interval. The rest, up to max_targets, carry tail_interval.
// Problem prefixes stay on the engine interval. A problem that also
// clears the floor still uses one slot, as it did under top_n alone.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	now := s.now()
	rows := s.win.aggregate(now)
	total, overflow := windowBytes(rows)
	hostOf := make(map[netip.Prefix][]netip.Addr, len(rows))
	subsOf := make(map[netip.Prefix][]subRank, len(rows))
	for _, r := range rows {
		hostOf[r.prefix] = r.hosts
		subsOf[r.prefix] = r.subs
	}
	subLeft := 0
	if s.sub != nil {
		subLeft = s.sub.maxTotal
	}
	out := []plugin.Target{}
	listed := map[netip.Prefix]bool{}
	if s.prob != nil {
		for _, p := range s.prob.win.Problems(now, s.prob.th, s.prob.maxTargets) {
			t := plugin.Target{Prefix: p.Prefix, Weight: p.Score}
			hosts := make([]netip.Addr, 0, 1+len(hostOf[p.Prefix]))
			if p.Host.IsValid() {
				hosts = append(hosts, p.Host)
			}
			hosts = append(hosts, hostOf[p.Prefix]...)
			setFlowHosts(&t, hosts)
			s.setSubranges(&t, subsOf[p.Prefix], &subLeft)
			out = append(out, t)
			listed[p.Prefix] = true
		}
	}
	added := 0
	for _, r := range rows {
		if !passesFloor(r.bytes, total, overflow, s.minBytes, s.minPctPPM) {
			continue
		}
		if added >= s.maxTargets {
			break
		}
		added++
		if listed[r.prefix] {
			continue
		}
		t := plugin.Target{Prefix: r.prefix, Weight: float64(r.bytes)}
		if added > s.topN {
			t.Interval = s.tailInterval
		}
		setFlowHosts(&t, r.hosts)
		s.setSubranges(&t, r.subs, &subLeft)
		out = append(out, t)
	}
	out = exchange.FilterTargets(s.lansSnapshot(), out)
	exchange.NoteDrops(s.takeLANDrops())
	return out, nil
}

// windowBytes is the sum of prefix bytes in one aggregated window.
// overflow is set when the sum does not fit in a uint64; total is then
// the maximum uint64 and the percent floor fails closed.
func windowBytes(rows []rank) (total uint64, overflow bool) {
	for _, r := range rows {
		if r.bytes > ^uint64(0)-total {
			return ^uint64(0), true
		}
		total += r.bytes
	}
	return total, false
}

// setFlowHosts records up to three destinations as probe candidates.
// The first is Host. The rest are Hosts. They are not pins: the engine
// probes them first, and uses the automatic in-prefix addresses only
// when fewer than three were named.
func setFlowHosts(t *plugin.Target, hosts []netip.Addr) {
	var in []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, h := range hosts {
		if !h.IsValid() || seen[h] || !t.Prefix.Contains(h) {
			continue
		}
		seen[h] = true
		in = append(in, h)
		if len(in) == maxFlowHosts {
			break
		}
	}
	if len(in) == 0 {
		return
	}
	t.Host = in[0]
	t.Candidate = true
	if len(in) > 1 {
		t.Hosts = append([]netip.Addr(nil), in[1:]...)
	}
}

// setSubranges attaches the prefix's busiest sub-ranges (#121), at most
// max_subranges and at most *left across the list, each weighted by its
// bytes. Fewer than two is none: one sub-range is what the destination
// candidates already measure. Measurement only.
func (s *Source) setSubranges(t *plugin.Target, subs []subRank, left *int) {
	if s.sub == nil || len(subs) < minMaxSubranges || *left < minMaxSubranges {
		return
	}
	n := min(len(subs), s.sub.maxPer, *left)
	out := make([]plugin.Subrange, 0, n)
	for _, sr := range subs[:n] {
		if !t.Prefix.Contains(sr.prefix.Addr()) || sr.prefix.Bits() <= t.Prefix.Bits() || !sr.prefix.Contains(sr.host) {
			continue
		}
		out = append(out, plugin.Subrange{Prefix: sr.prefix, Host: sr.host, Weight: float64(sr.bytes)})
	}
	if len(out) < minMaxSubranges {
		return
	}
	t.Subranges = out
	*left -= len(out)
}

func (s *Source) ingest(at time.Time, exporter netip.Addr, payload []byte) {
	obs, err := s.dec.decode(exporter, payload)
	defer putObs(obs)
	if err != nil {
		s.log.Debug("flow decode", "exporter", exporter.String(), "err", err)
	}
	for _, o := range obs {
		if s.prob != nil && o.haveFlags && !o.sampled && o.proto == 6 {
			s.noteProblem(at, o)
		}
		dst := o.dst.Unmap()
		if !s.keep(dst) {
			continue
		}
		p := s.prefixFor(dst)
		if !p.IsValid() || !p.Contains(dst) {
			continue
		}
		s.win.addSub(at, p, s.sub.of(p, dst), dst, o.bytes, s.tr.classify(o.src))
		s.ctr.add(at, p, o.proto, o.bytes)
	}
}

// noteProblem scores one unsampled TCP record. An outbound record whose
// flags hold SYN without ACK never completed its handshake. An inbound
// record with RST is a reset from the remote side. Records between two
// local or two remote addresses are ignored.
func (s *Source) noteProblem(at time.Time, o observation) {
	src, dst := o.src.Unmap(), o.dst.Unmap()
	srcLocal, dstLocal := passive.Contains(s.prob.local, src), passive.Contains(s.prob.local, dst)
	var remote netip.Addr
	var d passive.Counts
	switch {
	case srcLocal && !dstLocal:
		remote = dst
		d.Flows = 1
		if o.tcpFlags&tcpSYN != 0 && o.tcpFlags&tcpACK == 0 {
			d.Timeouts = 1
		}
	case dstLocal && !srcLocal:
		remote = src
		if o.tcpFlags&tcpRST == 0 {
			return
		}
		d.Resets = 1
	default:
		return
	}
	if !s.keep(remote) {
		return
	}
	p := s.prefixFor(remote)
	if !p.IsValid() || !p.Contains(remote) {
		return
	}
	s.prob.win.Add(at, p, remote, d)
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
	if lan, ok := exchange.Covering(s.lansSnapshot(), dst); ok {
		s.noteLAN(lan)
		return false
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
