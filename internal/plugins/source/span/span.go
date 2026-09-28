// Package span implements the "span" target source.
//
// It reads a SPAN or mirror port with an AF_PACKET socket (or replays a pcap
// file), follows TCP connections between the configured local networks and
// remote destinations, and scores each remote prefix by retransmissions,
// remote resets, handshake timeouts, and, when configured, handshake RTT.
// Prefixes over a threshold are returned as probe targets, marked urgent
// the first time they appear, so the probe engine measures them first.
//
// Packets are parsed and discarded. Only per-connection sequence state and
// per-prefix counters are kept, both capped. The source does not announce:
// injection still needs the prefix in the learned RIB, the allowlist, the
// community, the improvement cap, and hold time.
package span

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/passive"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "span"

// Defaults and bounds. A bare zero selects the default, except rtt_ms,
// where zero disables the RTT check.
const (
	DefaultWindow      = 5 * time.Minute
	DefaultRetransPct  = 5
	DefaultFailurePct  = 20
	DefaultMinSegments = 100
	DefaultMinFlows    = 10
	DefaultSYNTimeout  = 3 * time.Second
	DefaultFlowIdle    = 2 * time.Minute
	DefaultMaxFlows    = 100000
	DefaultMaxTargets  = 100
	defaultAgg4        = 24
	defaultAgg6        = 48

	minWindow     = 10 * time.Second
	maxWindow     = 24 * time.Hour
	maxSYNTimeout = time.Minute
	maxFlowIdle   = time.Hour
	maxFlowsLimit = 10000000
	maxTargets    = 10000
	maxPrefixes   = 20000

	captureBuffer = 8 << 20
	snapLen       = 512
	readTimeout   = time.Second
)

var errReadTimeout = errors.New("read timeout")

// capture is a live packet source.
type capture interface {
	link() int
	read(buf []byte) (int, error)
	close() error
}

func init() { plugin.Sources.Register(TypeName, New) }

// Config is the span source's config block.
type Config struct {
	Interface   string        `yaml:"interface"`
	PcapFile    string        `yaml:"pcap_file"`
	Promiscuous *bool         `yaml:"promiscuous"`
	Local       []string      `yaml:"local"`
	Exclude     []string      `yaml:"exclude"`
	Window      time.Duration `yaml:"window"`
	RetransPct  float64       `yaml:"retrans_pct"`
	FailurePct  float64       `yaml:"failure_pct"`
	RTTMs       float64       `yaml:"rtt_ms"`
	MinSegments uint64        `yaml:"min_segments"`
	MinFlows    uint64        `yaml:"min_flows"`
	SYNTimeout  time.Duration `yaml:"syn_timeout"`
	FlowIdle    time.Duration `yaml:"flow_idle"`
	MaxFlows    int           `yaml:"max_flows"`
	MaxTargets  int           `yaml:"max_targets"`
	AggregateV4 int           `yaml:"aggregate_v4"`
	AggregateV6 int           `yaml:"aggregate_v6"`
}

// Source detects problem prefixes from mirrored TCP traffic.
type Source struct {
	plugin.Base
	log        *slog.Logger
	iface      string
	pcapFile   string
	promisc    bool
	exclude    []netip.Prefix
	agg4, agg6 int
	th         passive.Thresholds
	maxTargets int
	now        func() time.Time

	win   *passive.Window
	trk   *tracker
	fresh passive.Fresh

	mu     sync.RWMutex
	lookup func(netip.Addr) (netip.Prefix, bool)

	cap      capture
	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New is the plugin factory. It opens no socket and reads no file.
func New(c plugin.Config, env plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	switch {
	case cfg.Interface == "" && cfg.PcapFile == "":
		return nil, fmt.Errorf("one of interface or pcap_file is required (omit the span source to disable it)")
	case cfg.Interface != "" && cfg.PcapFile != "":
		return nil, fmt.Errorf("interface and pcap_file are mutually exclusive")
	}
	if cfg.Interface != "" && (len(cfg.Interface) > 15 || strings.ContainsAny(cfg.Interface, "/ \t\n")) {
		return nil, fmt.Errorf("interface %q is not a valid interface name", cfg.Interface)
	}
	if cfg.PcapFile != "" && cfg.Promiscuous != nil {
		return nil, fmt.Errorf("promiscuous applies only to interface capture")
	}
	if cfg.PcapFile != "" && !filepath.IsAbs(cfg.PcapFile) {
		return nil, fmt.Errorf("pcap_file %q must be an absolute path inside the container", cfg.PcapFile)
	}
	local, err := passive.ParseNets("local", cfg.Local)
	if err != nil {
		return nil, err
	}
	if len(local) == 0 {
		return nil, fmt.Errorf("local is required: the prefixes of your own networks, so the source can tell remote destinations apart")
	}
	for i, p := range local {
		if p.Bits() == 0 {
			return nil, fmt.Errorf("local[%d]: a default route cannot be local", i)
		}
	}
	exclude, err := passive.ParseNets("exclude", cfg.Exclude)
	if err != nil {
		return nil, err
	}
	if cfg.Window == 0 {
		cfg.Window = DefaultWindow
	}
	if cfg.Window < minWindow || cfg.Window > maxWindow {
		return nil, fmt.Errorf("window %s must be between %s and %s", cfg.Window, minWindow, maxWindow)
	}
	if cfg.RetransPct == 0 {
		cfg.RetransPct = DefaultRetransPct
	}
	if cfg.FailurePct == 0 {
		cfg.FailurePct = DefaultFailurePct
	}
	if cfg.RTTMs < 0 || cfg.RTTMs > 60000 {
		return nil, fmt.Errorf("rtt_ms %v must be between 0 and 60000", cfg.RTTMs)
	}
	if cfg.MinSegments == 0 {
		cfg.MinSegments = DefaultMinSegments
	}
	if cfg.MinFlows == 0 {
		cfg.MinFlows = DefaultMinFlows
	}
	th := passive.Thresholds{
		RetransPct:  cfg.RetransPct,
		FailurePct:  cfg.FailurePct,
		RTT:         time.Duration(cfg.RTTMs * float64(time.Millisecond)),
		MinSegments: cfg.MinSegments,
		MinFlows:    cfg.MinFlows,
	}
	if err := th.Validate(); err != nil {
		return nil, err
	}
	if cfg.SYNTimeout == 0 {
		cfg.SYNTimeout = DefaultSYNTimeout
	}
	if cfg.SYNTimeout < 100*time.Millisecond || cfg.SYNTimeout > maxSYNTimeout {
		return nil, fmt.Errorf("syn_timeout %s must be between 100ms and %s", cfg.SYNTimeout, maxSYNTimeout)
	}
	if cfg.FlowIdle == 0 {
		cfg.FlowIdle = DefaultFlowIdle
	}
	if cfg.FlowIdle <= cfg.SYNTimeout || cfg.FlowIdle > maxFlowIdle {
		return nil, fmt.Errorf("flow_idle %s must be longer than syn_timeout (%s) and at most %s", cfg.FlowIdle, cfg.SYNTimeout, maxFlowIdle)
	}
	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = DefaultMaxFlows
	}
	if cfg.MaxFlows < 1 || cfg.MaxFlows > maxFlowsLimit {
		return nil, fmt.Errorf("max_flows %d must be between 1 and %d", cfg.MaxFlows, maxFlowsLimit)
	}
	if cfg.MaxTargets == 0 {
		cfg.MaxTargets = DefaultMaxTargets
	}
	if cfg.MaxTargets < 1 || cfg.MaxTargets > maxTargets {
		return nil, fmt.Errorf("max_targets %d must be between 1 and %d", cfg.MaxTargets, maxTargets)
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
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	promisc := true
	if cfg.Promiscuous != nil {
		promisc = *cfg.Promiscuous
	}
	s := &Source{
		log:        env.Logger,
		iface:      cfg.Interface,
		pcapFile:   cfg.PcapFile,
		promisc:    promisc,
		exclude:    exclude,
		agg4:       cfg.AggregateV4,
		agg6:       cfg.AggregateV6,
		th:         th,
		maxTargets: cfg.MaxTargets,
		now:        time.Now,
		win:        passive.NewWindow(cfg.Window, maxPrefixes),
		stop:       make(chan struct{}),
	}
	s.trk = &tracker{
		local:      local,
		keep:       s.keep,
		prefixFor:  s.prefixFor,
		win:        s.win,
		synTimeout: cfg.SYNTimeout,
		idle:       cfg.FlowIdle,
		maxFlows:   cfg.MaxFlows,
		flows:      map[flowKey]*flowState{},
	}
	return s, nil
}

// Fresh tells the probe engine to read Targets every round: the list
// changes with the traffic, not with the probe interval.
func (s *Source) Fresh() bool { return true }

// SetPrefixLookup attaches the RIB view, as for the flow source. A remote
// address is scored under its covering learned prefix when fn returns one,
// otherwise under aggregate_v4 or aggregate_v6.
func (s *Source) SetPrefixLookup(fn func(netip.Addr) (netip.Prefix, bool)) {
	s.mu.Lock()
	s.lookup = fn
	s.mu.Unlock()
}

// Start opens the capture. Interface capture needs CAP_NET_RAW; a missing
// capability or interface fails startup. A pcap file is replayed once in
// the background, its timestamps shifted to start now.
func (s *Source) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.pcapFile != "" {
		f, err := os.Open(s.pcapFile)
		if err != nil {
			return fmt.Errorf("pcap_file: %w", err)
		}
		pr, err := newPcapReader(f)
		if err != nil {
			_ = f.Close()
			return fmt.Errorf("pcap_file %s: %w", s.pcapFile, err)
		}
		s.log.Info("span replaying pcap", "file", s.pcapFile)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer f.Close()
			n, err := s.replay(pr, s.now())
			if err != nil {
				s.log.Warn("span pcap replay stopped", "file", s.pcapFile, "packets", n, "err", err)
				return
			}
			s.log.Info("span pcap replay done", "file", s.pcapFile, "packets", n)
		}()
		return nil
	}
	c, err := openCapture(s.iface, s.promisc, readTimeout)
	if err != nil {
		return err
	}
	s.cap = c
	s.log.Info("span capturing", "interface", s.iface, "promiscuous", s.promisc)
	s.wg.Add(1)
	go s.readLoop(ctx, c)
	return nil
}

// Stop ends capture or replay and waits for the reader.
func (s *Source) Stop(ctx context.Context) error {
	s.stopOnce.Do(func() { close(s.stop) })
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

func (s *Source) stopped(ctx context.Context) bool {
	select {
	case <-s.stop:
		return true
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (s *Source) readLoop(ctx context.Context, c capture) {
	defer s.wg.Done()
	defer c.close()
	buf := make([]byte, snapLen)
	link := c.link()
	for !s.stopped(ctx) {
		n, err := c.read(buf)
		if err != nil {
			if errors.Is(err, errReadTimeout) {
				continue
			}
			s.log.Warn("span capture stopped", "interface", s.iface, "err", err)
			return
		}
		s.ingest(s.now(), link, buf[:n])
	}
}

// replay feeds a pcap through the tracker. Timestamps keep their spacing
// and are shifted so the first packet lands at start.
func (s *Source) replay(pr *pcapReader, start time.Time) (int, error) {
	var first time.Time
	n := 0
	for {
		select {
		case <-s.stop:
			return n, errors.New("stopped")
		default:
		}
		ts, b, err := pr.next()
		if errors.Is(err, io.EOF) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if n == 0 {
			first = ts
		}
		n++
		s.ingest(start.Add(ts.Sub(first)), pr.link, b)
	}
}

func (s *Source) ingest(at time.Time, link int, frame []byte) {
	seg, ok := decodeFrame(link, frame)
	if !ok {
		return
	}
	s.trk.observe(at, seg)
}

// keep drops remote addresses that are not useful probe targets:
// non-unicast, loopback, link-local, multicast, private/ULA, and excluded.
func (s *Source) keep(a netip.Addr) bool {
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	return !passive.Contains(s.exclude, a)
}

func (s *Source) prefixFor(a netip.Addr) netip.Prefix {
	s.mu.RLock()
	fn := s.lookup
	s.mu.RUnlock()
	if fn != nil {
		if p, ok := fn(a); ok && p.IsValid() && p.Bits() > 0 && p.Contains(a) {
			return p.Masked()
		}
	}
	bits := s.agg4
	if a.Is6() {
		bits = s.agg6
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// Problems returns the current problem prefixes, worst first.
func (s *Source) Problems() []passive.Problem {
	now := s.now()
	s.trk.sweep(now)
	return s.win.Problems(now, s.th, s.maxTargets)
}

// Targets returns the problem prefixes, worst first, capped at
// max_targets. Weight is the problem score. A prefix is urgent on the
// first call that returns it. Quiet traffic returns an empty list.
func (s *Source) Targets(ctx context.Context) ([]plugin.Target, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ps := s.Problems()
	isNew := s.fresh.Mark(ps)
	out := make([]plugin.Target, 0, len(ps))
	for i, p := range ps {
		t := plugin.Target{Prefix: p.Prefix, Weight: p.Score, Urgent: isNew[i]}
		if p.Host.IsValid() && p.Prefix.Contains(p.Host) {
			t.Host = p.Host
		}
		if isNew[i] {
			c := p.Counts
			s.log.Info("span problem prefix", "prefix", p.Prefix, "host", t.Host, "reasons", strings.Join(p.Reasons, ","),
				"score", p.Score, "flows", c.Flows, "timeouts", c.Timeouts, "resets", c.Resets,
				"segments", c.Segments, "retrans", c.Retrans, "rtt_avg", c.RTTAvg())
		}
		out = append(out, t)
	}
	return out, nil
}
