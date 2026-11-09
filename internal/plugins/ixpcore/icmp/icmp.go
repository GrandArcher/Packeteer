// Package icmp is the ixp.core prober (#167). It sends ICMP echo from this
// site to the address of each other site that ixp.core_links names, across
// the exchange core, and records loss, RTT, and jitter. It does not
// announce and it is not an input to Decide.
package icmp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"

	// The packet sender is the built-in icmp prober. Register it even when
	// the controller did not import the prober set on its own.
	_ "github.com/GrandArcher/Packeteer/internal/plugins/prober/icmp"
)

// TypeName is the config type.
const TypeName = "icmp"

// Defaults and bounds. A zero value in config selects the default.
const (
	DefaultInterval = time.Minute
	minInterval     = 10 * time.Second
	maxInterval     = time.Hour
	DefaultTimeout  = time.Second
	minTimeout      = 100 * time.Millisecond
	maxTimeout      = 5 * time.Second
	DefaultPackets  = 5
	maxPackets      = 20
)

// Config is the core prober's config block.
type Config struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Packets  int           `yaml:"packets"`
}

func init() { plugin.CoreProbes.Register(TypeName, New) }

// The controller stores the prober as a CoreProbe.
var _ plugin.CoreProbe = (*Prober)(nil)

// Prober is the icmp core prober.
type Prober struct {
	log      *slog.Logger
	sender   plugin.Prober
	interval time.Duration
	timeout  time.Duration
	packets  int
	now      func() time.Time

	mu     sync.Mutex
	links  []plugin.CoreLink
	view   plugin.CoreView
	cancel context.CancelFunc
	done   chan struct{}
}

// New validates the config. It does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.CoreProbe, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Interval < minInterval || cfg.Interval > maxInterval {
		return nil, fmt.Errorf("interval %s must be between %s and %s", cfg.Interval, minInterval, maxInterval)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout > maxTimeout {
		return nil, fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, minTimeout, maxTimeout)
	}
	if cfg.Packets == 0 {
		cfg.Packets = DefaultPackets
	}
	if cfg.Packets < 1 || cfg.Packets > maxPackets {
		return nil, fmt.Errorf("packets %d must be between 1 and %d", cfg.Packets, maxPackets)
	}
	sender, err := plugin.Probers.New(TypeName, plugin.NewConfig(nil), env)
	if err != nil {
		return nil, err
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Prober{
		log: log, sender: sender, interval: cfg.Interval, timeout: cfg.Timeout, packets: cfg.Packets,
		view: plugin.CoreView{Configured: true, Links: []plugin.CoreLinkStatus{}},
	}, nil
}

// SetLinks records the links to measure. The controller calls it before Start.
func (p *Prober) SetLinks(l []plugin.CoreLink) {
	p.mu.Lock()
	p.links = append([]plugin.CoreLink(nil), l...)
	p.mu.Unlock()
}

// View returns the latest round.
func (p *Prober) View() plugin.CoreView {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.view
	v.Links = append([]plugin.CoreLinkStatus{}, v.Links...)
	return v
}

// Start begins the probe loop. It does not block.
func (p *Prober) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	p.mu.Lock()
	p.cancel, p.done = cancel, done
	p.mu.Unlock()
	go p.loop(ctx, done)
	return nil
}

// Stop cancels the loop and waits for it to leave.
func (p *Prober) Stop(ctx context.Context) error {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Prober) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		p.round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *Prober) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// round measures every link once. A cancelled round leaves the previous
// view in place.
func (p *Prober) round(ctx context.Context) {
	p.mu.Lock()
	links := append([]plugin.CoreLink(nil), p.links...)
	p.mu.Unlock()
	now := p.clock()
	out := make([]plugin.CoreLinkStatus, 0, len(links))
	for _, l := range links {
		if ctx.Err() != nil {
			return
		}
		out = append(out, p.measure(ctx, l, now))
	}
	if ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	p.view = plugin.CoreView{Configured: true, Round: now, Links: out}
	p.mu.Unlock()
	p.log.Info("ixp core round", "links", len(out))
}

func (p *Prober) measure(ctx context.Context, l plugin.CoreLink, now time.Time) plugin.CoreLinkStatus {
	s := plugin.CoreLinkStatus{Name: l.Name, Peer: l.Peer, Address: l.Address.String(), At: now}
	res, err := p.sender.Probe(ctx, plugin.ProbeRequest{
		Provider: l.Name, Source: l.Source, Target: l.Address, Count: p.packets, Timeout: p.timeout,
	})
	if err != nil {
		s.Error, s.Degraded = err.Error(), true
		return s
	}
	st := probe.Compute(res)
	s.Sent, s.LossPct = st.Sent, st.LossPct
	s.RTTMs = float64(st.RTTAvg) / float64(time.Millisecond)
	s.JitterMs = float64(st.Jitter) / float64(time.Millisecond)
	s.Up = st.Received > 0
	s.Degraded = !s.Up || st.LossPct > l.MaxLossPct || (l.MaxRTT > 0 && st.RTTAvg > l.MaxRTT)
	return s
}
