package httpapi

import (
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/portload"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Collector reads the live probe engine, decision engine, and RIB view.
// Attach and SetStarted may run while Snapshot is called.
type Collector struct {
	version   string
	mode      string
	providers []config.Provider

	mu          sync.RWMutex
	started     bool
	engine      *probe.Engine
	decider     *policy.Engine
	view        *rib.View
	telemetry   func() []plugin.Usage
	flowTracked func() int
	truncated   func() map[string]uint64
	exchanges   []exchange.Exchange
	hops        func() []rib.NextHopCount
	health      *exchange.Health
	peerPrefix  func() map[string]int
	rpki        func(netip.Prefix, uint32) plugin.RPKIAnswer
	portMaxAge  time.Duration
}

// NewCollector copies providers. The caller may reuse the slice afterward.
func NewCollector(version, mode string, providers []config.Provider) *Collector {
	return &Collector{
		version:   version,
		mode:      mode,
		providers: append([]config.Provider(nil), providers...),
	}
}

// Attach installs the live sources. A nil view means BGP is not configured.
func (c *Collector) Attach(engine *probe.Engine, decider *policy.Engine, view *rib.View) {
	c.mu.Lock()
	c.engine, c.decider, c.view = engine, decider, view
	c.mu.Unlock()
}

// SetFlowTracked installs the read of passively tracked flow prefixes
// (#125). Nil reports zero. The function may run while Snapshot is called.
func (c *Collector) SetFlowTracked(fn func() int) {
	c.mu.Lock()
	c.flowTracked = fn
	c.mu.Unlock()
}

// SetTruncated installs the read of the passive caps' truncation counts,
// by config key. Nil reports none. The function may run while Snapshot is
// called.
func (c *Collector) SetTruncated(fn func() map[string]uint64) {
	c.mu.Lock()
	c.truncated = fn
	c.mu.Unlock()
}

// SetTelemetry installs the read of interface usage. Nil leaves the
// telemetry list empty. The function may run while Snapshot is called.
func (c *Collector) SetTelemetry(fn func() []plugin.Usage) {
	c.mu.Lock()
	c.telemetry = fn
	c.mu.Unlock()
}

// SetExchanges installs the configured exchanges and the read of learned
// next hops on their peering LANs (#27). hops may be slow on a full table;
// the caller caches it.
func (c *Collector) SetExchanges(exs []exchange.Exchange, hops func() []rib.NextHopCount) {
	c.mu.Lock()
	c.exchanges, c.hops = exs, hops
	c.mu.Unlock()
}

// SetPortMaxAge sets how old a port's telemetry row may be before
// /api/exchanges reports it stale: the planning scorer's limit. Zero keeps
// the default.
func (c *Collector) SetPortMaxAge(d time.Duration) {
	c.mu.Lock()
	c.portMaxAge = d
	c.mu.Unlock()
}

// SetExchangeHealth installs the next-hop health of the exchange peers
// (#149). Nil leaves the peers' reachability unknown.
func (c *Collector) SetExchangeHealth(h *exchange.Health) {
	c.mu.Lock()
	c.health = h
	c.mu.Unlock()
}

// SetPeerPrefixes installs the read of each exchange peer's Adj-RIB-In
// route count from BMP statistics (#147). Nil leaves the counts at zero.
// The function may run while Snapshot is called.
func (c *Collector) SetPeerPrefixes(fn func() map[string]int) {
	c.mu.Lock()
	c.peerPrefix = fn
	c.mu.Unlock()
}

// SetRPKI installs the origin-validation lookup for learned paths (#158).
// Nil leaves every path without a validity label. The function is
// read-only and may run while Snapshot is called. Every snapshot labels
// every probed prefix's paths, so it must not ask the display fallback
// (#200); SetRPKIDisplay does that for /api/prefixes.
func (c *Collector) SetRPKI(fn func(netip.Prefix, uint32) plugin.RPKIAnswer) {
	c.mu.Lock()
	c.rpki = fn
	c.mu.Unlock()
}

// SetMode updates the mode Snapshot reports. A reload that changes mode
// calls it so the dashboard matches the running config.
func (c *Collector) SetMode(mode string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.mode = mode
	c.mu.Unlock()
}

// SetStarted marks process startup finished (or shutting down).
func (c *Collector) SetStarted(v bool) {
	c.mu.Lock()
	c.started = v
	c.mu.Unlock()
}

// Snapshot copies the current state. It looks up only prefixes that are
// already probed, decided, or improved, never the whole RIB. Exchange
// statistics read the next hop counts, which the caller caches.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	mode := c.mode
	started, engine, decider, view, telemetry := c.started, c.engine, c.decider, c.view, c.telemetry
	exs, hops, flowTracked, truncated := c.exchanges, c.hops, c.flowTracked, c.truncated
	health, peerPrefix, rpki, portMaxAge := c.health, c.peerPrefix, c.rpki, c.portMaxAge
	c.mu.RUnlock()

	in := Input{
		Version:   c.version,
		Mode:      mode,
		Started:   started,
		At:        time.Now().UTC(),
		Providers: c.providers,
		RPKI:      rpki,
	}
	if telemetry != nil {
		in.Telemetry = telemetry()
	}
	if engine != nil {
		in.Status = engine.Providers()
		in.Results = engine.Results()
		in.ProbePrefixCommits = engine.PrefixCommits()
	}
	if flowTracked != nil {
		in.FlowTracked = flowTracked()
	}
	if truncated != nil {
		in.Truncated = truncated()
	}
	if decider != nil {
		in.Decisions, in.DecidedAt = decider.Decisions()
		in.Improvements = decider.Improvements()
		in.Thresholds = decider.Thresholds()
		in.Quarantined = decider.Quarantined()
	}
	if view != nil {
		in.BGPConfigured = true
		in.RIBReady = view.Ready()
		in.RIBPrefixes = view.Len()
		in.Peers = view.Peers()
		in.Routes = map[netip.Prefix]rib.Route{}
		in.Paths = map[netip.Prefix][]rib.Route{}
		seen := map[netip.Prefix]struct{}{}
		consider := func(p netip.Prefix) {
			if !p.IsValid() {
				return
			}
			if _, ok := seen[p]; ok {
				return
			}
			seen[p] = struct{}{}
			if rt, ok := view.Exact(p); ok {
				in.Routes[p] = rt
			}
			if paths := view.Paths(p); len(paths) > 0 {
				in.Paths[p] = paths
			}
		}
		for _, r := range in.Results {
			consider(r.Prefix)
		}
		for _, d := range in.Decisions {
			consider(d.Prefix)
		}
		for _, im := range in.Improvements {
			consider(im.Prefix)
		}
	}
	if len(exs) > 0 {
		var nh []rib.NextHopCount
		if hops != nil {
			nh = hops()
		}
		up := map[string]bool{}
		for _, st := range in.Status {
			up[st.Name] = st.Up
		}
		imps := map[string][]exchange.Move{}
		for _, im := range in.Improvements {
			imps[im.Provider] = append(imps[im.Provider], exchange.Move{Prefix: im.Prefix.String(), Since: im.Since.UTC(), VolumeMbps: jsonFloat(im.VolumeMbps)})
		}
		in.Exchanges = exchange.Build(exs, nh, up, imps, health.Snapshot())
		if portMaxAge <= 0 {
			portMaxAge = portload.DefaultMaxAge
		}
		exchange.ApplyPorts(in.Exchanges, exs, in.Telemetry, in.At, portMaxAge)
		in.Telemetry = exchange.WithPortCommit(in.Telemetry, exchange.PortCommits(exs))
		if peerPrefix != nil {
			counts := peerPrefix()
			for i := range in.Exchanges {
				for j := range in.Exchanges[i].Peers {
					in.Exchanges[i].Peers[j].AdjRIBIn = counts[in.Exchanges[i].Peers[j].Name]
				}
			}
		}
	}
	in.ExchangeLANDrops = exchange.LANDrops()
	return Assemble(in)
}
