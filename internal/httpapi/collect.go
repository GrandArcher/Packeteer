package httpapi

import (
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// Collector reads the live probe engine, decision engine, and RIB view.
// Attach and SetStarted may run while Snapshot is called.
type Collector struct {
	version   string
	mode      string
	providers []config.Provider

	mu      sync.RWMutex
	started bool
	engine  *probe.Engine
	decider *policy.Engine
	view    *rib.View
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

// SetStarted marks process startup finished (or shutting down).
func (c *Collector) SetStarted(v bool) {
	c.mu.Lock()
	c.started = v
	c.mu.Unlock()
}

// Snapshot copies the current state. It looks up only prefixes that are
// already probed, decided, or improved, never the whole RIB.
func (c *Collector) Snapshot() Snapshot {
	c.mu.RLock()
	started, engine, decider, view := c.started, c.engine, c.decider, c.view
	c.mu.RUnlock()

	in := Input{
		Version:   c.version,
		Mode:      c.mode,
		Started:   started,
		At:        time.Now().UTC(),
		Providers: c.providers,
	}
	if engine != nil {
		in.Status = engine.Providers()
		in.Results = engine.Results()
	}
	if decider != nil {
		in.Decisions, in.DecidedAt = decider.Decisions()
		in.Improvements = decider.Improvements()
	}
	if view != nil {
		in.BGPConfigured = true
		in.RIBReady = view.Ready()
		in.Peers = view.Peers()
		in.Routes = map[netip.Prefix]rib.Route{}
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
	return Assemble(in)
}
