package main

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pin"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// pinControl is the API's handle on prefix pins (#558). A new pin is
// checked against the running config's providers and allowlist and the
// learned RIB view; Decide then treats it as a static rule.
type pinControl struct {
	store *pin.Store
	cfg   func() *config.Config
	// learned reports whether the exact prefix is in the RIB view. Nil
	// when there is no RIB view, which refuses every pin.
	learned func(netip.Prefix) bool
	log     *slog.Logger
	poke    func()
}

func (c pinControl) List(now time.Time) []pin.Pin { return c.store.List(now) }

func (c pinControl) Add(r pin.Request, now time.Time) (pin.Pin, error) {
	rails := pin.Rails{Learned: c.learned}
	if cfg := c.cfg(); cfg != nil {
		for _, p := range cfg.Providers {
			rails.Providers = append(rails.Providers, p.Name)
		}
		for _, s := range cfg.Allowlist.Prefixes {
			if p, err := netip.ParsePrefix(s); err == nil {
				rails.Allowlist = append(rails.Allowlist, p)
			}
		}
	}
	p, err := c.store.Add(r, rails, now)
	if err != nil {
		return p, err
	}
	c.log.Info("prefix pinned through the API", "id", p.ID, "prefix", p.Prefix, "provider", p.Provider, "expires", p.Expires, "by", p.By)
	c.poke()
	return p, nil
}

func (c pinControl) Remove(id string) bool {
	p, ok := c.store.Remove(id)
	if !ok {
		return false
	}
	c.log.Info("prefix pin removed through the API", "id", id, "prefix", p.Prefix)
	c.poke()
	return true
}

// applyPins puts each probed prefix's pin into the round's policy verdicts
// ahead of the policy chain: an operator's pin is the newer intent.
func applyPins(in *policy.Input, pins *pin.Store, now time.Time) {
	v := pins.Verdicts(now)
	if len(v) == 0 {
		return
	}
	for _, r := range in.Results {
		pv, ok := v[r.Prefix]
		if !ok {
			continue
		}
		if in.Policies == nil {
			in.Policies = map[netip.Prefix]plugin.PolicyVerdict{}
		}
		in.Policies[r.Prefix] = pv
	}
}

// optimizationControl pauses and resumes the decision engine (#558). The
// state is in memory: a restart resumes.
type optimizationControl struct {
	decider *policy.Engine
	log     *slog.Logger
	poke    func()

	mu sync.Mutex
	st httpapi.Pause
}

func (c *optimizationControl) State() httpapi.Pause {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

func (c *optimizationControl) Pause(by, reason string, now time.Time) (httpapi.Pause, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Paused {
		return c.st, false
	}
	c.st = httpapi.Pause{Paused: true, By: by, Reason: reason, Since: now.UTC()}
	c.decider.SetPaused(true)
	c.log.Warn("optimization paused through the API; every improvement is withdrawn", "by", by, "reason", reason)
	c.poke()
	return c.st, true
}

func (c *optimizationControl) Resume() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Paused {
		return false
	}
	c.st = httpapi.Pause{}
	c.decider.SetPaused(false)
	c.log.Info("optimization resumed through the API")
	c.poke()
	return true
}
