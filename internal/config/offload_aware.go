package config

import (
	"fmt"
	"net/netip"
	"time"
)

// offload_aware run levels (#735).
const (
	OffloadRunDryRun  = "dry_run"
	OffloadRunEnforce = "enforce"
)

// Offload_aware defaults and bounds (#735).
const (
	DefaultOffloadRecheck    = 5 * time.Minute
	MinOffloadRecheck        = 10 * time.Second
	MaxOffloadRecheck        = time.Hour
	DefaultOffloadReservePct = 10
	MaxOffloadReservePct     = 50
	MaxOffloadCapacity       = 100_000_000
	OffloadReaderStatic      = "static"
	DefaultOffloadProfile    = "generic"
)

// offloadMaxRun is the highest run level each router profile may reach. A
// profile without a hardware-offload reader stays at dry_run.
var offloadMaxRun = map[string]string{
	"generic":  OffloadRunDryRun,
	"mikrotik": OffloadRunEnforce,
}

var offloadReaders = map[string]bool{OffloadReaderStatic: true, "routeros": true, "snmp": true}

// OffloadAware is the opt-in hardware-offload-aware mode (#735). Only
// parsing and validation exist: nothing reads the block at runtime yet. Nil
// or disabled is off. A profile never changes mode: enforce still needs
// mode: inject.
type OffloadAware struct {
	Enabled bool `yaml:"enabled"`
	// Run is dry_run (the default) or enforce.
	Run string `yaml:"run"`
	// Recheck is how often a router's offload state is read again.
	Recheck time.Duration `yaml:"recheck"`
	// Routers lists the edge routers the mode watches. Each neighbor must
	// be a bgp.neighbors address.
	Routers []OffloadRouter `yaml:"routers"`
}

// OffloadRouter is one watched router.
type OffloadRouter struct {
	Neighbor string `yaml:"neighbor"`
	// Profile names the router family. It sets the highest run level the
	// router may reach. Empty is generic.
	Profile string `yaml:"profile"`
	// Reader is how the offloaded-route count is read: static, routeros, or
	// snmp. Empty is static.
	Reader string `yaml:"reader"`
	// Capacity is the router's hardware route capacity, in routes.
	Capacity int `yaml:"capacity"`
	// ReservePct is the share of Capacity kept free. Zero is the default.
	ReservePct int `yaml:"reserve_pct"`
	// OffloadCommunity, when set, is the community that marks a route for
	// hardware offload on this router, as asn:value or a large community.
	OffloadCommunity string `yaml:"offload_community"`
	// IPv6Offload says the router offloads IPv6 routes. MikroTik's ipv6-hw
	// is off by default, so this is false unless set.
	IPv6Offload bool `yaml:"ipv6_offload"`
}

// OffloadEnforcing reports whether offload_aware is on at run: enforce.
func (c *Config) OffloadEnforcing() bool {
	return c.OffloadAware != nil && c.OffloadAware.Enabled && c.OffloadAware.Run == OffloadRunEnforce
}

func (o *OffloadAware) applyDefaults() {
	if o.Run == "" {
		o.Run = OffloadRunDryRun
	}
	if o.Recheck == 0 {
		o.Recheck = DefaultOffloadRecheck
	}
	for i := range o.Routers {
		r := &o.Routers[i]
		if r.Profile == "" {
			r.Profile = DefaultOffloadProfile
		}
		if r.Reader == "" {
			r.Reader = OffloadReaderStatic
		}
		if r.ReservePct == 0 {
			r.ReservePct = DefaultOffloadReservePct
		}
	}
}

func (c *Config) validateOffloadAware(add func(string, ...any)) {
	o := c.OffloadAware
	if o == nil {
		return
	}
	if c.IXP != nil {
		add("offload_aware cannot be combined with ixp: IXP mode is observe-only and has no router of its own to offload")
	}
	run := o.Run
	switch run {
	case OffloadRunDryRun, OffloadRunEnforce:
	default:
		add("offload_aware.run %q must be %s or %s", run, OffloadRunDryRun, OffloadRunEnforce)
	}
	if run == OffloadRunEnforce && c.Mode != ModeInject {
		add("offload_aware.run enforce requires mode: inject (a profile never changes mode)")
	}
	if o.Recheck < MinOffloadRecheck || o.Recheck > MaxOffloadRecheck {
		add("offload_aware.recheck %s must be between %s and %s", o.Recheck, MinOffloadRecheck, MaxOffloadRecheck)
	}
	if o.Enabled && len(o.Routers) == 0 {
		add("offload_aware.routers: at least one router is required while enabled")
	}
	neighbors := map[netip.Addr]bool{}
	for _, n := range c.BGP.Neighbors {
		if a, err := netip.ParseAddr(n.Address); err == nil {
			neighbors[a] = true
		}
	}
	seen := map[netip.Addr]bool{}
	for i, r := range o.Routers {
		p := fmt.Sprintf("offload_aware.routers[%d]", i)
		a, err := netip.ParseAddr(r.Neighbor)
		switch {
		case err != nil:
			add("%s.neighbor: %q is not an IP address", p, r.Neighbor)
		case !neighbors[a]:
			add("%s.neighbor: %s is not a bgp.neighbors address", p, a)
		case seen[a]:
			add("%s.neighbor: %s is listed twice", p, a)
		default:
			seen[a] = true
		}
		top, ok := offloadMaxRun[r.Profile]
		if !ok {
			add("%s.profile: unknown profile %q", p, r.Profile)
		} else if run == OffloadRunEnforce && top == OffloadRunDryRun {
			add("%s: run enforce is above the highest run level (%s) of profile %q", p, top, r.Profile)
		}
		if !offloadReaders[r.Reader] {
			add("%s.reader: unknown reader %q", p, r.Reader)
		}
		if r.Capacity < 1 || r.Capacity > MaxOffloadCapacity {
			add("%s.capacity %d must be between 1 and %d", p, r.Capacity, MaxOffloadCapacity)
		}
		if r.ReservePct < 1 || r.ReservePct > MaxOffloadReservePct {
			add("%s.reserve_pct %d must be between 1 and %d (0 is the default %d)", p, r.ReservePct, MaxOffloadReservePct, DefaultOffloadReservePct)
		}
		if r.OffloadCommunity != "" {
			if _, err := CommunityText(r.OffloadCommunity); err != nil {
				add("%s.offload_community: %v", p, err)
			}
		}
	}
}
