package config

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
)

// offload_aware run levels (#735).
const (
	OffloadRunDryRun  = "dry_run"
	OffloadRunEnforce = "enforce"
)

// offload_aware defaults and bounds (#735).
const (
	DefaultOffloadRecheck    = 5 * time.Minute
	MinOffloadRecheck        = 10 * time.Second
	MaxOffloadRecheck        = time.Hour
	DefaultOffloadReservePct = 10
	MaxOffloadReservePct     = 50
	MaxOffloadCapacity       = 100_000_000
	OffloadReaderStatic      = "static"
	OffloadReaderRouterOS    = "routeros"
)

// offloadProfiles resolves router profiles. Tests replace it to register a
// profile that allows dry_run or enforce; the shipped registry has only
// platforms that stop at report or refuse.
var offloadProfiles = offload.NewRegistry()

// offloadChecks holds each registered profile's check of its routers' own
// settings (model, login), run while the block is enabled.
var offloadChecks = map[string]func(OffloadRouter) error{}

var offloadReaders = map[string]bool{OffloadReaderStatic: true, OffloadReaderRouterOS: true, "snmp": true}

// RegisterOffloadProfile adds a profile to the shipped registry, with the
// check of the router settings that profile needs. A profile package calls
// it from init.
func RegisterOffloadProfile(p offload.Profile, check func(OffloadRouter) error) {
	if err := offloadProfiles.Register(p); err != nil {
		panic(err)
	}
	offloadChecks[p.ID] = check
}

// OffloadAware is the opt-in hardware-offload-aware mode (#735). Nil or
// disabled is off. At dry_run it reads the routers and reports what it would
// do (#738) and changes nothing. A profile never changes mode: enforce still
// needs mode: inject.
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
	// Profile is the ID of a registered internal/offload profile. Its MaxRun
	// is the highest run level the router may reach. Required.
	Profile string `yaml:"profile"`
	// Reader is how the offloaded-route count is read: static, routeros, or
	// snmp. Empty is static.
	Reader string `yaml:"reader"`
	// Capacity is the router's hardware route capacity, in routes. It is
	// required for the static reader; the routeros reader reads it from the
	// router.
	Capacity int `yaml:"capacity"`
	// ReservePct is the share of Capacity kept free. Zero is the default.
	ReservePct int `yaml:"reserve_pct"`
	// OffloadCommunity, when set, is the community that marks a route for
	// hardware offload on this router, as asn:value or a large community.
	OffloadCommunity string `yaml:"offload_community"`
	// IPv6Offload says the router offloads IPv6 routes. MikroTik's ipv6-hw
	// is off by default, so this is false unless set.
	IPv6Offload bool `yaml:"ipv6_offload"`
	// Model names the router's switch chip for the profile, for example
	// ccr2216. Empty is unknown.
	Model string `yaml:"model,omitempty"`
	// VolumeSource names a sources entry that reports per-prefix traffic
	// from a device that sees hardware-forwarded traffic (sFlow or IPFIX).
	// Empty means none: RouterOS Traffic-Flow does not see that traffic.
	VolumeSource string `yaml:"volume_source,omitempty"`
	// URL, UsernameEnv, PasswordEnv and CAFile are the RouterOS REST login of
	// the routeros reader, as in preflight.router_check. The credentials are
	// read from the named environment variables, never from the file.
	URL         string `yaml:"url,omitempty"`
	UsernameEnv string `yaml:"username_env,omitempty"`
	PasswordEnv string `yaml:"password_env,omitempty"`
	CAFile      string `yaml:"ca_file,omitempty"`
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
		prof, err := offloadProfiles.Get(r.Profile)
		switch {
		case r.Profile == "":
			add("%s.profile is required (one of %v)", p, offloadProfiles.IDs())
		case err != nil:
			add("%s.profile: %v (one of %v)", p, err, offloadProfiles.IDs())
		case o.Enabled:
			level := offload.DryRun
			if run == OffloadRunEnforce {
				level = offload.Enforce
			}
			if _, err := offload.CheckRun(prof, level); err != nil {
				add("%s: %v", p, err)
			}
		}
		if !offloadReaders[r.Reader] {
			add("%s.reader: unknown reader %q", p, r.Reader)
		}
		if r.Reader == OffloadReaderStatic && r.Capacity < 1 || r.Capacity < 0 || r.Capacity > MaxOffloadCapacity {
			add("%s.capacity %d must be between 1 and %d (0 only with a reader that reads it from the router)", p, r.Capacity, MaxOffloadCapacity)
		}
		if r.ReservePct < 1 || r.ReservePct > MaxOffloadReservePct {
			add("%s.reserve_pct %d must be between 1 and %d (0 is the default %d)", p, r.ReservePct, MaxOffloadReservePct, DefaultOffloadReservePct)
		}
		if r.VolumeSource != "" && !slices.ContainsFunc(c.Sources, func(s PluginSpec) bool { return s.InstanceName() == r.VolumeSource }) {
			add("%s.volume_source: %q is not a sources entry", p, r.VolumeSource)
		}
		if check := offloadChecks[r.Profile]; check != nil && o.Enabled {
			if err := check(r); err != nil {
				add("%s: %v", p, err)
			}
		}
		if r.OffloadCommunity != "" {
			if _, err := CommunityText(r.OffloadCommunity); err != nil {
				add("%s.offload_community: %v", p, err)
			}
		}
	}
}
