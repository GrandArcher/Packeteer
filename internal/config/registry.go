package config

import (
	"cmp"
	"regexp"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/registry"
)

// Registry is registry hygiene (#289): a scheduled, read-only comparison of
// the learned RIB with IRR, RPKI, the as-set, and PeeringDB. Pushing a
// change is a separate switch, off by default. It never announces.
type Registry struct {
	// Enabled turns the scan on. False builds nothing.
	Enabled bool `yaml:"enabled"`
	// ASNs are the origin ASNs the network announces. A learned route is
	// the network's when its origin is one of them.
	ASNs []uint32 `yaml:"asns"`
	// ASSet is the operator's as-set, checked against the ASNs seen after
	// ASNs on learned paths. Optional.
	ASSet string `yaml:"as_set"`
	// Interval is the time between scans (default 24h).
	Interval time.Duration `yaml:"interval"`
	// HeadroomPercent is added to the announced prefix counts when a
	// PeeringDB max-prefix value is suggested (default 20).
	HeadroomPercent int `yaml:"headroom_percent"`
	// IRR names the database and maintainer written into generated route
	// objects.
	IRR RegistryIRR `yaml:"irr"`
	// PushEnabled allows POST /api/registry/push. Off by default; every
	// push still needs an admin and a confirmed diff.
	PushEnabled bool `yaml:"push_enabled"`
	// Sources are the registry plugins (peeringdb, ripe).
	Sources []PluginSpec `yaml:"sources"`
}

// RegistryIRR is the RPSL source: and mnt-by: of generated objects.
type RegistryIRR struct {
	Source string `yaml:"source"`
	MntBy  string `yaml:"mnt_by"`
}

var (
	rpslSource = regexp.MustCompile(`^[A-Z0-9][A-Z0-9_-]{0,31}$`)
	rpslMntner = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$`)
)

// RegistryOn reports whether registry hygiene is on.
func (c *Config) RegistryOn() bool { return c.Registry != nil && c.Registry.Enabled }

func (c *Config) normalizeRegistry() {
	r := c.Registry
	if r == nil {
		return
	}
	for i := range r.Sources {
		r.Sources[i].Type = strings.TrimSpace(r.Sources[i].Type)
	}
	if !r.Enabled {
		return
	}
	if r.Interval == 0 {
		r.Interval = registry.DefaultInterval
	}
	if r.HeadroomPercent == 0 {
		r.HeadroomPercent = registry.DefaultHeadroom
	}
	r.IRR.Source = strings.ToUpper(strings.TrimSpace(r.IRR.Source))
	if r.IRR.Source == "" {
		r.IRR.Source = "RIPE"
	}
}

func (c *Config) validateRegistry(add func(string, ...any)) {
	r := c.Registry
	if r == nil {
		return
	}
	if !r.Enabled {
		if len(r.ASNs) > 0 || r.ASSet != "" || r.Interval != 0 || r.HeadroomPercent != 0 || r.IRR != (RegistryIRR{}) || r.PushEnabled || len(r.Sources) > 0 {
			add("registry.enabled is false but another registry setting is set")
		}
		return
	}
	if len(r.ASNs) == 0 {
		add("registry.asns: at least one origin ASN is required when registry.enabled")
	}
	for i, a := range r.ASNs {
		if a == 0 {
			add("registry.asns[%d]: 0 is not an AS number", i)
		}
	}
	if r.ASSet != "" && !irr.ValidASSetName(r.ASSet) {
		add("registry.as_set: %q is not an as-set name (for example AS-EXAMPLE)", r.ASSet)
	}
	if r.Interval < registry.MinInterval || r.Interval > registry.MaxInterval {
		add("registry.interval %s must be between %s and %s", r.Interval, registry.MinInterval, registry.MaxInterval)
	}
	if r.HeadroomPercent < 1 || r.HeadroomPercent > registry.MaxHeadroom {
		add("registry.headroom_percent %d must be between 1 and %d", r.HeadroomPercent, registry.MaxHeadroom)
	}
	if !rpslSource.MatchString(r.IRR.Source) {
		add("registry.irr.source %q is not an IRR database name (for example RIPE)", r.IRR.Source)
	}
	if r.IRR.MntBy != "" && !rpslMntner.MatchString(r.IRR.MntBy) {
		add("registry.irr.mnt_by %q is not a maintainer name", r.IRR.MntBy)
	}
	names := map[string]bool{}
	hasRIPE := false
	for i, s := range r.Sources {
		if s.Type == "" {
			add("registry.sources[%d]: type is required", i)
			continue
		}
		if s.Type == "ripe" {
			hasRIPE = true
			var rc struct {
				Source string `yaml:"source"`
			}
			if s.Config.Decode(&rc) == nil && r.PushEnabled && (r.IRR.Source == "RIPE" || r.IRR.Source == "TEST") {
				if got := strings.ToUpper(cmp.Or(rc.Source, "RIPE")); got != r.IRR.Source {
					add("registry.sources[%d]: the ripe source writes to %s and registry.irr.source is %s; set both to the same database", i, got, r.IRR.Source)
				}
			}
		}
		if n := s.InstanceName(); names[n] {
			add("registry.sources[%d]: name %q is used twice; set name", i, n)
		} else {
			names[n] = true
		}
	}
	if r.PushEnabled && len(r.Sources) == 0 {
		add("registry.push_enabled needs at least one registry.sources entry to push to")
	}
	if r.PushEnabled && hasRIPE && r.IRR.MntBy == "" {
		add("registry.irr.mnt_by is required to push route objects through a ripe source")
	}
	if c.IXP != nil {
		add("registry cannot be combined with ixp: IXP mode is observe-only and has no learned RIB of its own routes")
	}
}
