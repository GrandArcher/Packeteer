// Package static implements the "static" target source: a fixed list of
// prefixes from config, each with an optional representative host.
package static

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "static"

func init() { plugin.Sources.Register(TypeName, New) }

// Source implements VolumeSource when a target sets mbps.
var _ plugin.VolumeSource = (*Source)(nil)

// maxMbps matches the telemetry commit cap. A larger declared rate is a
// typo, not a prefix Packeteer should steer.
const maxMbps = 100000000

// Config is the static source's config block.
type Config struct {
	Targets []Target `yaml:"targets"`
}

// Target is one configured prefix.
type Target struct {
	Prefix string  `yaml:"prefix"`
	Host   string  `yaml:"host"`
	Weight float64 `yaml:"weight"`
	// Mbps is an optional declared rate for commit control, decimal
	// megabits per second. Zero means this prefix has no volume.
	Mbps float64 `yaml:"mbps"`
}

// Source returns a fixed target list.
type Source struct {
	plugin.Base
	targets []plugin.Target
	vols    []plugin.PrefixVolume
}

// New is the plugin factory.
func New(c plugin.Config, _ plugin.Env) (plugin.TargetSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	s := &Source{}
	seen := map[netip.Prefix]bool{}
	for i, t := range cfg.Targets {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: prefix %q is not a valid CIDR", i, t.Prefix)
		}
		if p != p.Masked() {
			return nil, fmt.Errorf("targets[%d]: prefix %q has host bits set (did you mean %s?)", i, t.Prefix, p.Masked())
		}
		if seen[p] {
			return nil, fmt.Errorf("targets[%d]: duplicate prefix %s", i, p)
		}
		seen[p] = true
		tg := plugin.Target{Prefix: p, Weight: t.Weight}
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return nil, fmt.Errorf("targets[%d]: host %q must be an address inside %s", i, t.Host, p)
			}
			tg.Host = h
		}
		if t.Weight < 0 {
			return nil, fmt.Errorf("targets[%d]: weight must not be negative", i)
		}
		if math.IsNaN(t.Mbps) || math.IsInf(t.Mbps, 0) || t.Mbps < 0 || t.Mbps > maxMbps {
			return nil, fmt.Errorf("targets[%d]: mbps must be between 0 and 100000000", i)
		}
		s.targets = append(s.targets, tg)
		if t.Mbps > 0 {
			// Mbps() = bytes * 8 / seconds / 1e6. One second makes bytes
			// the rate in bits divided by 8.
			bytes := uint64(math.Round(t.Mbps * 1e6 / 8))
			if bytes > 0 {
				s.vols = append(s.vols, plugin.PrefixVolume{Prefix: p, Bytes: bytes, Window: time.Second})
			}
		}
	}
	return s, nil
}

// Volumes implements plugin.VolumeSource. Prefixes without mbps are omitted.
// This does not announce.
func (s *Source) Volumes(ctx context.Context) ([]plugin.PrefixVolume, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := make([]plugin.PrefixVolume, len(s.vols))
	copy(out, s.vols)
	return out, nil
}

// Targets implements plugin.TargetSource.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	out := make([]plugin.Target, len(s.targets))
	copy(out, s.targets)
	return out, nil
}
