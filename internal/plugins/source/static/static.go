// Package static implements the "static" target source: a fixed list of
// prefixes from config, each with an optional representative host.
package static

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "static"

func init() { plugin.Sources.Register(TypeName, New) }

// Config is the static source's config block.
type Config struct {
	Targets []struct {
		Prefix string  `yaml:"prefix"`
		Host   string  `yaml:"host"`
		Weight float64 `yaml:"weight"`
	} `yaml:"targets"`
}

// Source returns a fixed target list.
type Source struct {
	plugin.Base
	targets []plugin.Target
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
		s.targets = append(s.targets, tg)
	}
	return s, nil
}

// Targets implements plugin.TargetSource.
func (s *Source) Targets(context.Context) ([]plugin.Target, error) {
	out := make([]plugin.Target, len(s.targets))
	copy(out, s.targets)
	return out, nil
}
