// Package config loads and validates the Packeteer controller configuration.
//
// Loading is pure: it reads a YAML file, rejects unknown fields, applies a
// small set of defaults, and validates the result. It never opens sockets,
// sends probes, or speaks BGP.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Operating modes.
const (
	ModeObserve = "observe"
	ModeSuggest = "suggest"
	ModeInject  = "inject"
)

// Defaults and bounds.
const (
	DefaultMaxImprovements = 50
	MaxImprovementsLimit   = 10000

	DefaultProbeInterval = 30 * time.Second
	DefaultProbeTimeout  = 2 * time.Second
	DefaultProbePackets  = 10
	MaxProbePackets      = 1000
)

// Config is the top-level controller configuration.
type Config struct {
	Mode               string        `yaml:"mode"`
	ASN                uint32        `yaml:"asn"`
	RouterID           string        `yaml:"router_id"`
	PacketeerCommunity string        `yaml:"packeteer_community"`
	MaxImprovements    *int          `yaml:"max_improvements"`
	HoldTime           time.Duration `yaml:"hold_time"`
	Thresholds         Thresholds    `yaml:"thresholds"`
	Providers          []Provider    `yaml:"providers"`
	Allowlist          Allowlist     `yaml:"allowlist"`
	Probe              Probe         `yaml:"probe"`
}

// Thresholds are the minimum improvements required before a path flip.
type Thresholds struct {
	MinLossDeltaPct float64 `yaml:"min_loss_delta_pct"`
	MinRTTDeltaMs   float64 `yaml:"min_rtt_delta_ms"`
}

// Provider is one upstream transit that probes are sourced through.
type Provider struct {
	Name     string `yaml:"name"`
	SourceIP string `yaml:"source_ip"`
	NextHop  string `yaml:"next_hop"`
}

// Allowlist restricts which prefixes may ever be injected.
type Allowlist struct {
	Prefixes []string `yaml:"prefixes"`
}

// Probe holds probe timing settings.
type Probe struct {
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Packets  int           `yaml:"packets"`
}

// Load reads, parses, defaults, and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes YAML bytes strictly, applies defaults, and validates.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("config is empty")
		}
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse yaml: expected a single YAML document")
	}

	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.MaxImprovements == nil {
		n := DefaultMaxImprovements
		c.MaxImprovements = &n
	}
	if c.Probe.Interval == 0 {
		c.Probe.Interval = DefaultProbeInterval
	}
	if c.Probe.Timeout == 0 {
		c.Probe.Timeout = DefaultProbeTimeout
	}
	if c.Probe.Packets == 0 {
		c.Probe.Packets = DefaultProbePackets
	}
}

// Validate checks the config and returns all problems found, joined.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	switch c.Mode {
	case "":
		add("mode is required (one of %s, %s, %s)", ModeObserve, ModeSuggest, ModeInject)
	case ModeObserve, ModeSuggest, ModeInject:
	default:
		add("mode %q is invalid (want one of %s, %s, %s)", c.Mode, ModeObserve, ModeSuggest, ModeInject)
	}

	if c.ASN == 0 {
		add("asn is required and must be non-zero")
	}

	if c.RouterID == "" {
		add("router_id is required")
	} else if a, err := netip.ParseAddr(c.RouterID); err != nil || !a.Is4() {
		add("router_id %q must be an IPv4 address", c.RouterID)
	}

	if c.PacketeerCommunity != "" {
		if err := validateCommunity(c.PacketeerCommunity); err != nil {
			add("packeteer_community %q: %v", c.PacketeerCommunity, err)
		}
	}

	if c.MaxImprovements != nil {
		if n := *c.MaxImprovements; n < 1 || n > MaxImprovementsLimit {
			add("max_improvements %d must be between 1 and %d", n, MaxImprovementsLimit)
		}
	}

	if c.HoldTime < 0 {
		add("hold_time %s must not be negative", c.HoldTime)
	}

	if c.Thresholds.MinLossDeltaPct < 0 || c.Thresholds.MinLossDeltaPct > 100 {
		add("thresholds.min_loss_delta_pct %v must be between 0 and 100", c.Thresholds.MinLossDeltaPct)
	}
	if c.Thresholds.MinRTTDeltaMs < 0 {
		add("thresholds.min_rtt_delta_ms %v must not be negative", c.Thresholds.MinRTTDeltaMs)
	}

	if len(c.Providers) == 0 {
		add("providers: at least one provider is required")
	}
	names := map[string]bool{}
	sources := map[netip.Addr]bool{}
	for i, p := range c.Providers {
		label := fmt.Sprintf("providers[%d]", i)
		if p.Name == "" {
			add("%s: name is required", label)
		} else {
			label = fmt.Sprintf("providers[%d] (%s)", i, p.Name)
			if names[p.Name] {
				add("%s: duplicate provider name", label)
			}
			names[p.Name] = true
		}
		src, err := netip.ParseAddr(p.SourceIP)
		if err != nil {
			add("%s: source_ip %q is not a valid IP address", label, p.SourceIP)
		} else {
			if sources[src] {
				add("%s: duplicate source_ip %s", label, src)
			}
			sources[src] = true
		}
		nh, err := netip.ParseAddr(p.NextHop)
		if err != nil {
			add("%s: next_hop %q is not a valid IP address", label, p.NextHop)
		} else if src.IsValid() && src.Is4() != nh.Is4() {
			add("%s: source_ip and next_hop must be the same address family", label)
		}
	}

	seen := map[netip.Prefix]bool{}
	for i, s := range c.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			add("allowlist.prefixes[%d]: %q is not a valid CIDR", i, s)
			continue
		}
		if p != p.Masked() {
			add("allowlist.prefixes[%d]: %q has host bits set (did you mean %s?)", i, s, p.Masked())
			continue
		}
		if seen[p] {
			add("allowlist.prefixes[%d]: duplicate prefix %s", i, p)
		}
		seen[p] = true
	}

	if c.Probe.Interval < 0 {
		add("probe.interval %s must be positive", c.Probe.Interval)
	}
	if c.Probe.Timeout < 0 {
		add("probe.timeout %s must be positive", c.Probe.Timeout)
	}
	if c.Probe.Interval > 0 && c.Probe.Timeout > 0 && c.Probe.Timeout >= c.Probe.Interval {
		add("probe.timeout %s must be shorter than probe.interval %s", c.Probe.Timeout, c.Probe.Interval)
	}
	if c.Probe.Packets < 1 || c.Probe.Packets > MaxProbePackets {
		add("probe.packets %d must be between 1 and %d", c.Probe.Packets, MaxProbePackets)
	}

	// Inject mode has extra safety requirements (see AGENTS.md).
	if c.Mode == ModeInject {
		if len(c.Allowlist.Prefixes) == 0 {
			add("mode inject requires a non-empty allowlist.prefixes")
		}
		if c.PacketeerCommunity == "" {
			add("mode inject requires packeteer_community to tag injected routes")
		}
		if c.HoldTime <= 0 {
			add("mode inject requires a positive hold_time")
		}
		if c.Thresholds.MinLossDeltaPct <= 0 || c.Thresholds.MinRTTDeltaMs <= 0 {
			add("mode inject requires positive thresholds.min_loss_delta_pct and thresholds.min_rtt_delta_ms")
		}
	}

	return errors.Join(errs...)
}

// validateCommunity checks a standard RFC 1997 community in "asn:value" form.
func validateCommunity(s string) error {
	hi, lo, ok := strings.Cut(s, ":")
	if !ok {
		return errors.New(`must be in "asn:value" form`)
	}
	for _, part := range []string{hi, lo} {
		if _, err := strconv.ParseUint(part, 10, 16); err != nil {
			return errors.New("each half must be an integer 0-65535")
		}
	}
	return nil
}
