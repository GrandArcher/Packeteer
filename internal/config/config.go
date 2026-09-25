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
	"net"
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

	DefaultProbeWorkers              = 8
	MaxProbeWorkers                  = 1024
	DefaultProbeRateLimitPPS         = 100
	MaxProbeRateLimitPPS             = 100000
	DefaultProbePerTargetConcurrency = 2
	MaxProbePerTargetConcurrency     = 64

	// DefaultHTTPListen is the read-only ops server. Loopback keeps the
	// dashboard off the network unless the operator opts in.
	DefaultHTTPListen = "127.0.0.1:8080"
)

// Config is the top-level controller configuration.
type Config struct {
	Mode               string `yaml:"mode"`
	ASN                uint32 `yaml:"asn"`
	RouterID           string `yaml:"router_id"`
	PacketeerCommunity string `yaml:"packeteer_community"`
	// LocalPref is set on every injected route. Required when mode is inject.
	LocalPref uint32 `yaml:"local_pref"`
	// MoreSpecificBits is accepted only so a leftover more_specific_bits key
	// fails closed. Any value, including 0, is an error. Packeteer announces
	// the exact prefix learned from the RIB.
	MoreSpecificBits *int          `yaml:"more_specific_bits"`
	MaxImprovements  *int          `yaml:"max_improvements"`
	HoldTime         time.Duration `yaml:"hold_time"`
	// ImprovementTTL retires an improvement after this long so the native
	// path is re-measured (default 1h; negative disables).
	ImprovementTTL time.Duration `yaml:"improvement_ttl"`
	Thresholds     Thresholds    `yaml:"thresholds"`
	Providers      []Provider    `yaml:"providers"`
	Allowlist      Allowlist     `yaml:"allowlist"`
	Probe          Probe         `yaml:"probe"`

	// Log is the process logger. Environment variables override it.
	Log Log `yaml:"log"`
	// HTTP is the read-only ops server. A nil Listen means the default
	// until defaults are applied. After Parse, Listen is non-nil and an
	// empty string disables the server.
	HTTP HTTP `yaml:"http"`

	// BGP holds the iBGP sessions to the edge routers (RIB view, #6).
	BGP BGP `yaml:"bgp"`

	// Plugins. Each entry selects an implementation by type; see
	// docs/PLUGINS.md. Plugin-specific settings live under `config` and are
	// validated by the plugin itself when the plugin set is built.
	PluginDir string       `yaml:"plugin_dir"`
	Probers   []PluginSpec `yaml:"probers"`
	Sources   []PluginSpec `yaml:"sources"`
	Scorer    *PluginSpec  `yaml:"scorer"`
	Announcer *PluginSpec  `yaml:"announcer"`
	Notifiers []PluginSpec `yaml:"notifiers"`
	// Telemetry collects per-provider interface usage. It does not announce.
	Telemetry []PluginSpec `yaml:"telemetry"`
}

// Log configures slog output.
type Log struct {
	// Level is debug, info, warn, or error.
	Level string `yaml:"level"`
	// Format is text or json.
	Format string `yaml:"format"`
}

// HTTP is the read-only health, metrics, API, and dashboard server.
type HTTP struct {
	// Listen is host:port. Nil means "apply the default". A pointer to
	// an empty string disables the server (http.listen: "").
	Listen *string `yaml:"listen"`
}

// HTTPListen is the address to bind, or "" when the server is disabled.
func (c *Config) HTTPListen() string {
	if c == nil || c.HTTP.Listen == nil {
		return DefaultHTTPListen
	}
	return *c.HTTP.Listen
}

// BGP configures the embedded BGP speaker.
type BGP struct {
	// ListenPort accepts sessions from routers (e.g. 179). 0 = do not
	// listen; Packeteer connects out to each neighbor instead.
	ListenPort      int           `yaml:"listen_port"`
	ListenAddresses []string      `yaml:"listen_addresses"`
	Neighbors       []BGPNeighbor `yaml:"neighbors"`
}

// BGPNeighbor is an edge router peered over iBGP (same ASN as asn).
type BGPNeighbor struct {
	Address      string `yaml:"address"`
	Port         int    `yaml:"port"`          // remote port, default 179
	LocalAddress string `yaml:"local_address"` // optional session source
	Passive      bool   `yaml:"passive"`       // wait for the router to connect
	Description  string `yaml:"description"`
}

// PluginSpec selects one plugin instance.
type PluginSpec struct {
	Type   string    `yaml:"type"`
	Name   string    `yaml:"name"`
	Config yaml.Node `yaml:"config"`
}

// InstanceName is Name, or Type when no name is set.
func (p PluginSpec) InstanceName() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Type
}

// DefaultImprovementTTL is how long an improvement lives before re-evaluation.
const DefaultImprovementTTL = time.Hour

// DefaultPluginDir is where out-of-process plugins are looked up.
const DefaultPluginDir = "/etc/packeteer/plugins"

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
	// Exclude keeps the provider measured but never chosen for an improvement.
	Exclude bool `yaml:"exclude"`
	// Group is an optional load-balancing group. Empty means the provider
	// is not in a group. Commit control balances only inside a group, and
	// only when the commit scorer's balance mode is not off.
	Group string `yaml:"group"`
	// Precedence is the commit-control preference. Lower is preferred.
	// 0 means the default of 100. The highest precedence is a last resort:
	// it receives commit traffic only when every lower precedence lacks room.
	Precedence int `yaml:"precedence"`
	// CCDisable leaves this provider out of commit control. Performance
	// improvements can still select it unless Exclude is set.
	CCDisable bool `yaml:"cc_disable"`
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
	// Workers is the number of concurrent probe runs.
	Workers int `yaml:"workers"`
	// RateLimitPPS caps the global probe packet rate (packets per second).
	RateLimitPPS int `yaml:"rate_limit_pps"`
	// PerTargetConcurrency caps concurrent probe runs toward one host.
	PerTargetConcurrency int `yaml:"per_target_concurrency"`
	// RetryLossPct, when greater than zero, re-probes a path with
	// RetryPackets before the result is stored if its loss is at least
	// this percent. Zero disables retry.
	RetryLossPct float64 `yaml:"retry_loss_pct"`
	// RetryPackets is the packet count of that second probe. Zero means
	// three times packets when retry is enabled, and is otherwise unused.
	RetryPackets int `yaml:"retry_packets"`
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
	if c.Probe.Workers == 0 {
		c.Probe.Workers = DefaultProbeWorkers
	}
	if c.Probe.RateLimitPPS == 0 {
		c.Probe.RateLimitPPS = DefaultProbeRateLimitPPS
	}
	if c.Probe.PerTargetConcurrency == 0 {
		c.Probe.PerTargetConcurrency = DefaultProbePerTargetConcurrency
	}
	if c.Probe.RetryLossPct > 0 && c.Probe.RetryPackets == 0 {
		n := c.Probe.Packets * 3
		if n < 1 {
			n = DefaultProbePackets * 3
		}
		if n > MaxProbePackets {
			n = MaxProbePackets
		}
		c.Probe.RetryPackets = n
	}
	if len(c.Probers) == 0 {
		// ICMP echo with TCP-SYN (port 443) fallback.
		c.Probers = []PluginSpec{{Type: "icmp"}, {Type: "tcp"}}
	}
	if c.PluginDir == "" {
		c.PluginDir = DefaultPluginDir
	}
	if c.Scorer == nil {
		c.Scorer = &PluginSpec{Type: "weighted"}
	}
	if c.ImprovementTTL == 0 {
		c.ImprovementTTL = DefaultImprovementTTL
	}
	if strings.TrimSpace(c.Log.Level) == "" {
		c.Log.Level = "info"
	}
	if strings.TrimSpace(c.Log.Format) == "" {
		c.Log.Format = "text"
	}
	if c.HTTP.Listen == nil {
		s := DefaultHTTPListen
		c.HTTP.Listen = &s
	}
}

// Validate checks the config and returns all problems found, joined.
func (c *Config) Validate() error {
	c.normalize()
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
		if !validProviderGroup(p.Group) {
			add("%s: group %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", label, p.Group)
		}
		if p.Precedence < 0 || p.Precedence > 10000 {
			add("%s: precedence %d must be between 0 and 10000 (0 means the default 100)", label, p.Precedence)
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
	if c.Probe.RetryLossPct < 0 || c.Probe.RetryLossPct > 100 {
		add("probe.retry_loss_pct %v must be between 0 and 100", c.Probe.RetryLossPct)
	}
	if c.Probe.RetryPackets < 0 || c.Probe.RetryPackets > MaxProbePackets {
		add("probe.retry_packets %d must be between 0 and %d", c.Probe.RetryPackets, MaxProbePackets)
	}

	if c.BGP.ListenPort < 0 || c.BGP.ListenPort > 65535 {
		add("bgp.listen_port %d must be between 0 and 65535", c.BGP.ListenPort)
	}
	for i, a := range c.BGP.ListenAddresses {
		if _, err := netip.ParseAddr(a); err != nil {
			add("bgp.listen_addresses[%d]: %q is not a valid IP address", i, a)
		}
	}
	nbrs := map[netip.Addr]bool{}
	for i, n := range c.BGP.Neighbors {
		label := fmt.Sprintf("bgp.neighbors[%d]", i)
		a, err := netip.ParseAddr(n.Address)
		if err != nil {
			add("%s: address %q is not a valid IP address", label, n.Address)
		} else {
			if nbrs[a] {
				add("%s: duplicate neighbor %s", label, a)
			}
			nbrs[a] = true
		}
		if n.Port < 0 || n.Port > 65535 {
			add("%s: port %d must be between 0 and 65535", label, n.Port)
		}
		if n.LocalAddress != "" {
			if _, err := netip.ParseAddr(n.LocalAddress); err != nil {
				add("%s: local_address %q is not a valid IP address", label, n.LocalAddress)
			}
		}
		if n.Passive && c.BGP.ListenPort == 0 {
			add("%s: passive requires bgp.listen_port", label)
		}
	}

	validateSpecs := func(field string, specs []PluginSpec) {
		seen := map[string]bool{}
		for i, sp := range specs {
			if sp.Type == "" {
				add("%s[%d]: type is required", field, i)
				continue
			}
			n := sp.InstanceName()
			if seen[n] {
				add("%s[%d]: duplicate instance name %q (set a unique name)", field, i, n)
			}
			seen[n] = true
		}
	}
	validateSpecs("probers", c.Probers)
	validateSpecs("sources", c.Sources)
	validateSpecs("notifiers", c.Notifiers)
	validateSpecs("telemetry", c.Telemetry)
	if c.Scorer != nil && c.Scorer.Type == "" {
		add("scorer: type is required")
	}
	if c.Announcer != nil && c.Announcer.Type == "" {
		add("announcer: type is required")
	}

	if c.Probe.Workers < 1 || c.Probe.Workers > MaxProbeWorkers {
		add("probe.workers %d must be between 1 and %d", c.Probe.Workers, MaxProbeWorkers)
	}
	if c.Probe.RateLimitPPS < 1 || c.Probe.RateLimitPPS > MaxProbeRateLimitPPS {
		add("probe.rate_limit_pps %d must be between 1 and %d", c.Probe.RateLimitPPS, MaxProbeRateLimitPPS)
	}
	if c.Probe.PerTargetConcurrency < 1 || c.Probe.PerTargetConcurrency > MaxProbePerTargetConcurrency {
		add("probe.per_target_concurrency %d must be between 1 and %d", c.Probe.PerTargetConcurrency, MaxProbePerTargetConcurrency)
	}

	switch c.Log.Level {
	case "debug", "info", "warn", "warning", "error":
	default:
		add("log.level %q is invalid (want debug, info, warn, or error)", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		add("log.format %q is invalid (want text or json)", c.Log.Format)
	}
	if c.HTTP.Listen != nil {
		if err := validateListen(*c.HTTP.Listen); err != nil {
			add("http.listen: %v", err)
		}
	}

	// Inject mode has extra safety requirements (see AGENTS.md).
	if c.MoreSpecificBits != nil {
		add("more_specific_bits is removed: Packeteer announces only the exact prefix learned from the RIB")
	}

	if c.Mode == ModeInject {
		if len(c.Allowlist.Prefixes) == 0 {
			add("mode inject requires a non-empty allowlist.prefixes")
		}
		if len(c.BGP.Neighbors) == 0 {
			add("mode inject requires at least one bgp.neighbors entry")
		}
		if c.PacketeerCommunity == "" {
			add("mode inject requires packeteer_community to tag injected routes")
		}
		if c.LocalPref == 0 {
			add("mode inject requires local_pref (the local preference set on injected routes)")
		}
		if c.Announcer == nil {
			add("mode inject requires an announcer")
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

func (c *Config) normalize() {
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	c.Log.Format = strings.ToLower(strings.TrimSpace(c.Log.Format))
	for i := range c.Providers {
		c.Providers[i].Group = strings.TrimSpace(c.Providers[i].Group)
	}
	if c.HTTP.Listen != nil {
		s := strings.TrimSpace(*c.HTTP.Listen)
		c.HTTP.Listen = &s
	}
}

// validateListen accepts "" (disabled) or host:port. IPv6 addresses must
// be in brackets. The host is not resolved.
func validateListen(addr string) error {
	if addr == "" {
		return nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q must be host:port (wrap IPv6 in brackets, for example \"[2001:db8::1]:8080\")", addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%q port must be between 0 and 65535", addr)
	}
	return nil
}

// validProviderGroup accepts an empty group or a short token. Empty means
// the provider is not a member of a load-balancing group.
func validProviderGroup(s string) bool {
	if s == "" {
		return true
	}
	if len(s) > 64 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
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
