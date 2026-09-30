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
	"maps"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
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
	// Exchanges are Internet exchanges whose peers are providers (#27).
	// Parse expands every peer into Providers, so the rest of the
	// controller sees each peer as a provider with its own next hop.
	Exchanges []Exchange `yaml:"exchanges"`
	Allowlist Allowlist  `yaml:"allowlist"`
	Probe     Probe      `yaml:"probe"`

	// Log is the process logger. Environment variables override it.
	Log Log `yaml:"log"`
	// HTTP is the read-only ops server. A nil Listen means the default
	// until defaults are applied. After Parse, Listen is non-nil and an
	// empty string disables the server.
	HTTP HTTP `yaml:"http"`

	// BGP holds the iBGP sessions to the edge routers (RIB view, #6).
	BGP BGP `yaml:"bgp"`
	// RIBSources feed the RIB view from outside the iBGP session (a BMP
	// station, #26). Learn-only: they never announce.
	RIBSources []PluginSpec `yaml:"rib_sources"`

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
	// Policies is the routing-policy chain (rules, maintenance windows),
	// asked in order before each decision. It does not announce.
	Policies []PluginSpec `yaml:"policies"`
	// Storage keeps report history (sqlite). Nil disables history and
	// reports. It does not announce.
	Storage *PluginSpec `yaml:"storage"`
	// Troubleshoot configures the read-only operator tools on the ops
	// HTTP server. They never announce.
	Troubleshoot Troubleshoot `yaml:"troubleshoot"`
	// Inbound is inbound commit control (#25). Nil disables it.
	Inbound *Inbound `yaml:"inbound"`
	// Mitigation is threat mitigation: RTBH and BGP redirect (#28). Nil
	// disables it.
	Mitigation *Mitigation `yaml:"mitigation"`
	// MoreSpecific announces, with each improvement, the more-specifics
	// inside its prefix that a neighbor advertises in the learned RIB
	// (#56, docs/design/more-specific.md). Nil or disabled is off.
	MoreSpecific *MoreSpecific `yaml:"more_specific"`

	// Instance and Domain name this instance and its routing domain (POP)
	// for multi-POP federation (#30). Instance defaults to Domain.
	Instance string `yaml:"instance"`
	Domain   string `yaml:"domain"`
	// InterDCRTT is the round-trip time from this domain to each other
	// domain. It is added to a path measured by a peer in that domain.
	InterDCRTT map[string]time.Duration `yaml:"inter_dc_rtt"`
	// GlobalCommits are commits shared by providers in several domains.
	GlobalCommits []GlobalCommit `yaml:"global_commit"`
	// Federation is the instance-to-instance transport (#30). Nil runs
	// the instance standalone.
	Federation *PluginSpec `yaml:"federation"`
}

// GlobalCommit is one commit shared by several providers, usually links
// to one carrier in several POPs (#30). Commit control on each instance
// compares the sum of every member's usage with CommitMbps.
type GlobalCommit struct {
	Name       string   `yaml:"name"`
	CommitMbps float64  `yaml:"commit_mbps"`
	Providers  []string `yaml:"providers"`
}

// Remote reports whether provider p is in another routing domain: its
// paths are measured by the peer in that domain, not probed here.
func (c *Config) Remote(p Provider) bool {
	return p.Domain != "" && p.Domain != c.Domain
}

// More-specific injection defaults and bounds (#56).
const (
	DefaultMoreSpecificMaxRoutes = 100
	MoreSpecificMaxRoutesLimit   = 1000
)

// MoreSpecific is more-specific injection. Only exact learned prefixes are
// announced. MaxRoutes caps the outbound and inbound routes on a router;
// zero means DefaultMoreSpecificMaxRoutes when enabled.
type MoreSpecific struct {
	Enabled   bool `yaml:"enabled"`
	MaxRoutes int  `yaml:"max_routes"`
}

// Inbound defaults and bounds.
const (
	DefaultInboundLocalPref  = 1
	DefaultInboundReleasePct = 90
	// Performance trigger defaults: a provider is the worst performer when
	// its mean loss is DefaultInboundPerfLossPct points or its mean RTT is
	// DefaultInboundPerfLatencyMs above the best other provider, over at
	// least DefaultInboundPerfMinPrefixes prefixes measured through every
	// provider. It is released below DefaultInboundPerfReleasePct of that.
	DefaultInboundPerfLossPct     = 5
	DefaultInboundPerfLatencyMs   = 50
	DefaultInboundPerfMinPrefixes = 3
	DefaultInboundPerfReleasePct  = 50
	// Damping defaults. max_hold defaults to DefaultInboundMaxHoldFactor
	// times hold_time.
	DefaultInboundConfirm       = time.Minute
	DefaultInboundBackoff       = 2
	DefaultInboundMaxHoldFactor = 8
)

// Inbound triggers, as named in inbound.moderated.
const (
	InboundTriggerCommit      = "commit"
	InboundTriggerPerformance = "performance"
)

// Inbound steers inbound traffic for the operator's own prefixes away
// from providers whose inbound 95th percentile is over commit, with the
// prepends and TE communities in the inbound announcer's catalog.
type Inbound struct {
	// Mode is observe (default), suggest, or inject. inject also needs the
	// top-level mode to be inject. observe and suggest never announce.
	Mode string `yaml:"mode"`
	// Prefixes are the operator's own prefixes to steer. In inject each
	// must be covered by allowlist.prefixes, and a steer route is only
	// announced for a prefix that is in the learned RIB.
	Prefixes []string `yaml:"prefixes"`
	// LocalPref is set on steer routes (default 1). Keep it low: the edge
	// must choose the steer route on purpose (see docs/inbound.md).
	LocalPref uint32 `yaml:"local_pref"`
	// ReleasePct releases a steer once the provider's inbound 95th is at or
	// below this percent of its commit (default 90, 1-100).
	ReleasePct float64 `yaml:"release_pct"`
	// MaxImprovements caps inbound steer routes. Default and upper bound
	// are the top-level max_improvements; outbound improvements and
	// inbound steers also share that cap.
	MaxImprovements int `yaml:"max_improvements"`
	// Announcer is the in-process inbound announcer. Required in inject.
	Announcer *PluginSpec `yaml:"announcer"`
	// Performance steers inbound traffic away from the worst-performing
	// provider, measured by the probes. Nil disables it.
	Performance *InboundPerformance `yaml:"performance"`
	// Damping is inertia against oscillation. Defaults apply when omitted.
	Damping InboundDamping `yaml:"damping"`
	// Moderated lists triggers (commit, performance) whose steers are
	// only suggested, even in inject. The rest are automated.
	Moderated []string `yaml:"moderated"`
}

// InboundPerformance is the performance trigger. Loss and RTT are the
// means over prefixes probed through every provider with a fresh result.
type InboundPerformance struct {
	// LossPct is how many loss points above the best other provider make a
	// provider degraded (default 5). Negative disables the loss check.
	LossPct float64 `yaml:"loss_pct"`
	// LatencyMs is how many ms of mean RTT above the best other provider
	// make a provider degraded (default 50). Negative disables it.
	LatencyMs float64 `yaml:"latency_ms"`
	// MinPrefixes is how many commonly probed prefixes are needed before
	// providers are compared (default 3).
	MinPrefixes int `yaml:"min_prefixes"`
	// ReleasePct releases a performance steer once both gaps are at or
	// below this percent of their thresholds (default 50, 1-100).
	ReleasePct float64 `yaml:"release_pct"`
}

// InboundDamping is inertia against steer/release oscillation.
type InboundDamping struct {
	// Disabled turns damping off: steers use hold_time as is.
	Disabled bool `yaml:"disabled"`
	// Confirm is how long a trigger must hold before a provider is steered
	// (default 1m).
	Confirm time.Duration `yaml:"confirm"`
	// Backoff multiplies the hold time and the cooldown each time a
	// provider is steered again within max_hold of its release (default 2,
	// at least 1).
	Backoff float64 `yaml:"backoff"`
	// MaxHold caps the grown hold time and is the flap window (default 8x
	// hold_time).
	MaxHold time.Duration `yaml:"max_hold"`
}

// InboundMode is the inbound mode, or "" when inbound is not configured.
func (c *Config) InboundMode() string {
	if c == nil || c.Inbound == nil {
		return ""
	}
	return c.Inbound.Mode
}

// Troubleshooting defaults and bounds.
const (
	DefaultTroubleshootRequestsPerMinute = 6
	MaxTroubleshootRequestsPerMinute     = 600
	DefaultTroubleshootMaxHops           = 30
	MaxTroubleshootMaxHops               = 64
)

// Troubleshoot configures the looking glass, on-demand probe, traceroute,
// and whois tools. The looking glass only reads the RIB and is always on.
type Troubleshoot struct {
	// Enabled turns on the tools that send traffic or query a registry
	// (probe, traceroute, whois). Default false.
	Enabled bool `yaml:"enabled"`
	// RequestsPerMinute caps probe, traceroute, and whois requests
	// together (default 6).
	RequestsPerMinute int `yaml:"requests_per_minute"`
	// MaxHops bounds one traceroute (default 30).
	MaxHops int `yaml:"max_hops"`
	// Whois selects the registry lookup plugin (rdap). Nil disables whois.
	Whois *PluginSpec `yaml:"whois"`
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
	// ASPath is the AS path on injected routes (#27): empty (default),
	// native (the learned path of the prefix), or provider (the chosen
	// provider's learned path, else the native one).
	ASPath string `yaml:"as_path"`
}

// AS path behavior on injected routes (bgp.as_path).
const (
	ASPathEmpty    = "empty"
	ASPathNative   = "native"
	ASPathProvider = "provider"
)

// BGPNeighbor is an edge router peered over iBGP (same ASN as asn).
type BGPNeighbor struct {
	Address      string `yaml:"address"`
	Port         int    `yaml:"port"`          // remote port, default 179
	LocalAddress string `yaml:"local_address"` // optional session source
	Passive      bool   `yaml:"passive"`       // wait for the router to connect
	Description  string `yaml:"description"`
	// AddPath asks the router for additional paths (BGP add-path, RFC
	// 7911, receive only) on this session, so the RIB view holds its
	// inactive and IX paths too. The router must be set to send them
	// (FRR: neighbor X addpath-tx-all-paths).
	AddPath bool `yaml:"add_path"`
	// Providers lists the providers this router forwards to directly (its
	// own transits). Routes toward them go to this router with the
	// provider's next_hop, and the router is that provider's egress: when
	// every egress session of a provider is down, no improvement uses it
	// (#27). Empty, with NextHops also empty, means the router reaches
	// every provider with its next_hop (one edge, or a route reflector).
	Providers []string `yaml:"providers"`
	// NextHops lists providers this router reaches through another router,
	// keyed by provider name, with the next hop this router uses for them
	// (usually that router's loopback or link address). A provider in
	// neither list is never announced to this router.
	NextHops map[string]string `yaml:"next_hops"`
}

// Routed reports whether the neighbor restricts which providers it reaches.
func (n BGPNeighbor) Routed() bool { return len(n.Providers) > 0 || len(n.NextHops) > 0 }

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

// Provider bmp usage (rib_sources, #26).
const (
	BMPOff    = "off"
	BMPPrefer = "prefer"
	BMPOnly   = "only"
)

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
	// Cost is the provider's price per Mbps, in any currency as long as
	// every provider uses the same one. Nil means no cost: the cost scorer
	// never moves traffic onto this provider or off it for price.
	Cost *float64 `yaml:"cost"`
	// BMP is how this provider uses paths from rib_sources (BMP, #26):
	// off (default), prefer, or only.
	BMP string `yaml:"bmp"`
	// AddPath applies the route check to this provider from the iBGP
	// add-path paths (#26): while a bgp.neighbors session with add_path
	// has add-path negotiated, the provider must be advertising the exact
	// prefix before Packeteer steers to it.
	AddPath bool `yaml:"add_path"`
	// Domain is the routing domain (POP) the provider exits in (#30).
	// Empty is this instance's domain. A provider in another domain has no
	// source_ip: the peer in that domain measures it, and next_hop is how
	// this POP's routers reach it across the backbone.
	Domain string `yaml:"domain"`

	// Exchange and PeerASN are set on providers expanded from exchanges
	// (#27); they are not config keys. A peer always gets the route check:
	// it must advertise the exact prefix, on a path whose first AS is
	// PeerASN, before Packeteer steers to it.
	Exchange string `yaml:"-"`
	PeerASN  uint32 `yaml:"-"`
}

// Exchange is one Internet exchange (#27). Each peer is a provider with
// its own next hop on the peering LAN and its own probe source. A peer
// carries only its own routes, so it is always route-checked: the router
// must show Packeteer the peer's path (add-path on the iBGP session, or
// BMP) before a prefix is steered to it.
type Exchange struct {
	Name string `yaml:"name"`
	// LANs are the peering LAN prefixes. Every peer next_hop is inside
	// one. Learned next hops inside them that are not configured peers
	// are reported on /api/exchanges, never used.
	LANs []string `yaml:"lans"`
	// BMP is the peers' bmp usage (off, prefer, only), as on providers.
	BMP string `yaml:"bmp"`
	// Group is the peers' load-balancing group, as on providers.
	Group string         `yaml:"group"`
	Peers []ExchangePeer `yaml:"peers"`
}

// ExchangePeer is one peer on an exchange.
type ExchangePeer struct {
	Name string `yaml:"name"`
	// ASN is the peer's AS: the first AS on the paths it advertises.
	ASN        uint32   `yaml:"asn"`
	NextHop    string   `yaml:"next_hop"`
	SourceIP   string   `yaml:"source_ip"`
	Exclude    bool     `yaml:"exclude"`
	Precedence int      `yaml:"precedence"`
	Cost       *float64 `yaml:"cost"`
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
	cfg.expandExchanges()
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
	if c.MoreSpecific != nil && c.MoreSpecific.MaxRoutes == 0 {
		c.MoreSpecific.MaxRoutes = DefaultMoreSpecificMaxRoutes
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
	if c.Troubleshoot.RequestsPerMinute == 0 {
		c.Troubleshoot.RequestsPerMinute = DefaultTroubleshootRequestsPerMinute
	}
	if c.Troubleshoot.MaxHops == 0 {
		c.Troubleshoot.MaxHops = DefaultTroubleshootMaxHops
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
	if strings.TrimSpace(c.BGP.ASPath) == "" {
		c.BGP.ASPath = ASPathEmpty
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
	if in := c.Inbound; in != nil {
		if strings.TrimSpace(in.Mode) == "" {
			in.Mode = ModeObserve
		}
		if in.LocalPref == 0 {
			in.LocalPref = DefaultInboundLocalPref
		}
		if in.ReleasePct == 0 {
			in.ReleasePct = DefaultInboundReleasePct
		}
		if in.MaxImprovements == 0 && c.MaxImprovements != nil {
			in.MaxImprovements = *c.MaxImprovements
		}
		if pf := in.Performance; pf != nil {
			if pf.LossPct == 0 {
				pf.LossPct = DefaultInboundPerfLossPct
			}
			if pf.LatencyMs == 0 {
				pf.LatencyMs = DefaultInboundPerfLatencyMs
			}
			if pf.MinPrefixes == 0 {
				pf.MinPrefixes = DefaultInboundPerfMinPrefixes
			}
			if pf.ReleasePct == 0 {
				pf.ReleasePct = DefaultInboundPerfReleasePct
			}
		}
		if d := &in.Damping; !d.Disabled {
			if d.Confirm == 0 {
				d.Confirm = DefaultInboundConfirm
			}
			if d.Backoff == 0 {
				d.Backoff = DefaultInboundBackoff
			}
			if d.MaxHold == 0 {
				d.MaxHold = DefaultInboundMaxHoldFactor * c.HoldTime
			}
		}
	}
	c.normalizeMitigation()
	if c.Instance == "" {
		c.Instance = c.Domain
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
		if p.Domain != "" && !validProviderGroup(p.Domain) {
			add("%s: domain %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", label, p.Domain)
		}
		var src netip.Addr
		var err error
		if c.Remote(p) {
			if p.SourceIP != "" {
				add("%s: source_ip must be empty for a provider in domain %s (the peer there measures it)", label, p.Domain)
			}
		} else if src, err = netip.ParseAddr(p.SourceIP); err != nil {
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
		if p.Cost != nil && (math.IsNaN(*p.Cost) || *p.Cost < 0 || *p.Cost > 1e9) {
			add("%s: cost %v must be between 0 and 1000000000", label, *p.Cost)
		}
		switch p.BMP {
		case "", BMPOff:
		case BMPPrefer, BMPOnly:
			if len(c.RIBSources) == 0 {
				add("%s: bmp %s requires a rib_sources entry", label, p.BMP)
			}
		default:
			add("%s: bmp %q is invalid (want off, prefer, or only)", label, p.BMP)
		}
		if p.AddPath {
			if !slices.ContainsFunc(c.BGP.Neighbors, func(n BGPNeighbor) bool { return n.AddPath }) {
				add("%s: add_path requires a bgp.neighbors entry with add_path: true", label)
			}
			if p.BMP == BMPOnly {
				add("%s: add_path does not apply with bmp only (iBGP paths are ignored for it)", label)
			}
		}
	}

	c.validateFederation(add)

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
	switch c.BGP.ASPath {
	case ASPathEmpty, ASPathNative, ASPathProvider:
	default:
		add("bgp.as_path %q is invalid (want %s, %s, or %s)", c.BGP.ASPath, ASPathEmpty, ASPathNative, ASPathProvider)
	}
	c.validateExchanges(add)
	c.validateRouters(add)

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
	validateSpecs("policies", c.Policies)
	validateSpecs("rib_sources", c.RIBSources)
	if len(c.RIBSources) > 0 && len(c.BGP.Neighbors) == 0 {
		add("rib_sources requires at least one bgp.neighbors entry (the RIB view and the announcer use the iBGP session)")
	}
	if c.Scorer != nil && c.Scorer.Type == "cost" {
		priced := 0
		for _, p := range c.Providers {
			if p.Cost != nil && !p.Exclude {
				priced++
			}
		}
		if priced < 2 {
			add("scorer: type cost needs a cost on at least two non-excluded providers (providers[].cost)")
		}
	}
	if c.Scorer != nil && c.Scorer.Type == "" {
		add("scorer: type is required")
	}
	if c.Announcer != nil && c.Announcer.Type == "" {
		add("announcer: type is required")
	}
	if c.Storage != nil && c.Storage.Type == "" {
		add("storage: type is required")
	}
	if n := c.Troubleshoot.RequestsPerMinute; n < 1 || n > MaxTroubleshootRequestsPerMinute {
		add("troubleshoot.requests_per_minute %d must be between 1 and %d", n, MaxTroubleshootRequestsPerMinute)
	}
	if n := c.Troubleshoot.MaxHops; n < 1 || n > MaxTroubleshootMaxHops {
		add("troubleshoot.max_hops %d must be between 1 and %d", n, MaxTroubleshootMaxHops)
	}
	if c.Troubleshoot.Whois != nil && c.Troubleshoot.Whois.Type == "" {
		add("troubleshoot.whois: type is required")
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
		add("more_specific_bits is removed: Packeteer announces only the exact prefix learned from the RIB (see more_specific)")
	}
	if ms := c.MoreSpecific; ms != nil && (ms.MaxRoutes < 1 || ms.MaxRoutes > MoreSpecificMaxRoutesLimit) {
		add("more_specific.max_routes %d must be between 1 and %d", ms.MaxRoutes, MoreSpecificMaxRoutesLimit)
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

	c.validateInbound(add)
	c.validateMitigation(add)

	return errors.Join(errs...)
}

// validateRouters checks per-router provider reachability (#27). With no
// neighbor restricted, every router gets every route and nothing is checked.
func (c *Config) validateRouters(add func(string, ...any)) {
	routed := slices.ContainsFunc(c.BGP.Neighbors, BGPNeighbor.Routed)
	if !routed {
		return
	}
	provNH := map[string]netip.Addr{}
	byNH := map[netip.Addr]string{}
	for _, p := range c.Providers {
		nh, err := netip.ParseAddr(p.NextHop)
		if err != nil || p.Name == "" {
			continue
		}
		provNH[p.Name] = nh
		// Routes are matched to a provider by next hop at export time.
		if other, dup := byNH[nh]; dup {
			add("providers (%s, %s): next_hop %s is shared; per-router routing (bgp.neighbors[].providers/next_hops) needs a unique next_hop per provider", other, p.Name, nh)
		}
		byNH[nh] = p.Name
	}
	reached := map[string]bool{}
	for i, n := range c.BGP.Neighbors {
		label := fmt.Sprintf("bgp.neighbors[%d]", i)
		if !n.Routed() {
			for name := range provNH {
				reached[name] = true
			}
			continue
		}
		seen := map[string]bool{}
		for _, name := range n.Providers {
			if _, ok := provNH[name]; !ok {
				add("%s: providers: %q is not a configured provider", label, name)
				continue
			}
			if seen[name] {
				add("%s: providers: duplicate %q", label, name)
			}
			seen[name] = true
			reached[name] = true
		}
		for _, name := range slices.Sorted(maps.Keys(n.NextHops)) {
			pnh, ok := provNH[name]
			if !ok {
				add("%s: next_hops: %q is not a configured provider", label, name)
				continue
			}
			if seen[name] {
				add("%s: next_hops: %q is also in providers (a router reaches a provider directly or through a next hop, not both)", label, name)
			}
			nh, err := netip.ParseAddr(n.NextHops[name])
			if err != nil {
				add("%s: next_hops: %s: %q is not a valid IP address", label, name, n.NextHops[name])
				continue
			}
			if nh.Is4() != pnh.Is4() {
				add("%s: next_hops: %s: %s must be the same address family as the provider's next_hop %s", label, name, nh, pnh)
			}
			reached[name] = true
		}
	}
	for _, p := range c.Providers {
		if _, ok := provNH[p.Name]; ok && !p.Exclude && !reached[p.Name] {
			add("providers[%s]: no bgp.neighbors entry reaches it (list it in a neighbor's providers or next_hops, or exclude it)", p.Name)
		}
	}
}

func (c *Config) validateInbound(add func(string, ...any)) {
	in := c.Inbound
	if in == nil {
		return
	}
	switch in.Mode {
	case ModeObserve, ModeSuggest:
	case ModeInject:
		if c.Mode != ModeInject {
			add("inbound.mode inject requires mode inject")
		}
		if in.Announcer == nil {
			add("inbound.mode inject requires inbound.announcer")
		}
	default:
		add("inbound.mode %q is invalid (want one of %s, %s, %s)", in.Mode, ModeObserve, ModeSuggest, ModeInject)
	}
	if in.Announcer != nil && in.Announcer.Type == "" {
		add("inbound.announcer: type is required")
	}
	if len(c.Telemetry) == 0 && in.Performance == nil {
		add("inbound requires a telemetry plugin (inbound commit control reads the inbound 95th percentile) or inbound.performance")
	}
	if len(in.Prefixes) == 0 {
		add("inbound.prefixes: at least one prefix is required")
	}
	var allow []netip.Prefix
	for _, s := range c.Allowlist.Prefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			allow = append(allow, p.Masked())
		}
	}
	seen := map[netip.Prefix]bool{}
	for i, s := range in.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			add("inbound.prefixes[%d]: %q is not a valid CIDR", i, s)
			continue
		}
		if p != p.Masked() {
			add("inbound.prefixes[%d]: %q has host bits set (did you mean %s?)", i, s, p.Masked())
			continue
		}
		if seen[p] {
			add("inbound.prefixes[%d]: duplicate prefix %s", i, p)
		}
		seen[p] = true
		if in.Mode == ModeInject && !coveredBy(allow, p) {
			add("inbound.prefixes[%d]: %s is not covered by allowlist.prefixes", i, p)
		}
	}
	if in.ReleasePct <= 0 || in.ReleasePct > 100 || math.IsNaN(in.ReleasePct) {
		add("inbound.release_pct %v must be greater than 0 and at most 100", in.ReleasePct)
	}
	if c.MaxImprovements != nil && (in.MaxImprovements < 1 || in.MaxImprovements > *c.MaxImprovements) {
		add("inbound.max_improvements %d must be between 1 and max_improvements (%d)", in.MaxImprovements, *c.MaxImprovements)
	}
	if pf := in.Performance; pf != nil {
		if math.IsNaN(pf.LossPct) || math.IsNaN(pf.LatencyMs) || pf.LossPct > 100 {
			add("inbound.performance.loss_pct %v must be at most 100 and latency_ms %v a number", pf.LossPct, pf.LatencyMs)
		}
		if pf.LossPct < 0 && pf.LatencyMs < 0 {
			add("inbound.performance: loss_pct and latency_ms cannot both be disabled")
		}
		if pf.MinPrefixes < 1 {
			add("inbound.performance.min_prefixes %d must be at least 1", pf.MinPrefixes)
		}
		if pf.ReleasePct <= 0 || pf.ReleasePct > 100 || math.IsNaN(pf.ReleasePct) {
			add("inbound.performance.release_pct %v must be greater than 0 and at most 100", pf.ReleasePct)
		}
	}
	if d := in.Damping; !d.Disabled {
		if d.Confirm < 0 {
			add("inbound.damping.confirm %s must not be negative", d.Confirm)
		}
		if d.Backoff < 1 || math.IsNaN(d.Backoff) || d.Backoff > 16 {
			add("inbound.damping.backoff %v must be between 1 and 16", d.Backoff)
		}
		if d.MaxHold < c.HoldTime {
			add("inbound.damping.max_hold %s must not be shorter than hold_time %s", d.MaxHold, c.HoldTime)
		}
	}
	seenTrigger := map[string]bool{}
	for i, t := range in.Moderated {
		switch t {
		case InboundTriggerCommit:
			if len(c.Telemetry) == 0 {
				add("inbound.moderated[%d]: commit needs a telemetry plugin", i)
			}
		case InboundTriggerPerformance:
			if in.Performance == nil {
				add("inbound.moderated[%d]: performance needs inbound.performance", i)
			}
		default:
			add("inbound.moderated[%d]: %q is invalid (want %s or %s)", i, t, InboundTriggerCommit, InboundTriggerPerformance)
		}
		if seenTrigger[t] {
			add("inbound.moderated[%d]: duplicate trigger %q", i, t)
		}
		seenTrigger[t] = true
	}
}

// coveredBy reports whether p is an entry of list or inside one.
func coveredBy(list []netip.Prefix, p netip.Prefix) bool {
	for _, a := range list {
		if a.Bits() <= p.Bits() && a.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

func (c *Config) normalize() {
	c.BGP.ASPath = strings.ToLower(strings.TrimSpace(c.BGP.ASPath))
	c.Log.Level = strings.ToLower(strings.TrimSpace(c.Log.Level))
	c.Log.Format = strings.ToLower(strings.TrimSpace(c.Log.Format))
	for i := range c.Providers {
		c.Providers[i].BMP = strings.ToLower(strings.TrimSpace(c.Providers[i].BMP))
	}
	if c.Inbound != nil {
		c.Inbound.Mode = strings.ToLower(strings.TrimSpace(c.Inbound.Mode))
		for i, t := range c.Inbound.Moderated {
			c.Inbound.Moderated[i] = strings.ToLower(strings.TrimSpace(t))
		}
	}
	for i := range c.Providers {
		c.Providers[i].Group = strings.TrimSpace(c.Providers[i].Group)
	}
	if c.Mitigation != nil {
		c.Mitigation.Mode = strings.ToLower(strings.TrimSpace(c.Mitigation.Mode))
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
