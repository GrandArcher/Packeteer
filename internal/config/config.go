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
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/internal/ringlg"
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

	// DefaultProbeProberRecheckRounds is how often a host is probed from
	// the first prober again. Probe 1, 11, 21, ... start there when this
	// is 10. Keep it equal to probe.DefaultProberRecheckRounds.
	DefaultProbeProberRecheckRounds = 10
	MaxProbeProberRecheckRounds     = 10000
	// DefaultProbeProberMemory is how many hosts remember a prober.
	// Keep it equal to probe.DefaultProberMemory.
	DefaultProbeProberMemory = 100000
	MaxProbeProberMemory     = 1000000

	// DefaultProbeMinReplies is how many replies a host needs before it
	// can define the score. 1 is any reply, which is the historical rule.
	DefaultProbeMinReplies = 1
	// MaxProbeDispersionMS is the largest RTT spread (max−min), in
	// milliseconds, an operator may require of a qualified host.
	MaxProbeDispersionMS = 600000

	// Provider health (#343): a provider's mean loss at or above
	// DefaultProbeDegradedLossPct shows degraded, at or above
	// DefaultProbeDownLossPct shows down. No reply at all is always down.
	DefaultProbeDegradedLossPct = 5
	DefaultProbeDownLossPct     = 50

	// DefaultBGPNotEstablishedAfter is how long a neighbor may stay down
	// from the start before the controller raises an event (#347).
	DefaultBGPNotEstablishedAfter = 5 * time.Minute

	// MaxConfirmRounds is the upper bound of thresholds.confirm_rounds.
	// Omitted or 0 means 1 (announce on the first fresh win).
	MaxConfirmRounds = 100

	// DefaultHTTPListen is the read-only ops server. Loopback keeps the
	// dashboard off the network unless the operator opts in.
	DefaultHTTPListen = "127.0.0.1:8080"

	// MaxExtraCommunities is the most extra outbound communities one
	// cause or one provider may list (#132).
	MaxExtraCommunities = 16
)

// Config is the top-level controller configuration.
type Config struct {
	Mode     string `yaml:"mode"`
	ASN      uint32 `yaml:"asn"`
	RouterID string `yaml:"router_id"`
	// PacketeerCommunity tags every injected route. It is a standard
	// community ("asn:value", each half 0–65535) or a large community
	// ("global:data1:data2", RFC 8092). The export policy matches only
	// this community.
	PacketeerCommunity string `yaml:"packeteer_community"`
	// CommunitiesCause adds extra communities per improvement cause. They
	// are added to PacketeerCommunity; a provider's Communities are added
	// as well. An omitted cause adds none. An empty cause is performance.
	CommunitiesCause CommunityCauses `yaml:"communities_cause,omitempty"`
	// LocalPref is the local preference on an injected route when no cause
	// or provider override is set. Required, and non-zero, when mode is inject.
	LocalPref uint32 `yaml:"local_pref"`
	// LocalPrefCause overrides LocalPref per improvement cause. An omitted
	// cause uses LocalPref. A provider LocalPref wins over this.
	LocalPrefCause LocalPrefCauses `yaml:"local_pref_cause,omitempty"`
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
	// FlapQuarantine parks a prefix whose chosen provider keeps changing
	// (#228). On by default; it only withdraws.
	FlapQuarantine FlapQuarantine `yaml:"flap_quarantine"`
	Providers      []Provider     `yaml:"providers"`
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
	// Anomaly is automatic traffic anomaly detection (#33). It acts only
	// through Mitigation, and only for an explicit rule. Nil disables it.
	Anomaly *Anomaly `yaml:"anomaly"`
	// LeakWatch withdraws and holds out an injected route that shows up
	// outside the AS (#199). Nil or disabled is off.
	LeakWatch *LeakWatch `yaml:"leak_watch"`
	// MoreSpecific announces, with each improvement, the more-specifics
	// inside its prefix that a neighbor advertises in the learned RIB
	// (#56, docs/design/more-specific.md). Nil or disabled is off.
	MoreSpecific *MoreSpecific `yaml:"more_specific"`
	// RPKI is the shared RPKI origin-validation source (#158). Nil or
	// disabled is off.
	RPKI *RPKI `yaml:"rpki"`
	// IRR is the IRR origin check per learned path (#214). Nil or disabled
	// is off.
	IRR *IRR `yaml:"irr"`

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
	// HA is the active/standby elector (#31). Nil runs a single instance
	// that is always active. Only the active instance announces.
	HA *PluginSpec `yaml:"ha"`
	// Auth is users, roles, API tokens, and single sign-on for the ops
	// HTTP server (#32). Nil or disabled keeps the basic-auth account.
	Auth *Auth `yaml:"auth"`
	// ReportSubscriptions email stored reports on a schedule (#34).
	ReportSubscriptions []ReportSubscription `yaml:"report_subscriptions"`
	// Upgrade is the version check, one-click upgrade, and rollback in
	// the Settings page (#196). Nil or disabled: the page only shows the
	// running version.
	Upgrade *Upgrade `yaml:"upgrade"`
	// Linkouts picks the "open in" links on the prefix, ASN, and provider
	// pages (#211). Display only; Packeteer requests none of those sites.
	Linkouts linkout.Config `yaml:"linkouts"`
	// RingLG is the opt-in "Seen from NLNOG RING" panel on the prefix page
	// (#283). Off by default; display only.
	RingLG ringlg.Config `yaml:"ring_lg"`
	// Lookup is the read-only PeeringDB / IX-F directory (#153). Nil
	// disables it. It never announces.
	Lookup *PluginSpec `yaml:"lookup"`
	// Herd is opt-in sharing of probe measurements with other operators
	// (#260). Nil or disabled is off.
	Herd *Herd `yaml:"herd"`
	// IXP is exchange-operator mode (#160). Nil is an edge controller.
	// Set, Packeteer observes only and never announces.
	IXP *IXP `yaml:"ixp"`
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
	// AllowFrom restricts client addresses to these prefixes (#32). Empty
	// allows any. It applies with and without auth, health checks
	// included.
	AllowFrom []string `yaml:"allow_from"`
	// ConfigEditor lets an admin read, validate, and write this config
	// file through the API and the UI (#34). Writes need auth or the
	// basic-auth account. Online keys apply on the write (#128); the rest
	// take effect on restart. Nil (unset) turns it on only while the
	// first-run setup is pending (#416); false or true is explicit.
	ConfigEditor *bool `yaml:"config_editor"`
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
	// NotEstablishedAfter is how long a configured neighbor may stay out of
	// Established, from the start, before bgp.session_not_established
	// fires (#347). Zero uses the default.
	NotEstablishedAfter time.Duration `yaml:"not_established_after"`
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
	// MinRTTDeltaPct, when greater than 0, requires an RTT win to also be
	// this percent of the current path's RTT. 0 (the default) is off.
	MinRTTDeltaPct float64 `yaml:"min_rtt_delta_pct"`
	// ConfirmRounds is how many consecutive fresh probe rounds a new
	// performance move or a performance switch must win. 0 means 1.
	ConfirmRounds int `yaml:"confirm_rounds"`
}

// Flap quarantine defaults (#228).
const (
	DefaultFlapMaxFlips    = 6
	DefaultFlapWindow      = time.Hour
	DefaultFlapCooldown    = 15 * time.Minute
	DefaultFlapMaxCooldown = 4 * time.Hour
)

// FlapQuarantine withdraws Packeteer's route for a prefix that changes its
// chosen provider more than MaxFlips times in Window, and leaves it on the
// router's native path for Cooldown. Cooldown doubles on each repeat
// offense inside MaxCooldown of the last release, up to MaxCooldown.
type FlapQuarantine struct {
	Disabled    bool          `yaml:"disabled"`
	MaxFlips    int           `yaml:"max_flips"`
	Window      time.Duration `yaml:"window"`
	Cooldown    time.Duration `yaml:"cooldown"`
	MaxCooldown time.Duration `yaml:"max_cooldown"`
}

// CommunityCauses is an optional list of extra outbound communities per
// improvement cause (#132). Each value is a standard community or a large
// community (RFC 8092). Unknown keys are rejected. An empty list is the
// same as omitting the cause.
type CommunityCauses struct {
	Performance []string `yaml:"performance,omitempty"`
	Static      []string `yaml:"static,omitempty"`
	Commit      []string `yaml:"commit,omitempty"`
	Cost        []string `yaml:"cost,omitempty"`
}

// LocalPrefCauses is an optional local preference per improvement cause
// (#132). A nil field uses the global LocalPref. A set value must be
// non-zero: the same rule as LocalPref in inject, so the operator sets
// it above the edge's native local preference. Unknown keys are rejected.
type LocalPrefCauses struct {
	Performance *uint32 `yaml:"performance,omitempty"`
	Static      *uint32 `yaml:"static,omitempty"`
	Commit      *uint32 `yaml:"commit,omitempty"`
	Cost        *uint32 `yaml:"cost,omitempty"`
}

// Provider is one upstream transit that probes are sourced through.
type Provider struct {
	Name     string `yaml:"name"`
	SourceIP string `yaml:"source_ip"`
	NextHop  string `yaml:"next_hop"`
	// ASN is the provider's own AS and Type is transit, peer, or customer.
	// Both are labels for the Providers page and AS search; no decision
	// reads them. 0 and "" mean not set.
	ASN  uint32 `yaml:"asn"`
	Type string `yaml:"type"`
	// LocalPref, when set, is the local preference on routes steered to
	// this provider. It wins over local_pref_cause and the global
	// local_pref. Nil uses those. 0 is rejected.
	LocalPref *uint32 `yaml:"local_pref,omitempty"`
	// Communities are extra communities on routes steered to this
	// provider, added after the cause's. The export policy does not
	// match them. Large communities (RFC 8092) are accepted.
	Communities []string `yaml:"communities,omitempty"`
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
	// PathCheck is the first-hop probe-path check for this provider
	// (#150). Nil or true checks; false opts out, for a source_ip whose
	// traffic does not leave the edge directly through next_hop.
	PathCheck *bool `yaml:"path_check"`
	// FwMark and DSCP tag this provider's probe packets so providers can
	// share one source_ip (#157). The host's policy routing matches the
	// Linux fwmark; a router in front of the probe box matches the DSCP.
	// 0 means no tag. DSCP is 0-63 and FwMark needs CAP_NET_ADMIN.
	FwMark uint32 `yaml:"fwmark"`
	DSCP   int    `yaml:"dscp"`

	// Exchange and PeerASN are set on providers expanded from exchanges
	// (#27); they are not config keys. A peer always gets the route check:
	// it must advertise the exact prefix, on a path whose first AS is
	// PeerASN, before Packeteer steers to it.
	Exchange string `yaml:"-"`
	PeerASN  uint32 `yaml:"-"`
}

// ProviderTypes are the values of a provider's type.
var ProviderTypes = []string{"transit", "peer", "customer"}

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
	// Health tunes the next-hop probes and the exchange.degraded alert (#149).
	Health ExchangeHealth `yaml:"health"`
	// MaxPrefixWarnPct is the share of a peer's max_prefix at which
	// exchange.max_prefix fires (#147). Omitted or 0 uses the default.
	MaxPrefixWarnPct int `yaml:"max_prefix_warn_pct"`
	// Port is the one interface every peer shares (#151). Nil leaves each
	// peer an independent provider.
	Port *ExchangePort `yaml:"port"`
}

// ExchangePort is an exchange's shared port. Its usage comes from a
// telemetry binding named like the exchange (one interface); commit and cost
// planning treat the peers as drawing from it.
type ExchangePort struct {
	// CapacityMbps is the port speed. Planned moves never push the port's
	// load past it.
	CapacityMbps float64 `yaml:"capacity_mbps"`
	// CommitMbps is the port's own commit on its billable 95th, 0 for none.
	CommitMbps float64 `yaml:"commit_mbps"`
	// PortCost is the flat monthly fee. Set, it makes every peer's marginal
	// cost 0 per Mbps while the port has room, so peers may not set cost.
	PortCost *float64 `yaml:"port_cost"`
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
	// MaxPrefix is the router's maximum-prefix limit on this peer's
	// session, when known (#147). 0 (default) disables the warning. It is
	// read-only: Packeteer never sets or changes the limit.
	MaxPrefix int `yaml:"max_prefix"`
	// PathCheck is the peer's first-hop probe-path check opt-out, as on
	// providers (#150).
	PathCheck *bool `yaml:"path_check"`
	// FwMark and DSCP tag the peer's probe packets so many peers can share
	// one source_ip (#157), as on providers.
	FwMark uint32 `yaml:"fwmark"`
	DSCP   int    `yaml:"dscp"`
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
	// this percent. Zero disables loss retry. DispersionMS escalates
	// on its own when a host's RTT spread is over the limit.
	RetryLossPct float64 `yaml:"retry_loss_pct"`
	// RetryPackets is the packet count of that second probe. Zero means
	// three times packets when loss retry or dispersion is enabled, and
	// is otherwise unused.
	RetryPackets int `yaml:"retry_packets"`
	// MinReplies is how many replies a host needs before it can define
	// the score. Zero uses the default of 1 (any reply counts). A host
	// with fewer replies is left out the way a silent host is.
	MinReplies int `yaml:"min_replies"`
	// DispersionMS is the maximum RTT spread (maximum reply minus
	// minimum reply), in milliseconds, for a host that defines the
	// score. Zero disables the check. A wider spread is left out the
	// way a silent host is, and that prefix is probed again with
	// RetryPackets.
	DispersionMS int `yaml:"dispersion_ms"`
	// DegradedLossPct and DownLossPct set when the dashboard shows a
	// provider as degraded or down, from its mean loss over the measured
	// prefixes. They only label; they do not change any decision. Zero
	// uses the default.
	DegradedLossPct float64 `yaml:"degraded_loss_pct"`
	DownLossPct     float64 `yaml:"down_loss_pct"`
	// ProberRecheckRounds is how often each host is probed from the first
	// prober again. Omitted or 0 uses the default. The other rounds start
	// at the prober that last got a reply from that host.
	ProberRecheckRounds int `yaml:"prober_recheck_rounds"`
	// ProberMemory caps the hosts that remember a prober. Omitted or 0
	// uses the default. Hosts that leave the probe set are dropped first.
	ProberMemory int `yaml:"prober_memory"`
	// Indirect traces silent prefixes per provider (#123). Nil is off.
	Indirect *ProbeIndirect `yaml:"indirect"`
	// PathCheck verifies that probes from each provider's source_ip leave
	// through that provider's next_hop (#150).
	PathCheck ProbePathCheck `yaml:"path_check"`
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
	if err := ixpForbidsSynthesize(data); err != nil {
		return nil, err
	}

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
