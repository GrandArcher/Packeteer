package config

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/agentwire"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/sockmark"
)

// Validate checks the config and returns all problems found, joined.
func (c *Config) Validate() error {
	c.normalize()
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	c.validateCore(add)
	c.validateProviders(add)
	c.validateFederation(add)
	c.validateAuth(add)
	c.validateAllowlist(add)
	c.validateProbe(add)
	c.validateIndirect(add)
	c.validateReorder(add)
	c.validatePathCheck(add)
	c.validateBGP(add)
	c.validateExchanges(add)
	c.validateExchangeHealth(add)
	c.validateRouters(add)
	c.validatePlugins(add)
	c.validateTroubleshoot(add)
	c.validateProbeBudget(add)
	c.validateLogHTTP(add)
	c.validateMoreSpecific(add)
	c.validateSynthesize(add)
	c.validateRPKI(add)
	c.validateIRR(add)
	c.validateRegistry(add)
	c.validateInject(add)
	c.validateIXP(add)
	c.validateHerd(add)

	// Cause and provider overrides are optional in every mode. A set 0 is
	// rejected the same way inject rejects a global local_pref of 0, so a
	// file prepared in observe fails before the mode changes.
	c.validateLocalPref(add)
	c.validateCommunities(add)
	c.validateInbound(add)
	c.validateMitigation(add)
	c.validateAnomaly(add)
	c.validateThreatFeeds(add)
	c.validateLeakWatch(add)
	c.validateSubscriptions(add)
	c.validateUpgrade(add)
	c.Linkouts.Validate(add)
	c.RingLG.Validate(add)
	c.Atlas.Validate(add)
	c.validateGeoIP(add)
	c.Verify.Validate(add)

	return errors.Join(errs...)
}

// validateCore checks mode, identity, caps, hold and flap settings, and thresholds.
func (c *Config) validateCore(add func(string, ...any)) {
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
		text, err := CommunityText(c.PacketeerCommunity)
		if err != nil {
			add("packeteer_community %q: %v", c.PacketeerCommunity, err)
		} else {
			c.PacketeerCommunity = text
		}
	}

	if c.MaxImprovements != nil {
		if n := *c.MaxImprovements; n < 0 || n > MaxImprovementsLimit {
			add("max_improvements %d must be between 0 and %d", n, MaxImprovementsLimit)
		}
	}

	if c.HoldTime < 0 {
		add("hold_time %s must not be negative", c.HoldTime)
	}

	if f := c.FlapQuarantine; !f.Disabled {
		if f.MaxFlips < 1 {
			add("flap_quarantine.max_flips %d must be at least 1", f.MaxFlips)
		}
		if f.Window <= 0 {
			add("flap_quarantine.window %s must be positive", f.Window)
		}
		if f.Cooldown <= 0 {
			add("flap_quarantine.cooldown %s must be positive", f.Cooldown)
		}
		if f.MaxCooldown < f.Cooldown {
			add("flap_quarantine.max_cooldown %s must not be shorter than cooldown %s", f.MaxCooldown, f.Cooldown)
		}
	}

	if c.Thresholds.MinLossDeltaPct < 0 || c.Thresholds.MinLossDeltaPct > 100 {
		add("thresholds.min_loss_delta_pct %v must be between 0 and 100", c.Thresholds.MinLossDeltaPct)
	}
	if c.Thresholds.MinRTTDeltaMs < 0 {
		add("thresholds.min_rtt_delta_ms %v must not be negative", c.Thresholds.MinRTTDeltaMs)
	}
	if c.Thresholds.MinRTTDeltaPct < 0 || c.Thresholds.MinRTTDeltaPct > 100 {
		add("thresholds.min_rtt_delta_pct %v must be between 0 and 100", c.Thresholds.MinRTTDeltaPct)
	}
	if m := c.Thresholds.MEDMargin; m != nil && (*m < 0 || math.IsNaN(*m) || math.IsInf(*m, 0)) {
		add("thresholds.med_margin %v must be zero or positive", *m)
	}
	if c.Thresholds.ConfirmRounds < 1 || c.Thresholds.ConfirmRounds > MaxConfirmRounds {
		add("thresholds.confirm_rounds %d must be between 1 and %d", c.Thresholds.ConfirmRounds, MaxConfirmRounds)
	}
}

// validateProviders checks providers.
func (c *Config) validateProviders(add func(string, ...any)) {
	if len(c.Providers) == 0 {
		add("providers: at least one provider is required")
	}
	names := map[string]bool{}
	sources := map[netip.Addr]*sharedSource{}
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
		if p.Site != "" {
			c.validateSite(p, label, add)
		}
		if p.DSCP < 0 || p.DSCP > sockmark.MaxDSCP {
			add("%s: dscp %d must be between 0 and %d", label, p.DSCP, sockmark.MaxDSCP)
		}
		if c.Remote(p) {
			if p.SourceIP != "" {
				add("%s: source_ip must be empty for a provider in domain %s (the peer there measures it)", label, p.Domain)
			}
			if p.FwMark != 0 || p.DSCP != 0 {
				add("%s: fwmark and dscp must be empty for a provider in domain %s (the peer there measures it)", label, p.Domain)
			}
		} else if p.Site == "" {
			if !slices.ContainsFunc(c.Probers, func(s PluginSpec) bool { return s.Type != "agent" }) {
				add("%s: no probers entry other than agent can measure a provider without a site", label)
			}
			if src, err = netip.ParseAddr(p.SourceIP); err != nil {
				add("%s: source_ip %q is not a valid IP address", label, p.SourceIP)
			} else {
				sources[src] = sources[src].admit(src, p, label, add)
			}
		}
		nh, err := netip.ParseAddr(p.NextHop)
		if err != nil {
			add("%s: next_hop %q is not a valid IP address", label, p.NextHop)
		} else if src.IsValid() && src.Is4() != nh.Is4() {
			add("%s: source_ip and next_hop must be the same address family", label)
		}
		if !slices.Contains(ProviderTypes, p.Type) && p.Type != "" {
			add("%s: type %q is invalid (want transit, peer, or customer)", label, p.Type)
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
		if pct := p.InterfaceCapacityThresholdPct; math.IsNaN(pct) || pct < 0 || pct > 100 {
			add("%s: interface_capacity_threshold_pct %v must be between 0 and 100 (0 is off)", label, pct)
		} else if pct > 0 && len(c.Telemetry) == 0 {
			add("%s: interface_capacity_threshold_pct requires a telemetry plugin (a provider with no interface reading takes no new performance steer)", label)
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
}

// validateSite checks a provider measured by probe agents (#230).
func (c *Config) validateSite(p Provider, label string, add func(string, ...any)) {
	switch {
	case !agentwire.NameRE.MatchString(p.Site):
		add("%s: site %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", label, p.Site)
	case c.Remote(p):
		add("%s: site and domain cannot both be set (a peer measures a provider in another domain)", label)
	case p.SourceIP != "" || p.FwMark != 0 || p.DSCP != 0:
		add("%s: source_ip, fwmark, and dscp must be empty for a provider with a site (the agent declares them)", label)
	case !slices.ContainsFunc(c.Probers, func(s PluginSpec) bool { return s.Type == "agent" }):
		add("%s: site requires a probers entry of type agent", label)
	}
}

// sharedSource tracks the providers on one source_ip (#157). Providers may
// share it only when each sets fwmark or dscp and no two use the same one,
// so policy routing can tell them apart.
type sharedSource struct {
	untagged bool // a provider on the source sets neither fwmark nor dscp
	marks    map[uint32]string
	dscps    map[int]string
}

// admit records p on its source and reports what makes the share
// ambiguous. A nil receiver is the first provider on the source.
func (s *sharedSource) admit(src netip.Addr, p Provider, label string, add func(string, ...any)) *sharedSource {
	tagged := p.FwMark != 0 || p.DSCP != 0
	if s == nil {
		s = &sharedSource{marks: map[uint32]string{}, dscps: map[int]string{}}
	} else if s.untagged || !tagged {
		add("%s: duplicate source_ip %s (providers may share one only when each sets fwmark or dscp)", label, src)
	}
	s.untagged = s.untagged || !tagged
	if other, dup := s.marks[p.FwMark]; dup && p.FwMark != 0 {
		add("%s: fwmark %d is already used by %s on source_ip %s", label, p.FwMark, other, src)
	}
	if other, dup := s.dscps[p.DSCP]; dup && p.DSCP != 0 {
		add("%s: dscp %d is already used by %s on source_ip %s", label, p.DSCP, other, src)
	}
	s.marks[p.FwMark], s.dscps[p.DSCP] = p.Name, p.Name
	return s
}

// validateAllowlist checks allowlist prefixes.
func (c *Config) validateAllowlist(add func(string, ...any)) {
	var lans []netip.Prefix
	for _, ex := range c.Exchanges {
		lans = append(lans, ex.ExchangeLANs()...)
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
		for _, lan := range lans {
			if exchange.Overlaps(p, lan) {
				add("allowlist.prefixes[%d]: %s overlaps exchange LAN %s", i, p, lan)
				break
			}
		}
	}
}

// validateProbe checks probe timing and packet settings.
func (c *Config) validateProbe(add func(string, ...any)) {
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
	if c.Probe.DegradedLossPct <= 0 || c.Probe.DownLossPct > 100 || c.Probe.DegradedLossPct > c.Probe.DownLossPct {
		add("probe.degraded_loss_pct %v and probe.down_loss_pct %v must satisfy 0 < degraded <= down <= 100",
			c.Probe.DegradedLossPct, c.Probe.DownLossPct)
	}
	if c.Probe.RetryPackets < 0 || c.Probe.RetryPackets > MaxProbePackets {
		add("probe.retry_packets %d must be between 0 and %d", c.Probe.RetryPackets, MaxProbePackets)
	}
	if c.Probe.MinReplies < 1 || c.Probe.MinReplies > MaxProbePackets {
		add("probe.min_replies %d must be between 1 and %d", c.Probe.MinReplies, MaxProbePackets)
	}
	if c.Probe.DispersionMS < 0 || c.Probe.DispersionMS > MaxProbeDispersionMS {
		add("probe.dispersion_ms %d must be between 0 and %d", c.Probe.DispersionMS, MaxProbeDispersionMS)
	}
	if c.Probe.ProberRecheckRounds < 1 || c.Probe.ProberRecheckRounds > MaxProbeProberRecheckRounds {
		add("probe.prober_recheck_rounds %d must be between 1 and %d", c.Probe.ProberRecheckRounds, MaxProbeProberRecheckRounds)
	}
	if c.Probe.ProberMemory < 1 || c.Probe.ProberMemory > MaxProbeProberMemory {
		add("probe.prober_memory %d must be between 1 and %d", c.Probe.ProberMemory, MaxProbeProberMemory)
	}
}

// validateBGP checks the bgp section.
func (c *Config) validateBGP(add func(string, ...any)) {
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
	if c.BGP.NotEstablishedAfter < 0 {
		add("bgp.not_established_after %s must not be negative", c.BGP.NotEstablishedAfter)
	}
	switch c.BGP.ASPath {
	case ASPathEmpty, ASPathNative, ASPathProvider:
	default:
		add("bgp.as_path %q is invalid (want %s, %s, or %s)", c.BGP.ASPath, ASPathEmpty, ASPathNative, ASPathProvider)
	}
}

// validatePlugins checks plugin specs and the sections that depend on them.
func (c *Config) validatePlugins(add func(string, ...any)) {
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
	validateSpecs("exporters", c.Exporters)
	validateSpecs("telemetry", c.Telemetry)
	validateSpecs("policies", c.Policies)
	validateSpecs("rib_sources", c.RIBSources)
	if c.LeakWatching() {
		validateSpecs("leak_watch.sources", c.LeakWatch.Sources)
	}
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
	if c.Lookup != nil && c.Lookup.Type == "" {
		add("lookup: type is required")
	}
	if c.Inventory != nil && c.Inventory.Type == "" {
		add("inventory: type is required")
	}
	if c.IXP != nil && c.IXP.Members != nil && c.IXP.Members.Type == "" {
		add("ixp.members: type is required")
	}
	if c.IXP != nil && c.IXP.Fabric != nil && c.IXP.Fabric.Type == "" {
		add("ixp.fabric: type is required")
	}
	if c.IXP != nil && c.IXP.RouteServers != nil && c.IXP.RouteServers.Type == "" {
		add("ixp.routeservers: type is required")
	}
	if c.IXP != nil && c.IXP.Correlate != nil && c.IXP.Correlate.Type == "" {
		add("ixp.correlate: type is required")
	}
	if c.IXP != nil && c.IXP.Core != nil && c.IXP.Core.Type == "" {
		add("ixp.core: type is required")
	}
	if c.Announcer != nil && c.Announcer.Type == "" {
		add("announcer: type is required")
	}
	if c.Storage != nil && c.Storage.Type == "" {
		add("storage: type is required")
	}
	if c.HA != nil {
		if c.HA.Type == "" {
			add("ha: type is required")
		}
		if len(c.BGP.Neighbors) == 0 {
			add("ha requires bgp.neighbors (an instance may lead only while its RIB view is ready)")
		}
	}
}

// validateTroubleshoot checks troubleshoot.
func (c *Config) validateTroubleshoot(add func(string, ...any)) {
	if n := c.Troubleshoot.RequestsPerMinute; n < 1 || n > MaxTroubleshootRequestsPerMinute {
		add("troubleshoot.requests_per_minute %d must be between 1 and %d", n, MaxTroubleshootRequestsPerMinute)
	}
	if n := c.Troubleshoot.MaxHops; n < 1 || n > MaxTroubleshootMaxHops {
		add("troubleshoot.max_hops %d must be between 1 and %d", n, MaxTroubleshootMaxHops)
	}
	if c.Troubleshoot.Whois != nil && c.Troubleshoot.Whois.Type == "" {
		add("troubleshoot.whois: type is required")
	}
}

// validateProbeBudget checks probe worker and rate limits.
func (c *Config) validateProbeBudget(add func(string, ...any)) {
	if c.Probe.Workers < 1 || c.Probe.Workers > MaxProbeWorkers {
		add("probe.workers %d must be between 1 and %d", c.Probe.Workers, MaxProbeWorkers)
	}
	if c.Probe.RateLimitPPS < 1 || c.Probe.RateLimitPPS > MaxProbeRateLimitPPS {
		add("probe.rate_limit_pps %d must be between 1 and %d", c.Probe.RateLimitPPS, MaxProbeRateLimitPPS)
	}
	if c.Probe.PerASNPPS < 0 || c.Probe.PerASNPPS > c.Probe.RateLimitPPS {
		add("probe.per_asn_pps %d must be between 0 and probe.rate_limit_pps %d", c.Probe.PerASNPPS, c.Probe.RateLimitPPS)
	}
	c.Probe.Exclude.validate(add, "probe.exclude")
	if c.Probe.PerTargetConcurrency < 1 || c.Probe.PerTargetConcurrency > MaxProbePerTargetConcurrency {
		add("probe.per_target_concurrency %d must be between 1 and %d", c.Probe.PerTargetConcurrency, MaxProbePerTargetConcurrency)
	}
}

// validateLogHTTP checks log and http.
func (c *Config) validateLogHTTP(add func(string, ...any)) {
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
}

// validateMoreSpecific checks more_specific.
func (c *Config) validateMoreSpecific(add func(string, ...any)) {
	if c.MoreSpecificBits != nil {
		add("more_specific_bits is removed: Packeteer announces only the exact prefix learned from the RIB (see more_specific)")
	}
	if ms := c.MoreSpecific; ms != nil && (ms.MaxRoutes < 1 || ms.MaxRoutes > MoreSpecificMaxRoutesLimit) {
		add("more_specific.max_routes %d must be between 1 and %d", ms.MaxRoutes, MoreSpecificMaxRoutesLimit)
	}
}

// validateInject enforces the extra safety requirements of inject mode
// (see AGENTS.md).
func (c *Config) validateInject(add func(string, ...any)) {
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
}

// validateLocalPref rejects a cause or provider local preference of 0.
// Omitting the key is the global local_pref. A set value has to be above
// the edge's native local preference, which is the same rule as the global
// value: 0 is rejected and anything else is the operator's number.
func (c *Config) validateLocalPref(add func(string, ...any)) {
	check := func(where string, v *uint32) {
		if v != nil && *v == 0 {
			add("%s: 0 is rejected; set it above the edge's native local preference, or omit it", where)
		}
	}
	check("local_pref_cause.performance", c.LocalPrefCause.Performance)
	check("local_pref_cause.static", c.LocalPrefCause.Static)
	check("local_pref_cause.commit", c.LocalPrefCause.Commit)
	check("local_pref_cause.cost", c.LocalPrefCause.Cost)
	for i, p := range c.Providers {
		label := fmt.Sprintf("providers[%d]", i)
		if p.Name != "" {
			label = fmt.Sprintf("providers[%d] (%s)", i, p.Name)
		}
		check(label+".local_pref", p.LocalPref)
	}
}

// validateCommunities checks packeteer's extra outbound communities and
// rewrites each accepted value to its canonical text. The export policy
// matches only packeteer_community; these are attributes for the edge.
func (c *Config) validateCommunities(add func(string, ...any)) {
	pack := c.PacketeerCommunity
	check := func(where string, list *[]string) {
		if len(*list) == 0 {
			return
		}
		if len(*list) > MaxExtraCommunities {
			add("%s: at most %d communities", where, MaxExtraCommunities)
		}
		seen := map[string]bool{}
		out := make([]string, 0, len(*list))
		for i, s := range *list {
			text, err := ExtraCommunityText(s, pack)
			if err != nil {
				add("%s[%d] %q: %v", where, i, s, err)
				continue
			}
			if seen[text] {
				add("%s: duplicate community %s", where, text)
				continue
			}
			seen[text] = true
			out = append(out, text)
		}
		if len(out) == len(*list) {
			*list = out
		}
	}
	check("communities_cause.performance", &c.CommunitiesCause.Performance)
	check("communities_cause.static", &c.CommunitiesCause.Static)
	check("communities_cause.commit", &c.CommunitiesCause.Commit)
	check("communities_cause.cost", &c.CommunitiesCause.Cost)
	for i := range c.Providers {
		p := &c.Providers[i]
		label := fmt.Sprintf("providers[%d]", i)
		if p.Name != "" {
			label = fmt.Sprintf("providers[%d] (%s)", i, p.Name)
		}
		check(label+".communities", &p.Communities)
	}
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
		if in.Mode == ModeInject && !netpfx.CoveredBy(allow, p) {
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

// CommunityText parses s as a standard community ("asn:value", each half
// 0–65535) or a large community ("global:data1:data2", each part
// 0–4294967295, RFC 8092) and returns the canonical decimal text.
func CommunityText(s string) (string, error) {
	parts := strings.Split(s, ":")
	nums := make([]uint64, len(parts))
	bits := 16
	switch len(parts) {
	case 2:
	case 3:
		bits = 32
	default:
		return "", errors.New(`must be "asn:value" or a large community "global:data1:data2" (RFC 8092)`)
	}
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, bits)
		if err != nil || part == "" {
			if bits == 16 {
				return "", errors.New("each half must be an integer 0-65535")
			}
			return "", errors.New("each part must be an integer 0-4294967295")
		}
		nums[i] = n
	}
	if len(nums) == 2 {
		return fmt.Sprintf("%d:%d", nums[0], nums[1]), nil
	}
	return fmt.Sprintf("%d:%d:%d", nums[0], nums[1], nums[2]), nil
}

// ExtraCommunityText is CommunityText for an outbound extra. It rejects a
// duplicate of packeteer and a well-known standard community (0:x and
// 65535:x), which would change BGP propagation instead of being a signal
// the edge maps to weight, VRF, interface, or QoS.
func ExtraCommunityText(s, packeteer string) (string, error) {
	text, err := CommunityText(s)
	if err != nil {
		return "", err
	}
	if packeteer != "" && text == packeteer {
		return "", errors.New("duplicates packeteer_community")
	}
	if hi, rest, ok := strings.Cut(text, ":"); ok && !strings.Contains(rest, ":") && (hi == "0" || hi == "65535") {
		return "", errors.New("0:x and 65535:x are reserved")
	}
	return text, nil
}
