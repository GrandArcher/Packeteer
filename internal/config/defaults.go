package config

import "strings"

func (c *Config) applyDefaults() {
	c.defaultSubscriptions()
	c.defaultUpgrade()
	// A file without mode observes (#49): the safe default. Inject is
	// never a default; it needs an explicit mode: inject and its checks.
	if strings.TrimSpace(c.Mode) == "" {
		c.Mode = ModeObserve
	}
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
	if c.Probe.ProberRecheckRounds == 0 {
		c.Probe.ProberRecheckRounds = DefaultProbeProberRecheckRounds
	}
	if c.Probe.ProberMemory == 0 {
		c.Probe.ProberMemory = DefaultProbeProberMemory
	}
	c.defaultIndirect()
	c.defaultPathCheck()
	c.defaultExchangeHealth()
	c.defaultExchangeMaxPrefix()
	if c.Probe.MinReplies == 0 {
		c.Probe.MinReplies = DefaultProbeMinReplies
	}
	if (c.Probe.RetryLossPct > 0 || c.Probe.DispersionMS > 0) && c.Probe.RetryPackets == 0 {
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
	if c.Thresholds.ConfirmRounds == 0 {
		c.Thresholds.ConfirmRounds = 1
	}
	if f := &c.FlapQuarantine; !f.Disabled {
		if f.MaxFlips == 0 {
			f.MaxFlips = DefaultFlapMaxFlips
		}
		if f.Window == 0 {
			f.Window = DefaultFlapWindow
		}
		if f.Cooldown == 0 {
			f.Cooldown = DefaultFlapCooldown
		}
		if f.MaxCooldown == 0 {
			f.MaxCooldown = max(DefaultFlapMaxCooldown, f.Cooldown)
		}
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
	c.normalizeAnomaly()
	c.normalizeRPKI()
	if c.Instance == "" {
		c.Instance = c.Domain
	}
}
