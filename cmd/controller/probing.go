package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/sockmark"
	"github.com/GrandArcher/Packeteer/internal/troubleshoot"
)

// newTools builds the troubleshooting tools. They share the provider
// sources and prober chain with the engine. On-demand results go back to
// the HTTP caller only. Optimize is the one write: it adds a learned prefix
// to the engine's probe targets (wired through SetQueue).
func newTools(cfg *config.Config, plugins *pluginhost.Set, lim *rate.Limiter) (*troubleshoot.Tools, error) {
	var providers []probe.Provider
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			// Measured by the peer in its domain (#30), never probed here.
			continue
		}
		src, err := parseAddr(p.SourceIP)
		if err != nil {
			return nil, err
		}
		var hop netip.Addr
		if p.NextHop != "" {
			hop, err = parseAddr(p.NextHop)
			if err != nil {
				return nil, err
			}
		}
		providers = append(providers, probe.Provider{Name: p.Name, Source: src, NextHop: hop, Marking: markingOf(p)})
	}
	var probers []probe.NamedProber
	for _, p := range plugins.Probers {
		probers = append(probers, probe.NamedProber{Name: p.Name, Prober: p.Plugin})
	}
	rpm := cfg.Troubleshoot.RequestsPerMinute
	opt := troubleshoot.Options{
		Enabled:   cfg.Troubleshoot.Enabled,
		Providers: providers,
		Probers:   probers,
		Packets:   cfg.Probe.Packets,
		Timeout:   cfg.Probe.Timeout,
		MaxHops:   cfg.Troubleshoot.MaxHops,
		Hop:       traceroute.Hop,
		Reverse:   reverseName,
		Indirect:  indirectTracer(cfg),
		Limiter:   rate.NewLimiter(rate.Every(time.Minute/time.Duration(rpm)), min(rpm, 3)),
		// The indirect fallback trace packets share the engine's budget.
		PacketLimiter: lim,
		ExchangeLANs:  exchangeLANPrefixes(cfg),
	}
	if plugins.Whois != nil {
		opt.Whois = plugins.Whois.Plugin
	}
	if plugins.Scorer != nil {
		opt.Scorer = plugins.Scorer.Plugin
	}
	return troubleshoot.New(opt), nil
}

// reverseName is the PTR name of a traceroute hop through the container's
// resolver, or "" when there is none.
func reverseName(ctx context.Context, a netip.Addr) string {
	names, err := net.DefaultResolver.LookupAddr(ctx, a.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func newEngine(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger, onRound func(), onProbe func(probe.Result), lim *rate.Limiter) (*probe.Engine, error) {
	var providers []probe.Provider
	for _, p := range cfg.Providers {
		if cfg.Remote(p) {
			// Measured by the peer in its domain (#30), never probed here.
			continue
		}
		src, err := parseAddr(p.SourceIP)
		if err != nil {
			return nil, err
		}
		providers = append(providers, probe.Provider{Name: p.Name, Source: src, Marking: markingOf(p)})
	}
	var probers []probe.NamedProber
	for _, p := range plugins.Probers {
		probers = append(probers, probe.NamedProber{Name: p.Name, Prober: p.Plugin})
	}
	var sources []probe.NamedSource
	for _, s := range plugins.Sources {
		sources = append(sources, probe.NamedSource{Name: s.Name, Source: s.Plugin})
	}
	onResult := func(r probe.Result) {
		logResult(log, r)
		if onProbe != nil {
			onProbe(r)
		}
	}
	return probe.New(providers, probers, sources, probe.Options{
		Interval:             cfg.Probe.Interval,
		Timeout:              cfg.Probe.Timeout,
		Packets:              cfg.Probe.Packets,
		Workers:              cfg.Probe.Workers,
		PerTargetConcurrency: cfg.Probe.PerTargetConcurrency,
		RoundTimeout:         maxResultAge(cfg),
		RetryLossPct:         cfg.Probe.RetryLossPct,
		RetryPackets:         cfg.Probe.RetryPackets,
		MinReplies:           cfg.Probe.MinReplies,
		Dispersion:           time.Duration(cfg.Probe.DispersionMS) * time.Millisecond,
		ProberRecheckRounds:  cfg.Probe.ProberRecheckRounds,
		ProberMemory:         cfg.Probe.ProberMemory,
		ExchangeLANs:         exchangeLANPrefixes(cfg),
		Indirect:             indirectOptions(cfg),
		Limiter:              lim,
		Logger:               log,
		OnResult:             onResult,
		OnRound:              onRound,
	})
}

// packetLimiter is the global probe.rate_limit_pps budget. The probe engine
// and the troubleshooting tools' indirect fallback trace packets share it.
func packetLimiter(cfg *config.Config) *rate.Limiter {
	burst := cfg.Probe.RateLimitPPS
	need := cfg.Probe.Packets
	if cfg.Probe.RetryPackets > need {
		need = cfg.Probe.RetryPackets
	}
	if burst < need {
		burst = need
	}
	return rate.NewLimiter(rate.Limit(cfg.Probe.RateLimitPPS), burst)
}

// indirectTracer walks TTL from a provider's source with the built-in Linux
// traceroute. It uses the probe.indirect settings when they are enabled and
// the same defaults otherwise, so an on-demand probe's indirect fallback
// (#126) does not need background indirect probing on. Hops on an exchange
// LAN are not adopted.
func indirectTracer(cfg *config.Config) traceroute.Tracer {
	in := cfg.Probe.Indirect
	if in == nil || !in.Enabled {
		in = &config.ProbeIndirect{MaxHops: config.DefaultIndirectMaxHops, Probes: config.DefaultIndirectProbes,
			MinReplies: config.DefaultIndirectMinReplies, Port: config.DefaultIndirectPort, Timeout: config.DefaultIndirectTimeout}
	}
	lans := exchangeLANPrefixes(cfg)
	return traceroute.Tracer{
		MaxHops:    in.MaxHops,
		Probes:     in.Probes,
		MinReplies: in.MinReplies,
		Port:       in.Port,
		Timeout:    in.Timeout,
		Hop:        traceroute.Hop,
		Skip:       func(a netip.Addr) bool { return exchange.ContainsAddr(lans, a) },
	}
}

// indirectOptions turns probe.indirect into engine options (#123). Nil
// when it is omitted or disabled. Traces use indirectTracer; every packet
// waits on the engine's rate limit.
func indirectOptions(cfg *config.Config) *probe.Indirect {
	in := cfg.Probe.Indirect
	if in == nil || !in.Enabled {
		return nil
	}
	return &probe.Indirect{
		Tracer:   indirectTracer(cfg),
		Budget:   in.Budget,
		MinShare: in.Timeout,
		CacheTTL: in.CacheTTL,
		MaxQueue: in.MaxQueue,
	}
}

// retainImprovedPrefixes keeps every active improvement's prefix in the
// probe set after its configured source drops it (#116). The probe engine
// reuses the last host and interval. An empty list clears the set, so the
// next completed round drops a prefix no source still lists.
func retainImprovedPrefixes(engine *probe.Engine, imps []policy.Improvement) {
	if engine == nil {
		return
	}
	ps := make([]netip.Prefix, len(imps))
	for i, imp := range imps {
		ps[i] = imp.Prefix
	}
	engine.SetRetained(ps)
}

// maxResultAge is how old a measurement may be before Decide treats it as
// stale. It is also the overall probe-round deadline, so a stuck round
// cannot outlive the freshness window.
func maxResultAge(cfg *config.Config) time.Duration {
	pkts := cfg.Probe.Packets
	// Same condition as the probe engine: a second probe can run when
	// loss retry or dispersion escalation is on, and then the window is
	// 3*interval + (packets + retry_packets)*timeout.
	if cfg.Probe.RetryPackets > 0 && (cfg.Probe.RetryLossPct > 0 || cfg.Probe.DispersionMS > 0) {
		pkts += cfg.Probe.RetryPackets
	}
	return 3*cfg.Probe.Interval + time.Duration(pkts)*cfg.Probe.Timeout
}

func logResult(log *slog.Logger, r probe.Result) {
	if !r.OK() {
		log.Warn("probe failed", "provider", r.Provider, "prefix", r.Prefix, "target", r.Target, "err", r.Err)
		return
	}
	s := r.Stats
	log.Info("probe", "provider", r.Provider, "prefix", r.Prefix, "target", r.Target, "targets", r.Targets, "prober", r.Prober,
		"loss_pct", s.LossPct, "rtt_avg", s.RTTAvg, "rtt_min", s.RTTMin, "rtt_max", s.RTTMax, "jitter", s.Jitter,
		"sent", s.Sent, "received", s.Received)
}

// markingOf is the probe tag of a provider that shares its source_ip (#157).
func markingOf(p config.Provider) sockmark.Marking {
	return sockmark.Marking{Mark: p.FwMark, DSCP: uint8(p.DSCP)}
}
