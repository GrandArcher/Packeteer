package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"runtime"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// firstHopTTL is the TTL of a probe-path check (#150). The first router
// past the edge answers with time exceeded, so the reply address must be
// the provider's next_hop.
const firstHopTTL = 1

// pathCheckPort is the destination UDP port of a check. It is not
// expected to be listening.
const pathCheckPort = 33434

// pathSink4 and pathSink6 are the destinations of a check. The TTL is
// one, so the sink is never reached: the first router past the edge
// answers with time exceeded (or unreachable), and its address must be
// the provider's next_hop. Documentation ranges only, so the check sends
// nothing toward a customer prefix.
var (
	pathSink4 = netip.MustParseAddr("203.0.113.254")
	pathSink6 = netip.MustParseAddr("2001:db8:ffff::1")
)

// pathStatus records one provider's probe-path result. *probe.Engine
// implements it.
type pathStatus interface {
	SetPathMismatch(name string, mismatch bool)
}

// pathHop sends one TTL-limited probe from src toward dst and returns the
// address that answered. traceroute.Hop satisfies it.
type pathHop func(ctx context.Context, src, dst netip.Addr, ttl, port int, timeout time.Duration) (netip.Addr, bool, error)

// pathTarget is one provider whose probe path is checked.
type pathTarget struct {
	Name    string
	Source  netip.Addr
	NextHop netip.Addr
}

// pathChecker verifies that probes from each target's source_ip leave
// through that target's next_hop (#150). A mis-routed source silently
// measures another provider's path. Nothing is announced: a mismatch only
// fails the provider closed until a later check matches.
type pathChecker struct {
	status  pathStatus
	targets []pathTarget
	hop     pathHop
	timeout time.Duration
	limiter *rate.Limiter
	log     *slog.Logger
}

// pathTargets lists the local providers that expect probes from their
// source_ip to leave through their next_hop. A provider measured in
// another domain is checked by its peer (#30), and path_check: false
// opts one out. A target with an address Validate already rejects is
// skipped.
func pathTargets(cfg *config.Config) []pathTarget {
	var out []pathTarget
	for _, p := range cfg.Providers {
		if cfg.Remote(p) || !p.PathCheckOn() {
			continue
		}
		src, serr := netip.ParseAddr(p.SourceIP)
		nh, nerr := netip.ParseAddr(p.NextHop)
		if serr != nil || nerr != nil || src.Is4() != nh.Is4() {
			continue
		}
		out = append(out, pathTarget{Name: p.Name, Source: src, NextHop: nh.Unmap()})
	}
	return out
}

// pathCheckerFor builds the running checker, or nil when the check is
// off. The traceroute socket calls are Linux-only; other systems skip the
// check so every provider is not reported mismatched.
func pathCheckerFor(cfg *config.Config, engine *probe.Engine, lim *rate.Limiter, log *slog.Logger) *pathChecker {
	if runtime.GOOS != "linux" || !cfg.Probe.PathCheck.On() {
		return nil
	}
	targets := pathTargets(cfg)
	if len(targets) == 0 {
		return nil
	}
	return &pathChecker{status: engine, targets: targets, hop: traceroute.Hop,
		timeout: cfg.Probe.Timeout, limiter: lim, log: log}
}

// run checks every target immediately and then once per interval until
// ctx ends.
func (c *pathChecker) run(ctx context.Context, interval time.Duration) {
	for {
		c.round(ctx)
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// round checks every target once and returns how many produced a status.
func (c *pathChecker) round(ctx context.Context) int {
	checked := 0
	for _, t := range c.targets {
		if ctx.Err() != nil {
			return checked
		}
		mismatch, ok := c.one(ctx, t)
		if !ok {
			continue
		}
		c.status.SetPathMismatch(t.Name, mismatch)
		checked++
	}
	return checked
}

// one probes a single target. ok is false when no status change should be
// made: the context ended, or the source_ip could not be bound (the
// normal probes already fail that provider closed). Every other outcome,
// including no reply, is a verdict, so a mis-routed source is not missed.
func (c *pathChecker) one(ctx context.Context, t pathTarget) (mismatch, ok bool) {
	if c.limiter != nil {
		if err := c.limiter.WaitN(ctx, 1); err != nil {
			return false, false
		}
	}
	dst := pathSink4
	if t.NextHop.Is6() {
		dst = pathSink6
	}
	from, _, err := c.hop(ctx, t.Source, dst, firstHopTTL, pathCheckPort, c.timeout)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, plugin.ErrSourceUnavailable) {
			return false, false
		}
		c.log.Warn("probe path check failed", "provider", t.Name, "source", t.Source, "next_hop", t.NextHop, "err", err)
		return true, true
	}
	if !from.IsValid() {
		c.log.Warn("probe path mismatch: no first hop answered", "provider", t.Name, "source", t.Source, "next_hop", t.NextHop)
		return true, true
	}
	if from.Unmap() != t.NextHop {
		c.log.Warn("probe path mismatch", "provider", t.Name, "source", t.Source, "next_hop", t.NextHop, "first_hop", from.Unmap())
		return true, true
	}
	return false, true
}
