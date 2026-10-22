package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	checks "github.com/GrandArcher/Packeteer/internal/preflight"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/snippet"
)

// preflightFile keeps the administrator's confirmations next to the storage
// file. Without a storage file they are kept in memory only.
const preflightFile = "preflight.json"

// preflightTimeout bounds one run: the speaker read and one first-hop probe
// per provider.
const preflightTimeout = 30 * time.Second

// preflightSource gathers the facts the preflight checks read (#221). It
// only reads: the sessions, the learned RIB, the leak watch, and one
// TTL-limited probe per provider toward a documentation address.
type preflightSource struct {
	live    *liveConfig
	view    *rib.View
	leaks   *leakwatch.Watcher
	plugins *pluginhost.Set
	limiter *rate.Limiter
	hop     pathHop
	log     *slog.Logger
}

func (p *preflightSource) facts(ctx context.Context) checks.Facts {
	cfg := p.live.snapshot()
	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	f := checks.Facts{
		Community:   cfg.PacketeerCommunity,
		Announcer:   p.plugins != nil && p.plugins.Announcer != nil,
		Leaks:       len(p.leaks.Status().Leaks),
		Fingerprint: preflightFingerprint(cfg),
	}
	up := map[netip.Addr]bool{}
	if p.view != nil {
		for _, ps := range p.view.Peers() {
			up[ps.Address.Unmap()] = ps.Established
		}
		f.RIBReady, f.Learned = p.view.Ready(), p.view.Len()
		timers, err := p.view.SessionTimers(ctx)
		if err != nil {
			f.TimersErr = err.Error()
		}
		for _, t := range timers {
			f.Timers = append(f.Timers, checks.Timers{Address: t.Address.String(), Hold: t.HoldTime, LocalGR: t.LocalGR, RouterGR: t.RouterGR})
		}
	}
	for _, n := range cfg.BGP.Neighbors {
		addr, _ := netip.ParseAddr(n.Address)
		f.Neighbors = append(f.Neighbors, checks.Neighbor{Address: n.Address, Established: up[addr.Unmap()]})
	}
	f.Providers = p.providers(ctx, cfg)
	return f
}

// providers checks, for each provider measured here, which way a probe from
// its source_ip leaves.
func (p *preflightSource) providers(ctx context.Context, cfg *config.Config) []checks.Provider {
	checker := &pathChecker{hop: p.hop, timeout: cfg.Probe.Timeout, limiter: p.limiter, log: p.log}
	targets := map[string]pathTarget{}
	if runtime.GOOS == "linux" && cfg.Probe.PathCheck.On() {
		for _, t := range pathTargets(cfg) {
			targets[t.Name] = t
		}
	}
	var out []checks.Provider
	for _, pr := range cfg.Providers {
		if cfg.Remote(pr) {
			continue
		}
		row := checks.Provider{Name: pr.Name, SourceIP: pr.SourceIP, NextHop: pr.NextHop, Egress: checks.EgressUnchecked}
		t, ok := targets[pr.Name]
		if !ok {
			row.Why = uncheckedWhy(cfg, pr)
			out = append(out, row)
			continue
		}
		r := checker.check(ctx, t)
		switch {
		case !r.ok && r.why == "":
			row.Why = "the check was cut short"
		case !r.ok:
			row.Egress, row.Why = checks.EgressNoReply, r.why
		case !r.mismatch:
			row.Egress, row.FirstHop = checks.EgressOK, r.from.String()
		case r.from.IsValid():
			row.Egress, row.FirstHop = checks.EgressMismatch, r.from.String()
		default:
			row.Egress, row.Why = checks.EgressNoReply, r.why
		}
		out = append(out, row)
	}
	return out
}

func uncheckedWhy(cfg *config.Config, p config.Provider) string {
	switch src, _ := netip.ParseAddr(p.SourceIP); {
	case runtime.GOOS != "linux":
		return "the path check runs on Linux only"
	case !cfg.Probe.PathCheck.On():
		return "probe.path_check is off"
	case !p.PathCheckOn():
		return "path_check is off for this provider"
	case src.IsLoopback():
		return "the source_ip is a loopback address; its traffic never leaves this host"
	default:
		return "the source_ip and next_hop are not the same address family"
	}
}

// preflightFingerprint identifies what the administrator confirmed the
// router filters for: the AS, the community, and the routers.
func preflightFingerprint(cfg *config.Config) string {
	var addrs []string
	for _, n := range cfg.BGP.Neighbors {
		addrs = append(addrs, n.Address)
	}
	slices.Sort(addrs)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", cfg.ASN, cfg.PacketeerCommunity, strings.Join(addrs, ","))))
	return hex.EncodeToString(sum[:8])
}

// snippetFor renders the router config for the running config.
func snippetFor(live *liveConfig, vendor string) (string, error) {
	params, err := snippet.ForConfig(live.snapshot())
	if err != nil {
		return "", err
	}
	return snippet.Join(vendor, params)
}

// preflightAPI is the runner with the router snippets of the running config.
type preflightAPI struct {
	*checks.Runner
	live *liveConfig
}

func (p preflightAPI) Snippet(vendor string) (string, error) { return snippetFor(p.live, vendor) }

// Gate checks that the candidate keeps the setup the confirmations were made
// for, then runs the checks.
func (p preflightAPI) Gate(ctx context.Context, candidate []byte) error {
	next, err := config.Parse(candidate)
	if err != nil {
		return fmt.Errorf("the candidate config does not load: %w", err)
	}
	return p.Runner.Gate(ctx, preflightFingerprint(next))
}

// newPreflight builds the onboarding checks. A confirmations file that cannot
// be read is not fatal: the filters stay unverified until confirmed again.
func newPreflight(live *liveConfig, view *rib.View, lw *leakwatch.Watcher, plugins *pluginhost.Set, limiter *rate.Limiter, log *slog.Logger) preflightAPI {
	store, err := checks.OpenStore(besideStorage(plugins, preflightFile))
	if err != nil {
		log.Warn("preflight confirmations not read; they are asked for again", "err", err)
		store, _ = checks.OpenStore("")
	}
	src := &preflightSource{live: live, view: view, leaks: lw, plugins: plugins, limiter: limiter, hop: traceroute.Hop, log: log}
	return preflightAPI{Runner: checks.NewRunner(src.facts, store, nil), live: live}
}
