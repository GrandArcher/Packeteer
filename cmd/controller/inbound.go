package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// inboundInput is telemetry plus the probe results that hold a measurement
// from providers whose probe source is up.
func inboundInput(ctx context.Context, plugins *pluginhost.Set, in policy.Input) inbound.Input {
	out := inbound.Input{Usage: collectTelemetry(ctx, plugins)}
	for _, r := range in.Results {
		if !r.OK() || !in.ProviderUp[r.Provider] || r.Stats.Sent == 0 {
			continue
		}
		out.Paths = append(out.Paths, inbound.Path{Provider: r.Provider, Prefix: r.Prefix, LossPct: r.Stats.LossPct, RTT: r.Stats.RTTAvg, Time: r.Time})
	}
	return out
}

// newInbound returns nil when inbound is not configured. others counts
// outbound improvements on the wire for the shared cap.
func newInbound(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, others func() int, mit *mitigation.Controller, held func(netip.Prefix) bool, log *slog.Logger) (*inbound.Controller, error) {
	in := cfg.Inbound
	if in == nil {
		return nil, nil
	}
	var ann plugin.InboundAnnouncer
	if plugins.Inbound != nil {
		ann = plugins.Inbound.Plugin
	}
	ic := inbound.Config{
		Mode:            in.Mode,
		Community:       cfg.PacketeerCommunity,
		LocalPref:       in.LocalPref,
		MaxImprovements: in.MaxImprovements,
		SharedCap:       *cfg.MaxImprovements,
		Others:          others,
		HoldTime:        cfg.HoldTime,
		TTL:             cfg.ImprovementTTL,
		ReleasePct:      in.ReleasePct,
		MaxAge:          inbound.DefaultMaxAge,
		PerfMaxAge:      maxResultAge(cfg),
		Damping: inbound.Damping{
			Disabled: in.Damping.Disabled, Confirm: in.Damping.Confirm,
			Backoff: in.Damping.Backoff, MaxHold: in.Damping.MaxHold,
		},
		Moderated: map[string]bool{},
		Excluded:  func(p netip.Prefix) bool { return mit.Holds(p) || held(p) },
		Leader:    haLeader(plugins),
	}
	if pf := in.Performance; pf != nil {
		ic.Performance = &inbound.PerfConfig{LossPct: pf.LossPct, LatencyMs: pf.LatencyMs, MinPrefixes: pf.MinPrefixes, ReleasePct: pf.ReleasePct}
	}
	for _, t := range in.Moderated {
		ic.Moderated[t] = true
	}
	ic.ASN = map[string]uint32{}
	for _, p := range cfg.Providers {
		if !p.Exclude {
			ic.Providers = append(ic.Providers, p.Name)
			ic.ASN[p.Name] = p.ASN
		}
	}
	for _, s := range in.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ic.Prefixes = append(ic.Prefixes, p)
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ic.Allowlist = append(ic.Allowlist, p)
	}
	var gate inbound.RIB
	if view != nil {
		gate = ribGate{view}
	}
	return inbound.New(ic, ann, gate, log.With("component", "inbound"))
}

// checkInboundMED refuses a catalog MED action (#303) on a provider that
// no other non-excluded provider shares an asn with: the MED moves inbound
// traffic between links to one AS, so it needs a second link.
func checkInboundMED(cfg *config.Config, plugins *pluginhost.Set) error {
	if cfg.Inbound == nil || plugins.Inbound == nil {
		return nil
	}
	links := map[uint32]int{}
	for _, p := range cfg.Providers {
		if !p.Exclude && p.ASN != 0 {
			links[p.ASN]++
		}
	}
	for _, p := range cfg.Providers {
		act, ok := plugins.Inbound.Plugin.Action(p.Name)
		if !ok || act.MED == 0 {
			continue
		}
		if p.Exclude || links[p.ASN] < 2 {
			return fmt.Errorf("inbound: provider %q has a med action but no other provider shares its asn (set providers[].asn on each link to that AS)", p.Name)
		}
	}
	return nil
}

// bindInbound attaches the inbound announcer to the speaker when inbound
// injects. It runs after the gobgp announcer has installed its export
// policy.
func bindInbound(cfg *config.Config, plugins *pluginhost.Set, srv any) error {
	if cfg.InboundMode() != config.ModeInject {
		return nil
	}
	if plugins.Inbound == nil {
		return errors.New("inbound: inject requires inbound.announcer")
	}
	b, ok := plugins.Inbound.Plugin.(interface {
		Bind(any, string, []netip.Prefix) error
	})
	if !ok {
		return fmt.Errorf("inbound: announcer %T cannot publish on the embedded iBGP speaker", plugins.Inbound.Plugin)
	}
	var prefixes []netip.Prefix
	for _, s := range cfg.Inbound.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return err
		}
		prefixes = append(prefixes, p)
	}
	return b.Bind(srv, cfg.PacketeerCommunity, prefixes)
}

// runInbound plans inbound steers and syncs them. Sync is a no-op outside
// inject. results are the probe results the decision round used.
func runInbound(ctx context.Context, now time.Time, inb *inbound.Controller, plugins *pluginhost.Set, log *slog.Logger, mode string, in policy.Input) ([]inbound.Change, error) {
	if inb == nil {
		return nil, nil
	}
	changes := inb.Plan(now, inboundInput(ctx, plugins, in))
	for _, c := range changes {
		act := c.Steer.Action
		log.Info("inbound "+c.Action, "mode", mode, "trigger", c.Steer.Trigger, "moderated", c.Steer.Moderated,
			"provider", c.Steer.Provider, "in_mbps_95", c.Steer.InMbps95, "commit_mbps", c.Steer.CommitMbps,
			"hold", c.Steer.Hold, "flaps", c.Steer.Flaps, "inertia_mbps", c.Steer.Shift,
			"action", act.Name, "prepend", act.Prepend, "withhold", act.Withhold, "med", act.MED, "communities", strings.Join(act.Communities, " "), "reason", c.Reason)
	}
	actx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := inb.Sync(actx)
	if err != nil {
		log.Error("inbound announce", "err", err)
	}
	return changes, err
}
