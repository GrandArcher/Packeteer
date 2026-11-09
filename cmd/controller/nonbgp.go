package main

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/nonbgp"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// nonbgpSyncTimeout bounds one pass over the router's API.
const nonbgpSyncTimeout = 10 * time.Second

// nonbgpState is the flow-driven mode for a site whose router has no BGP
// (#300): the synthetic prefix table the flow source reads, and the steer
// controller that turns improvements into static routes. A nil state is
// every other deployment, and its methods do nothing.
type nonbgpState struct {
	table  *nonbgp.Table
	steer  *nonbgp.Steer
	meta   nonbgp.Meta
	native string
	asns   map[string]uint32
	log    *slog.Logger
}

// newNonBGP builds the state for cfg, or returns nil when the mode is off.
// Observe and suggest build a steer controller that never calls the
// steerer.
func newNonBGP(cfg *config.Config, plugins *pluginhost.Set, log *slog.Logger) (*nonbgpState, error) {
	n := cfg.NonBGP
	if n == nil {
		return nil, nil
	}
	var cov plugin.Covering
	meta := nonbgp.Meta{Mode: cfg.Mode, DefaultProvider: n.DefaultProvider, WidenBits: *n.WidenBits, MaxBlocks: n.MaxBlocks}
	if plugins.Covering != nil {
		cov, meta.Covering = plugins.Covering.Plugin, plugins.Covering.Type
	}
	table := nonbgp.NewTable(nonbgp.Options{WidenBits: *n.WidenBits, Idle: n.Idle, MaxBlocks: n.MaxBlocks, Log: log}, cov)
	sc := nonbgp.SteerConfig{
		Inject:   cfg.Mode == config.ModeInject,
		Max:      *cfg.MaxImprovements,
		NextHops: map[string]netip.Addr{},
		Live:     table.Has,
	}
	asns := map[string]uint32{}
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		sc.NextHops[p.Name] = nh
		if p.ASN != 0 {
			asns[p.Name] = p.ASN
		}
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		sc.Allowlist = append(sc.Allowlist, p)
	}
	var drv plugin.Steerer
	if plugins.Steerer != nil {
		drv, meta.Steerer = plugins.Steerer.Plugin, plugins.Steerer.Type
	}
	steer, err := nonbgp.NewSteer(sc, drv, log)
	if err != nil {
		return nil, err
	}
	return &nonbgpState{table: table, steer: steer, meta: meta, native: n.DefaultProvider, asns: asns, log: log}, nil
}

// wireLookup makes every flow source count destinations under
// their synthetic prefix.
func (s *nonbgpState) wireLookup(plugins *pluginhost.Set) {
	if s == nil {
		return
	}
	for _, src := range plugins.SourcesSnapshot() {
		if l, ok := src.Plugin.(prefixLookup); ok {
			l.SetPrefixLookup(s.table.Lookup)
		}
	}
}

// Refresh ages the table and recomputes the synthetic prefixes. It runs
// before each decision round.
func (s *nonbgpState) Refresh() {
	if s != nil {
		s.table.Refresh()
	}
}

// Fill gives Decide the synthetic prefixes as the learned view, each
// exited through the default route's provider.
func (s *nonbgpState) Fill(in *policy.Input) {
	if s != nil {
		s.table.Fill(in, s.native)
	}
}

// Sync puts the improvements on the router. In observe and suggest it
// does nothing.
func (s *nonbgpState) Sync(imps []policy.Improvement) error {
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), nonbgpSyncTimeout)
	defer cancel()
	err := s.steer.Sync(ctx, imps)
	if err != nil {
		// The announce event fires only when the state flips, so each failing
		// round, a failed withdraw included, is logged here.
		s.log.Error("non-BGP steer", "err", err)
	}
	return err
}

// WithdrawAll removes every route this process put on the router.
func (s *nonbgpState) WithdrawAll(ctx context.Context) error {
	if s == nil {
		return nil
	}
	return s.steer.WithdrawAll(ctx)
}

// Has reports whether p is a synthetic prefix. It labels API rows.
func (s *nonbgpState) Has(p netip.Prefix) bool {
	return s != nil && s.table.Has(p)
}

// Status is the /api/synthetic body.
func (s *nonbgpState) Status() nonbgp.Status {
	return nonbgp.Report(s.meta, s.table, s.steer)
}

// addTruncated adds the blocks the table could not track to the passive
// caps' truncation counts.
func (s *nonbgpState) addTruncated(m map[string]uint64) {
	if s != nil {
		m["nonbgp.max_blocks"] += s.table.Stats().Dropped
	}
}

// herdView is the herd's stand-in for a RIB view.
func (s *nonbgpState) herdView() herd.RIB {
	return nonbgp.HerdView{Table: s.table, ProviderASN: s.asns}
}

// forHerd maps a probe round to the announced prefixes the herd may see.
func (s *nonbgpState) forHerd(b []probe.Result) []probe.Result {
	return nonbgp.ForHerd(s.table, b)
}

// Run looks up the announced prefix of new blocks until ctx ends.
func (s *nonbgpState) Run(ctx context.Context) {
	if s != nil {
		s.table.Run(ctx)
	}
}

// pluginType is the configured type of an optional plugin, or "none".
func pluginType[T plugin.Lifecycle](i *pluginhost.Instance[T]) string {
	if i == nil {
		return "none"
	}
	return i.Type
}
