package main

import (
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// localPrefTables is the cause and provider local-preference overrides
// (#132). Nil means every route uses the global local_pref. A provider
// value wins over a cause value.
func localPrefTables(cfg *config.Config) (cause, provider map[string]uint32) {
	if cfg == nil {
		return nil, nil
	}
	put := func(m map[string]uint32, k string, v *uint32) map[string]uint32 {
		if v == nil {
			return m
		}
		if m == nil {
			m = map[string]uint32{}
		}
		m[k] = *v
		return m
	}
	lp := cfg.LocalPrefCause
	cause = put(cause, plugin.CausePerformance, lp.Performance)
	cause = put(cause, plugin.CauseStatic, lp.Static)
	cause = put(cause, plugin.CauseCommit, lp.Commit)
	cause = put(cause, plugin.CauseCost, lp.Cost)
	for _, p := range cfg.Providers {
		provider = put(provider, p.Name, p.LocalPref)
	}
	return cause, provider
}

// formatLocalPrefOverrides is the -check suffix for set overrides. Causes
// are printed in a fixed order; providers follow the config.
func formatLocalPrefOverrides(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	var b strings.Builder
	type named struct {
		name string
		v    *uint32
	}
	var cs []string
	for _, c := range []named{
		{plugin.CausePerformance, cfg.LocalPrefCause.Performance},
		{plugin.CauseStatic, cfg.LocalPrefCause.Static},
		{plugin.CauseCommit, cfg.LocalPrefCause.Commit},
		{plugin.CauseCost, cfg.LocalPrefCause.Cost},
	} {
		if c.v != nil {
			cs = append(cs, fmt.Sprintf("%s:%d", c.name, *c.v))
		}
	}
	if len(cs) > 0 {
		b.WriteString(" cause=")
		b.WriteString(strings.Join(cs, ","))
	}
	var ps []string
	for _, p := range cfg.Providers {
		if p.LocalPref != nil {
			ps = append(ps, fmt.Sprintf("%s:%d", p.Name, *p.LocalPref))
		}
	}
	if len(ps) > 0 {
		b.WriteString(" provider=")
		b.WriteString(strings.Join(ps, ","))
	}
	return b.String()
}

// communityTables is the extra outbound communities per cause and per
// provider (#132). They are added after packeteer_community. Nil means none.
func communityTables(cfg *config.Config) (cause, provider map[string][]string) {
	if cfg == nil {
		return nil, nil
	}
	put := func(m map[string][]string, k string, v []string) map[string][]string {
		if len(v) == 0 {
			return m
		}
		if m == nil {
			m = map[string][]string{}
		}
		m[k] = slices.Clone(v)
		return m
	}
	cc := cfg.CommunitiesCause
	cause = put(cause, plugin.CausePerformance, cc.Performance)
	cause = put(cause, plugin.CauseStatic, cc.Static)
	cause = put(cause, plugin.CauseCommit, cc.Commit)
	cause = put(cause, plugin.CauseCost, cc.Cost)
	for _, p := range cfg.Providers {
		provider = put(provider, p.Name, p.Communities)
	}
	return cause, provider
}

// formatCommunityOverrides is the -check suffix for extra communities.
// Lists use "+" so a large community's colons stay unambiguous. Causes are
// printed in a fixed order; providers follow the config.
func formatCommunityOverrides(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	join := func(list []string) string { return strings.Join(list, "+") }
	var b strings.Builder
	cc := cfg.CommunitiesCause
	var cs []string
	for _, c := range []struct {
		name string
		list []string
	}{
		{plugin.CausePerformance, cc.Performance},
		{plugin.CauseStatic, cc.Static},
		{plugin.CauseCommit, cc.Commit},
		{plugin.CauseCost, cc.Cost},
	} {
		if len(c.list) > 0 {
			cs = append(cs, c.name+":"+join(c.list))
		}
	}
	if len(cs) > 0 {
		b.WriteString(" communities=")
		b.WriteString(strings.Join(cs, ","))
	}
	var ps []string
	for _, p := range cfg.Providers {
		if len(p.Communities) > 0 {
			ps = append(ps, p.Name+":"+join(p.Communities))
		}
	}
	if len(ps) > 0 {
		b.WriteString(" provider=")
		b.WriteString(strings.Join(ps, ","))
	}
	return b.String()
}

func newController(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, inb *inbound.Controller, mit *mitigation.Controller, held func(netip.Prefix) bool, log *slog.Logger) (*announce.Controller, error) {
	var ann plugin.Announcer
	if plugins.Announcer != nil {
		ann = plugins.Announcer.Plugin
	}
	causeLP, providerLP := localPrefTables(cfg)
	causeC, providerC := communityTables(cfg)
	ac := announce.Config{
		Mode:                cfg.Mode,
		LocalPref:           cfg.LocalPref,
		CauseLocalPref:      causeLP,
		ProviderLocalPref:   providerLP,
		Community:           cfg.PacketeerCommunity,
		CauseCommunities:    causeC,
		ProviderCommunities: providerC,
		MaxImprovements:     *cfg.MaxImprovements,
		NextHops:            map[string]netip.Addr{},
		ASPath:              cfg.BGP.ASPath,
		Leader:              haLeader(plugins),
	}
	if ms := cfg.MoreSpecific; ms != nil && ms.Enabled {
		ac.MoreSpecific, ac.MaxRoutes = true, ms.MaxRoutes
	}
	if inb != nil {
		ac.Others = inb.Active
	}
	// A prefix is reserved while inbound steering owns it or a mitigation
	// rule holds it (#28). Both are nil-safe.
	ac.Reserved = func(p netip.Prefix) bool { return inb.Reserved(p) || mit.Holds(p) }
	ac.Held = held
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		ac.NextHops[p.Name] = nh
	}
	for _, s := range cfg.Allowlist.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ac.Allowlist = append(ac.Allowlist, p)
	}
	routers, err := routerExports(cfg)
	if err != nil {
		return nil, err
	}
	ac.Routers = routers
	return announce.New(ac, ann, ribGate{view}, log)
}

// routerSummary is a neighbor's provider reachability for -check, or ""
// when it reaches every provider.
func routerSummary(n config.BGPNeighbor) string {
	if !n.Routed() {
		return ""
	}
	out := " providers=" + strings.Join(n.Providers, ",")
	for _, name := range slices.Sorted(maps.Keys(n.NextHops)) {
		out += " " + name + "_via=" + n.NextHops[name]
	}
	return out
}

// routerExports is per-router provider reachability for the announcer
// (#27), or nil when no neighbor restricts providers. A router with no
// providers or next_hops of its own still reaches every provider directly.
func routerExports(cfg *config.Config) ([]plugin.RouterExport, error) {
	if !slices.ContainsFunc(cfg.BGP.Neighbors, config.BGPNeighbor.Routed) {
		return nil, nil
	}
	provNH := map[string]netip.Addr{}
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		provNH[p.Name] = nh
	}
	var out []plugin.RouterExport
	for _, n := range cfg.BGP.Neighbors {
		a, err := parseAddr(n.Address)
		if err != nil {
			return nil, err
		}
		re := plugin.RouterExport{Neighbor: a}
		if n.Routed() {
			re.Via = map[netip.Addr]netip.Addr{}
			for name, s := range n.NextHops {
				nh, err := parseAddr(s)
				if err != nil {
					return nil, err
				}
				re.Via[provNH[name]] = nh
			}
			for _, p := range cfg.Providers {
				_, via := n.NextHops[p.Name]
				if !via && !slices.Contains(n.Providers, p.Name) {
					re.Blocked = append(re.Blocked, provNH[p.Name])
				}
			}
		}
		out = append(out, re)
	}
	return out, nil
}
