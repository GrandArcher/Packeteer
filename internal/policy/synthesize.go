package policy

import (
	"maps"
	"net/netip"
	"slices"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// withSynthesized returns in with a result of its own for every measured
// sub-range listed in in.Synthesize (#122), so a sub-range is decided like
// any other prefix: thresholds, confirm_rounds, hold time, cooldown, and
// max_improvements. Its native provider is its covering prefix's, and it
// is in the RIB only while the covering prefix is: a covering prefix
// missing from the RIB retires the sub-range at once, with no
// NativePathConfirm window, unless Packeteer steers the covering prefix
// itself. A covering prefix under a static or ignore policy is not split,
// and the sub-range takes no policy of its own. A sub-range some source
// also lists as a target is left to that target. cover maps each added
// sub-range to its covering prefix. The caller's slices and maps are not
// changed.
func withSynthesized(in Input) (Input, map[netip.Prefix]netip.Prefix) {
	if len(in.Synthesize) == 0 {
		return in, nil
	}
	direct := map[netip.Prefix]bool{}
	for _, r := range in.Results {
		direct[r.Prefix] = true
	}
	cover := map[netip.Prefix]netip.Prefix{}
	results := slices.Clone(in.Results)
	native := maps.Clone(in.Native)
	if native == nil {
		native = map[netip.Prefix]string{}
	}
	noRoute := maps.Clone(in.NoRoute)
	rpki := maps.Clone(in.RPKI)
	irr := maps.Clone(in.IRR)
	for _, r := range in.Results {
		if v, ok := in.Policies[r.Prefix]; ok && (v.Action == plugin.PolicyIgnore || v.Action == plugin.PolicyStatic) {
			continue
		}
		for _, sr := range r.Subranges {
			c, ok := in.Synthesize[sr.Prefix]
			if !ok || c != r.Prefix || direct[sr.Prefix] {
				continue
			}
			res := probe.Result{Provider: r.Provider, Prefix: sr.Prefix, Target: sr.Target, Prober: sr.Prober,
				Stats: sr.Stats, Err: sr.Err, Time: sr.Time, Round: r.Round, Confidence: r.Confidence}
			if res.Err == "" {
				res.Err = r.Err
			}
			if res.Time.IsZero() {
				res.Time = r.Time
			}
			results = append(results, res)
			cover[sr.Prefix] = c
			if n, ok := in.Native[c]; ok {
				native[sr.Prefix] = n
			}
			if m, ok := in.NoRoute[c]; ok {
				noRoute[sr.Prefix] = m
			}
			if m, ok := in.RPKI[c]; ok {
				rpki[sr.Prefix] = m
			}
			if m, ok := in.IRR[c]; ok {
				irr[sr.Prefix] = m
			}
		}
	}
	in.Results, in.Native, in.NoRoute, in.RPKI, in.IRR = results, native, noRoute, rpki, irr
	return in, cover
}
