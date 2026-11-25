package mikrotik

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
)

// Ranking of the candidate defaults of one router (#739). It only advises: the
// result is a report and a snippet for an operator to review. Packeteer never
// edits a default, its distance or its local-pref.
const (
	// A provider passes the one ranked above it only with a 25% better score,
	// and the order then stays for 15 minutes.
	rankMargin   = 0.25
	rankCooldown = 15 * time.Minute
	// maxRanked bounds the ranks so every proposed local-pref stays positive.
	maxRanked     = 16
	localPrefTop  = 200
	localPrefStep = 10

	attrDistance  = "distance"
	attrLocalPref = "bgp-local-pref"
)

// trackDefaults notes a new reading of the router and reports whether the
// active default changed recently: from the reading that showed the change
// until one taken after the settle time. A reading seen again is not new.
func (e *Evaluator) trackDefaults(at time.Time, l routeros.L3HW) (settling bool, since time.Time) {
	if l.Applicable && !at.Equal(e.seenAt) {
		if e.prev != nil && DefaultsChanged(*e.prev, l) {
			e.changedAt = at
		}
		cur := l
		e.prev, e.seenAt = &cur, at
	}
	window := time.Duration(max(e.profile.Timing.InstallSeconds, e.profile.Timing.AgeOutSeconds)) * time.Second
	if e.changedAt.IsZero() || !at.Before(e.changedAt.Add(window)) {
		return false, time.Time{}
	}
	return true, e.changedAt
}

// attribute is what a proposal sets on a default of the given RouterOS
// protocol (belongs-to), or empty when Packeteer has no proposal for it.
func attribute(protocol string) string {
	switch p := strings.ToLower(protocol); {
	case strings.Contains(p, "bgp"):
		return attrLocalPref
	case strings.Contains(p, "static"):
		return attrDistance
	}
	return ""
}

func proposed(attr string, rank int) int64 {
	if attr == attrLocalPref {
		return int64(localPrefTop - localPrefStep*(rank-1))
	}
	return int64(rank)
}

// rankDefaults ranks the providers behind the router's default routes. While
// settling the last ranking is held and no snippet is offered.
func (e *Evaluator) rankDefaults(in Input, l routeros.L3HW, settling bool, since time.Time) *offload.DefaultsReport {
	d := &offload.DefaultsReport{Settling: settling, Providers: []offload.RankedProvider{},
		Routes: []offload.DefaultRank{}, Failovers: []offload.Failover{}}
	var providers []string
	for _, r := range l.DefaultRoutes {
		x := offload.DefaultRank{Family: r.Family, Gateway: r.Gateway, Protocol: r.Protocol, Active: r.Active}
		if a, err := netip.ParseAddr(r.Gateway); err == nil {
			x.Provider = in.NextHops[a.WithZone("")]
		}
		if x.Provider != "" && !slices.Contains(providers, x.Provider) {
			providers = append(providers, x.Provider)
		}
		d.Routes = append(d.Routes, x)
	}
	switch {
	case settling:
		d.SettlingSince = &since
		d.Providers = append(d.Providers, e.lastRank...)
		d.Note = "the active default changed: the ranking is held and no snippet is offered until a reading is taken after the settle time"
	case len(providers) == 0:
		d.Note = "no default route has a provider's next_hop as its gateway"
	case len(providers) > maxRanked:
		d.Note = fmt.Sprintf("%d providers on defaults: more than %d are not ranked", len(providers), maxRanked)
	default:
		e.lastRank = e.ranker.Rank(in.Now, providers, in.Quality)
		d.Providers = append(d.Providers, e.lastRank...)
	}

	rank := map[string]offload.RankedProvider{}
	for _, p := range d.Providers {
		rank[p.Provider] = p
		if !p.Known && d.Note == "" {
			d.Note = "provider " + p.Provider + " has no measurement: nothing is proposed"
		}
	}
	for i, r := range l.DefaultRoutes {
		x := &d.Routes[i]
		p, ok := rank[x.Provider]
		switch {
		case x.Provider == "":
			x.Note = "the gateway is no provider's next_hop: not ranked"
			continue
		case !ok:
			continue
		}
		x.Rank = p.Rank
		x.Attribute = attribute(r.Protocol)
		if x.Attribute == "" {
			x.Note = "protocol " + r.Protocol + ": no proposal"
			continue
		}
		x.Current = r.Distance
		if x.Attribute == attrLocalPref {
			x.Current = r.LocalPref
		}
		if d.Note == "" {
			x.Proposed = proposed(x.Attribute, p.Rank)
		}
	}
	if d.Note == "" {
		d.Snippet = Snippet(d.Routes, d.Providers)
	}
	return d
}

// Snippet is the RouterOS commands that give each ranked default its
// proposed distance (static) or bgp-local-pref (BGP), best provider first.
// Every default keeps suppress-hw-offload=yes, so backups stay on the CPU
// path. It is text for review; Packeteer never sends it to a router. Empty
// when no route has a proposal.
func Snippet(routes []offload.DefaultRank, ranked []offload.RankedProvider) string {
	byProvider := map[string]offload.RankedProvider{}
	for _, p := range ranked {
		byProvider[p.Provider] = p
	}
	rs := slices.DeleteFunc(slices.Clone(routes), func(r offload.DefaultRank) bool { return r.Proposed == 0 })
	if len(rs) == 0 {
		return ""
	}
	slices.SortStableFunc(rs, func(a, b offload.DefaultRank) int {
		if a.Rank != b.Rank {
			return a.Rank - b.Rank
		}
		return strings.Compare(a.Family+a.Gateway, b.Family+b.Gateway)
	})
	var b strings.Builder
	b.WriteString("# Packeteer default-route ranking for RouterOS 7. Generated for review: nothing is applied.\n")
	b.WriteString("# Check the commands against your RouterOS release first.\n")
	fmt.Fprintf(&b, "# Providers ranked by volume-weighted measured quality, lower score first. The order changes\n"+
		"# only past a %.0f%% margin and then holds for %s.\n", rankMargin*100, rankCooldown)
	b.WriteString("# Every default keeps suppress-hw-offload=yes: misses go to the CPU, backups included.\n")
	b.WriteString("# Packeteer never changes a default route, its distance or its local-pref.\n")
	for _, r := range rs {
		p := byProvider[r.Provider]
		fmt.Fprintf(&b, "\n# %d. %s via %s: score %.2f, loss %.2f%%, rtt %.1f ms (now %s %d)\n",
			r.Rank, r.Provider, r.Gateway, p.Score, p.LossPct, p.RTTMs, r.Attribute, r.Current)
		dst, table := "0.0.0.0/0", "/ip route"
		if r.Family == "ipv6" {
			dst, table = "::/0", "/ipv6 route"
		}
		if r.Attribute == attrDistance {
			fmt.Fprintf(&b, "%s set [find dst-address=%s gateway=%s] distance=%d suppress-hw-offload=yes\n", table, dst, r.Gateway, r.Proposed)
			continue
		}
		fmt.Fprintf(&b, "# BGP default: add it to the input filter chain of the connection to %s (rename the chain).\n", r.Provider)
		fmt.Fprintf(&b, "/routing filter rule add chain=%s-in place-before=0 \\\n    rule=\"if (dst == %s) { set bgp-local-pref %d; set suppress-hw-offload yes }\"\n",
			chainName(r.Provider), dst, r.Proposed)
	}
	return b.String()
}

// chainName makes a provider name safe as a RouterOS chain name.
func chainName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '-'
	}, s)
}

// failovers precomputes, for each backup default, the fix plan if it became
// the active one. Providers ahead of it, and the one active now, are taken as
// lost: Decide holds no steer to a provider that is down. res carries no
// settling freeze, because that window is what the plan waits out first.
func (e *Evaluator) failovers(d *offload.DefaultsReport, in Input, res offload.Result, blocked string, base []offload.Fix) []offload.Failover {
	var active []string
	for _, r := range d.Routes {
		if r.Active && r.Provider != "" && !slices.Contains(active, r.Provider) {
			active = append(active, r.Provider)
		}
	}
	settle := max(e.profile.Timing.InstallSeconds, e.profile.Timing.AgeOutSeconds)
	state := map[string]offload.FixState{}
	for _, f := range base {
		state[f.Prefix] = f.State
	}
	out := []offload.Failover{}
	done := map[string]bool{}
	for _, r := range d.Routes {
		if r.Provider == "" || r.Rank == 0 || slices.Contains(active, r.Provider) || done[r.Provider] {
			continue
		}
		done[r.Provider] = true
		lost := slices.Clone(active)
		for _, p := range d.Providers {
			if p.Rank < r.Rank && !slices.Contains(lost, p.Provider) {
				lost = append(lost, p.Provider)
			}
		}
		slices.Sort(lost)
		f := offload.Failover{Backup: r.Provider, Gateway: r.Gateway, Rank: r.Rank, Lost: lost, SettleSeconds: settle}
		var left []offload.Wanted
		for _, w := range in.Wanted {
			if slices.Contains(lost, w.Provider) {
				f.Dropped++
				if state[w.Prefix.String()] == offload.FixOffload {
					f.Freed++
				}
				continue
			}
			left = append(left, w)
		}
		fixes, _ := e.fixStates(in.Now, left, res, blocked)
		for _, x := range fixes {
			switch x.State {
			case offload.FixOffload:
				f.Offload++
			case offload.FixSoftware:
				f.Software++
			case offload.FixWithhold:
				f.Withhold++
			default:
				f.Blocked++
			}
		}
		out = append(out, f)
	}
	slices.SortFunc(out, func(a, b offload.Failover) int { return a.Rank - b.Rank })
	return out
}
