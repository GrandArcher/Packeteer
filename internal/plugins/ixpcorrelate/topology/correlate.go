package topology

import (
	"sort"
	"strconv"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// groupKey identifies one switch, colo, or bundle. Switch ids are per
// IXP, so the IXP id is part of every key. id is the switch id, the colo
// name, or the bundle name.
type groupKey struct {
	scope string
	ixp   int
	id    string
}

// group is one group in one round.
type group struct {
	key      groupKey
	name     string
	members  int
	degraded []uint32
}

// member is a member that is degraded on every measured address.
type member struct {
	asn       uint32
	name      string
	addresses int
}

// observation is one round, before any hysteresis.
type observation struct {
	groups []group
	// firing is the keys of the groups that meet the thresholds.
	firing map[groupKey]bool
	// alone is the degraded members that no firing group explains.
	alone []member
}

type addrKey struct {
	ixp, vlan int
	addr      string
}

type addrState struct {
	asn      uint32
	name     string
	ixp      int
	switches []plugin.FabricSwitch
	bad      bool
}

// tally counts one member's measured addresses behind one group.
type tally struct{ total, bad int }

type groupAcc struct {
	name    string
	members map[uint32]*tally
}

// observe groups one fabric round. An address is measured when at least
// one vantage got a result for it, and degraded when every such vantage
// saw it past tolerance. A probe error is not a measurement. A member is
// degraded in a group when every address it has there is degraded. A
// member behind several switches counts in each of them.
func observe(samples []plugin.FabricSample, bundles []Bundle, cfg thresholds) observation {
	addrs := map[addrKey]*addrState{}
	for _, s := range samples {
		if s.Error != "" || s.Sent == 0 {
			continue
		}
		k := addrKey{s.IXPID, s.VLANID, s.Address}
		a := addrs[k]
		if a == nil {
			a = &addrState{asn: s.ASN, name: s.Name, ixp: s.IXPID, switches: s.Switches, bad: true}
			addrs[k] = a
		}
		if !s.PastTolerance {
			a.bad = false
		}
	}

	byMember := map[uint32]*tally{}
	names := map[uint32]string{}
	acc := map[groupKey]*groupAcc{}
	for _, a := range addrs {
		t := byMember[a.asn]
		if t == nil {
			t = &tally{}
			byMember[a.asn] = t
		}
		names[a.asn] = a.name
		t.total++
		if a.bad {
			t.bad++
		}
		for k, name := range groupsOf(a, bundles) {
			g := acc[k]
			if g == nil {
				g = &groupAcc{name: name, members: map[uint32]*tally{}}
				acc[k] = g
			}
			mt := g.members[a.asn]
			if mt == nil {
				mt = &tally{}
				g.members[a.asn] = mt
			}
			mt.total++
			if a.bad {
				mt.bad++
			}
		}
	}

	obs := observation{firing: map[groupKey]bool{}}
	explained := map[uint32]bool{}
	for k, g := range acc {
		out := group{key: k, name: g.name, members: len(g.members)}
		for asn, t := range g.members {
			if t.bad == t.total {
				out.degraded = append(out.degraded, asn)
			}
		}
		sort.Slice(out.degraded, func(i, j int) bool { return out.degraded[i] < out.degraded[j] })
		if cfg.fires(len(out.degraded), out.members) {
			obs.firing[k] = true
			for _, asn := range out.degraded {
				explained[asn] = true
			}
		}
		obs.groups = append(obs.groups, out)
	}
	sort.Slice(obs.groups, func(i, j int) bool { return lessKey(obs.groups[i].key, obs.groups[j].key) })

	for asn, t := range byMember {
		if t.bad == t.total && !explained[asn] {
			obs.alone = append(obs.alone, member{asn: asn, name: names[asn], addresses: t.total})
		}
	}
	sort.Slice(obs.alone, func(i, j int) bool { return obs.alone[i].asn < obs.alone[j].asn })
	return obs
}

func lessKey(a, b groupKey) bool {
	if a.scope != b.scope {
		return a.scope < b.scope
	}
	if a.ixp != b.ixp {
		return a.ixp < b.ixp
	}
	return a.id < b.id
}

// groupsOf returns the groups an address belongs to, with display names.
// Two switches in one colo put the address in that colo once.
func groupsOf(a *addrState, bundles []Bundle) map[groupKey]string {
	out := map[groupKey]string{}
	for _, sw := range a.switches {
		id := strconv.Itoa(sw.ID)
		name := sw.Name
		if name == "" {
			name = "switch-" + id
		}
		out[groupKey{plugin.ScopeSwitch, a.ixp, id}] = name
		if sw.Colo != "" {
			out[groupKey{plugin.ScopeColo, a.ixp, sw.Colo}] = sw.Colo
		}
		for _, b := range bundles {
			if b.has(a.ixp, sw.ID) {
				out[groupKey{plugin.ScopeBundle, a.ixp, b.Name}] = b.Name
			}
		}
	}
	return out
}

// thresholds decide when a group is a fabric problem.
type thresholds struct {
	minMembers int
	pct        int
}

// fires is true when enough members are degraded, and enough of the
// measured members. Both guard against a two-member switch alarming.
func (t thresholds) fires(degraded, measured int) bool {
	return degraded >= t.minMembers && degraded*100 >= t.pct*measured
}
