package policy

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/portload"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// overloadRefused starts the reason of every decision the overload limit
// refused; the explanation reads it to tell that the limit was reached.
const overloadRefused = "overload: "

// Overload actions on an Output.
const (
	OverloadRefused = "refused"
	OverloadShed    = "shed"
)

const overloadEps = 0.01

// Load is a provider's interface reading (#307): the outbound rate of the
// latest telemetry sample and the interface capacity it is judged against.
type Load struct {
	CapacityMbps float64
	OutMbps      float64
	Updated      time.Time
}

// Overload is one performance steer the interface capacity limit refused or
// shed (#307). Provider is the provider whose limit applied. UsedPct and
// ProjectedPct are shares of its interface capacity, before and after the
// steer's volume; they are 0 when the reading is missing.
type Overload struct {
	Action       string
	Prefix       netip.Prefix
	Provider     string
	UsedPct      float64
	ProjectedPct float64
	LimitPct     float64
	VolumeMbps   float64
	Reason       string
}

// Unreadable says why the reading cannot be judged at now, or "" when it
// can: the capacity is unknown, no sample has been taken, or the sample is
// older than portload.DefaultMaxAge.
func (l Load) Unreadable(now time.Time) string {
	switch {
	case l.CapacityMbps <= 0:
		return "interface capacity unknown"
	case l.Updated.IsZero():
		return "no interface sample yet"
	case !portload.Fresh(l.Updated, now, portload.DefaultMaxAge):
		return "interface reading is stale"
	}
	return ""
}

// LimitMbps is the outbound rate at limitPct percent of the capacity.
func (l Load) LimitMbps(limitPct float64) float64 { return l.CapacityMbps * limitPct / 100 }

// shedMark is the last shed off a provider: the sample it was judged on and
// when it happened.
type shedMark struct {
	sample time.Time
	at     time.Time
}

// providerLoad is one limited provider's load for this evaluation.
type providerLoad struct {
	limitPct float64
	// ok is false when the reading is missing, stale, or has no capacity;
	// why says which. Such a provider takes no new steer.
	ok       bool
	why      string
	capacity float64
	updated  time.Time
	// used is the outbound rate plus the volume of steers the sample does
	// not hold yet (all of them outside inject mode, where nothing is on
	// the wire), plus steers admitted in this evaluation, less steers
	// retired in it.
	used float64
}

func (l *providerLoad) limit() float64 { return Load{CapacityMbps: l.capacity}.LimitMbps(l.limitPct) }

func (l *providerLoad) pct(mbps float64) float64 {
	if l.capacity <= 0 {
		return 0
	}
	return mbps / l.capacity * 100
}

// loadGate holds back performance steers from a provider whose interface
// is at its capacity limit and sheds the ones already there (#307). A nil
// gate admits everything.
type loadGate struct {
	byProv map[string]*providerLoad
	vols   map[netip.Prefix]float64
}

// newLoadGate reads the limited providers' load. A steer created after the
// sample was taken is not in its rate, so its volume is added. Outside
// inject mode no steer moves traffic, so every steer on the provider is
// added: observe judges the recommendations as inject would judge them.
func newLoadGate(st State, in Input, cfg Config, now time.Time) *loadGate {
	var g *loadGate
	for _, pp := range cfg.Providers {
		if pp.CapacityThresholdPct <= 0 {
			continue
		}
		if g == nil {
			g = &loadGate{byProv: map[string]*providerLoad{}, vols: in.volumes()}
		}
		l := &providerLoad{limitPct: pp.CapacityThresholdPct}
		g.byProv[pp.Name] = l
		row, have := in.Load[pp.Name]
		switch why := row.Unreadable(now); {
		case !have:
			l.why = "no interface reading"
		case why != "":
			l.why = why
		default:
			l.ok, l.capacity, l.updated, l.used = true, row.CapacityMbps, row.Updated, row.OutMbps
			for _, imp := range st.Improvements {
				if imp.Provider == pp.Name && (cfg.Mode != "inject" || imp.Since.After(row.Updated)) {
					l.used += g.vols[imp.Prefix]
				}
			}
		}
	}
	return g
}

// refuse reports whether a performance steer of prefix p onto provider
// would break the provider's limit. A provider without a limit never
// refuses. An unknown volume is judged on the current rate alone.
func (g *loadGate) refuse(provider string, p netip.Prefix) (Overload, bool) {
	if g == nil {
		return Overload{}, false
	}
	l := g.byProv[provider]
	if l == nil {
		return Overload{}, false
	}
	note := Overload{Action: OverloadRefused, Prefix: p, Provider: provider, LimitPct: l.limitPct, VolumeMbps: g.vols[p]}
	if !l.ok {
		note.Reason = fmt.Sprintf("%s%s: %s, so no new steer goes there", overloadRefused, provider, l.why)
		return note, true
	}
	note.UsedPct, note.ProjectedPct = l.pct(l.used), l.pct(l.used+note.VolumeMbps)
	if l.used+note.VolumeMbps <= l.limit()+overloadEps {
		return Overload{}, false
	}
	if note.VolumeMbps > 0 {
		note.Reason = fmt.Sprintf("%s%s would reach %s%% of its %s Mbps interface with this steer (limit %s%%)",
			overloadRefused, provider, fnum(note.ProjectedPct), fnum(l.capacity), fnum(l.limitPct))
	} else {
		note.Reason = fmt.Sprintf("%s%s is at %s%% of its %s Mbps interface (limit %s%%)",
			overloadRefused, provider, fnum(note.UsedPct), fnum(l.capacity), fnum(l.limitPct))
	}
	return note, true
}

// book counts an admitted steer onto provider, so the next one in the same
// evaluation sees it.
func (g *loadGate) book(provider string, p netip.Prefix) {
	if g == nil {
		return
	}
	if l := g.byProv[provider]; l != nil && l.ok {
		l.used += g.vols[p]
	}
}

// release takes a retired or switched-away steer's volume off its provider:
// the rate the evaluation judged still holds it.
func (g *loadGate) release(imp Improvement) {
	if g == nil {
		return
	}
	if l := g.byProv[imp.Provider]; l != nil && l.ok {
		l.used = max(l.used-g.vols[imp.Prefix], 0)
	}
}

type shedCandidate struct {
	imp  Improvement
	gain float64
	vol  float64
}

// shed retires performance steers from every provider over its limit,
// lowest gain first, until the projected rate is back inside it. A steer
// younger than hold_time stays. A provider is shed once per sample: the
// rate it was judged on does not yet hold the effect of an earlier shed,
// so shedding again before a newer sample, or inside hold_time, would
// unwind steers that are no longer needed. retire takes a shed steer's
// volume off the provider through release. The shed prefix waits out
// hold_time before it can be steered again, and the limit refuses any
// steer back onto the provider meanwhile.
func (g *loadGate) shed(st *State, out *Output, decIdx map[netip.Prefix]*Decision, byPrefix map[netip.Prefix][]Candidate,
	cfg Config, now time.Time, retire func(netip.Prefix, string, bool)) {
	if g == nil {
		return
	}
	names := make([]string, 0, len(g.byProv))
	for name := range g.byProv {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		l := g.byProv[name]
		if !l.ok || l.used <= l.limit()+overloadEps {
			continue
		}
		if last, shedBefore := st.shedAt[name]; shedBefore && (!l.updated.After(last.sample) || now.Sub(last.at) < cfg.HoldTime) {
			continue
		}
		var cands []shedCandidate
		for _, imp := range st.Improvements {
			if imp.Provider != name || planned(imp.Cause) || imp.Cause == plugin.CauseStatic || now.Sub(imp.Since) < cfg.HoldTime {
				continue
			}
			cands = append(cands, shedCandidate{imp: imp, gain: steerGain(byPrefix[imp.Prefix], imp), vol: g.vols[imp.Prefix]})
		}
		sort.Slice(cands, func(a, b int) bool {
			if cands[a].gain != cands[b].gain {
				return cands[a].gain < cands[b].gain
			}
			if cands[a].vol != cands[b].vol {
				return cands[a].vol > cands[b].vol
			}
			return netpfx.Less(cands[a].imp.Prefix, cands[b].imp.Prefix)
		})
		for _, c := range cands {
			note := Overload{Action: OverloadShed, Prefix: c.imp.Prefix, Provider: name, UsedPct: l.pct(l.used), LimitPct: l.limitPct, VolumeMbps: c.vol}
			note.ProjectedPct = l.pct(max(l.used-c.vol, 0))
			note.Reason = fmt.Sprintf("%s%s is at %s%% of its %s Mbps interface (limit %s%%); steer shed, lowest gain first",
				overloadRefused, name, fnum(note.UsedPct), fnum(l.capacity), fnum(l.limitPct))
			retire(c.imp.Prefix, note.Reason, true)
			if d := decIdx[c.imp.Prefix]; d != nil {
				d.Action, d.Reason, d.Current, d.Cause = ActionRetire, note.Reason, c.imp.Native, c.imp.Cause
			}
			out.Overloads = append(out.Overloads, note)
			st.shedAt[name] = shedMark{sample: l.updated, at: now}
			// A steer with no known volume frees an unknown amount: wait for
			// the next sample before shedding more.
			if l.used <= l.limit()+overloadEps || c.vol <= 0 {
				break
			}
		}
	}
}

// steerGain is how much better the steer's provider scored than its native
// path when the evaluation ran. A native path with no usable score ranks
// last, so its steer is shed last.
func steerGain(cands []Candidate, imp Improvement) float64 {
	nat, okNat := findCandidate(cands, imp.Native)
	cur, okCur := findCandidate(cands, imp.Provider)
	if !okNat || !okCur || !nat.Usable || !cur.Usable {
		return math.Inf(1)
	}
	return nat.Score - cur.Score
}

// volumes is the per-prefix traffic rate the evaluation reads: the
// planner's, else the one read for improvement weights or the overload
// limit.
func (in Input) volumes() map[netip.Prefix]float64 {
	if in.WeightVolumeMbps != nil {
		return in.WeightVolumeMbps
	}
	return in.VolumeMbps
}
