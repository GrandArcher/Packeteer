// Package blast builds the blast-radius preview (#227): what inject mode
// would put on the wire, compared with what is on the wire now. It reads a
// Decide outcome that internal/policy computed on a copy of the live state
// (policy.Engine.WhatIf), so the preview is the real decision path. It
// announces nothing and changes no state.
package blast

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Warning codes.
const (
	WarnCapacity    = "capacity"
	WarnCommit      = "commit"
	WarnCap         = "cap"
	WarnAllowlist   = "allowlist"
	WarnNoAllowlist = "no_allowlist"
	WarnStale       = "stale"
	WarnUnmeasured  = "unmeasured"
	WarnRefused     = "refused"
	WarnVolume      = "volume_unknown"
	WarnInputs      = "inputs_fixed"
	WarnSynthesized = "synthesized"
)

// ErrNoRound is returned by a preview source before the first decision round
// has run: there is nothing to decide again.
var ErrNoRound = errors.New("no decision round has run yet; try again after the first probe round")

// maxListed bounds the prefixes a warning names.
const maxListed = 5

// Route is one outbound route that would be added, moved, or withdrawn.
// Traffic leaves From and arrives at To. VolumeMbps is nil when no flow
// source reported a rate for the prefix.
type Route struct {
	Prefix     netip.Prefix `json:"prefix"`
	From       string       `json:"from"`
	To         string       `json:"to"`
	Cause      string       `json:"cause,omitempty"`
	Reason     string       `json:"reason,omitempty"`
	VolumeMbps *float64     `json:"volume_mbps,omitempty"`
	// Covering is set on a synthesized sub-range (#122): the learned
	// prefix it lies inside. Prefix is not in the learned RIB.
	Covering netip.Prefix `json:"covering,omitzero"`
}

// Shift is the estimated traffic change on one provider. Unknown counts the
// routes touching it whose volume is not known, so the figures are a lower
// bound when it is above zero. The capacity and commit fields are zero when
// no telemetry row reports them.
type Shift struct {
	Provider      string  `json:"provider"`
	InMbps        float64 `json:"in_mbps"`
	OutMbps       float64 `json:"out_mbps"`
	Unknown       int     `json:"unknown"`
	CurrentMbps   float64 `json:"current_mbps"`
	ProjectedMbps float64 `json:"projected_mbps"`
	CapacityMbps  float64 `json:"capacity_mbps,omitempty"`
	LimitMbps     float64 `json:"limit_mbps,omitempty"`
	CommitMbps    float64 `json:"commit_mbps,omitempty"`
}

// Warning is a condition the operator should read before enabling inject.
// Prefixes names up to five of Count.
type Warning struct {
	Code     string   `json:"code"`
	Provider string   `json:"provider,omitempty"`
	Count    int      `json:"count,omitempty"`
	Prefixes []string `json:"prefixes,omitempty"`
	Message  string   `json:"message"`
}

// Report is the preview. Announces is false when the decided mode is not
// inject: nothing would be on the wire, so every route now on the wire is
// listed as withdrawn.
type Report struct {
	At        time.Time `json:"at"`
	Mode      string    `json:"mode"`
	Announces bool      `json:"announces"`
	Add       []Route   `json:"add"`
	Move      []Route   `json:"move"`
	Withdraw  []Route   `json:"withdraw"`
	Keep      int       `json:"keep"`
	Cap       int       `json:"cap"`
	Providers []Shift   `json:"providers"`
	Warnings  []Warning `json:"warnings"`
	// Changes is true when the wire would differ.
	Changes bool `json:"changes"`
}

// Params are the inputs of Build.
type Params struct {
	Now time.Time
	// Cfg is the config the outcome was decided under.
	Cfg policy.Config
	// OnWire is what is announced now, empty unless the running mode is
	// inject.
	OnWire []policy.Improvement
	// What is the Decide outcome under Cfg.
	What policy.WhatIf
	// Refuse returns why the announcer would refuse an improvement the
	// decision kept (leak-watch hold, inbound or mitigation reservation,
	// not in the learned RIB, a synthesize rail), or "".
	Refuse func(policy.Improvement) string
	// Volumes is observed Mbps per prefix; nil when no flow source is
	// configured.
	Volumes map[netip.Prefix]float64
	Usage   []plugin.Usage
	// Changed lists the online config keys a candidate changes; empty for
	// the running config.
	Changed []string
}

// gatedTop are the online keys that can change what gets announced and
// that the preview can show: Decide reads them from the config.
var gatedTop = []string{"mode", "thresholds", "hold_time", "improvement_ttl", "flap_quarantine", "max_improvements", "allowlist"}

// inputTop are online keys that change what Decide is fed (policy verdicts,
// target sources). A preview decides the latest round again with the old
// inputs, so it cannot show their effect.
var inputTop = []string{"policies", "sources"}

// Gated reports whether a change to these online keys can change what is
// announced, so it needs a preview before it applies. Probe timing, the
// inbound and mitigation modes (they have their own inject confirmation),
// and router reachability do not.
func Gated(online []string) bool {
	return slices.ContainsFunc(online, func(k string) bool {
		return slices.Contains(gatedTop, k) || slices.Contains(inputTop, k)
	})
}

// Build compares the wire with the decided improvements.
func Build(p Params) Report {
	rep := Report{At: p.Now, Mode: p.Cfg.Mode, Announces: p.Cfg.Mode == "inject", Cap: p.Cfg.MaxImprovements,
		Add: []Route{}, Move: []Route{}, Withdraw: []Route{}, Providers: []Shift{}, Warnings: []Warning{}}
	wire := map[netip.Prefix]policy.Improvement{}
	for _, im := range p.OnWire {
		wire[im.Prefix] = im
	}
	want := map[netip.Prefix]policy.Improvement{}
	var refused []string
	if rep.Announces {
		for _, im := range p.What.State.Improvements {
			if why := refusal(p.Refuse, im); why != "" {
				refused = append(refused, im.Prefix.String()+" ("+why+")")
				continue
			}
			want[im.Prefix] = im
		}
	}
	vol := func(pfx netip.Prefix) *float64 {
		if v, ok := p.Volumes[pfx]; ok {
			return &v
		}
		return nil
	}
	for _, pfx := range netpfx.SortedKeys(want) {
		im := want[pfx]
		old, on := wire[pfx]
		switch {
		case !on:
			rep.Add = append(rep.Add, Route{Prefix: pfx, From: im.Native, To: im.Provider, Cause: im.Cause, Reason: im.Reason, VolumeMbps: vol(pfx), Covering: im.Covering})
		case old.Provider != im.Provider:
			rep.Move = append(rep.Move, Route{Prefix: pfx, From: old.Provider, To: im.Provider, Cause: im.Cause, Reason: im.Reason, VolumeMbps: vol(pfx), Covering: im.Covering})
		default:
			rep.Keep++
		}
	}
	for _, pfx := range netpfx.SortedKeys(wire) {
		if _, ok := want[pfx]; ok {
			continue
		}
		old := wire[pfx]
		rep.Withdraw = append(rep.Withdraw, Route{Prefix: pfx, From: old.Provider, To: old.Native, Cause: old.Cause, VolumeMbps: vol(pfx), Covering: old.Covering})
	}
	rep.Changes = len(rep.Add)+len(rep.Move)+len(rep.Withdraw) > 0
	rep.Providers = shifts(rep, p)
	rep.Warnings = warnings(rep, p, refused)
	if fixed := slices.DeleteFunc(slices.Clone(p.Changed), func(k string) bool { return !slices.Contains(inputTop, k) }); len(fixed) > 0 {
		rep.Warnings = append(rep.Warnings, Warning{Code: WarnInputs,
			Message: "the preview keeps the current " + strings.Join(fixed, " and ") + " results; their effect shows after the next probe round"})
	}
	return rep
}

func refusal(f func(policy.Improvement) string, im policy.Improvement) string {
	if f == nil {
		return ""
	}
	return f(im)
}

// shifts totals the traffic each provider gains and loses, and judges it
// against the telemetry row of that provider.
func shifts(rep Report, p Params) []Shift {
	by := map[string]*Shift{}
	get := func(name string) *Shift {
		if by[name] == nil {
			by[name] = &Shift{Provider: name}
		}
		return by[name]
	}
	for _, list := range [][]Route{rep.Add, rep.Move, rep.Withdraw} {
		for _, r := range list {
			from, to := get(r.From), get(r.To)
			if r.VolumeMbps == nil {
				from.Unknown++
				to.Unknown++
				continue
			}
			from.OutMbps += *r.VolumeMbps
			to.InMbps += *r.VolumeMbps
		}
	}
	pct := map[string]float64{}
	for _, pp := range p.Cfg.Providers {
		pct[pp.Name] = pp.CapacityThresholdPct
	}
	for _, u := range p.Usage {
		s := by[u.Provider]
		if s == nil {
			continue
		}
		s.CurrentMbps, s.CapacityMbps, s.CommitMbps = u.OutMbps, u.CapacityMbps, u.CommitMbps
		s.ProjectedMbps = max(u.OutMbps+s.InMbps-s.OutMbps, 0)
		if u.CapacityMbps > 0 {
			s.LimitMbps = u.CapacityMbps
			if t := pct[u.Provider]; t > 0 {
				s.LimitMbps = u.CapacityMbps * t / 100
			}
		}
	}
	out := make([]Shift, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

func warnings(rep Report, p Params, refused []string) []Warning {
	var out []Warning
	var synth []string
	for _, list := range [][]Route{rep.Add, rep.Move} {
		for _, r := range list {
			if r.Covering.IsValid() {
				synth = append(synth, r.Prefix.String()+" inside "+r.Covering.String())
			}
		}
	}
	if len(synth) > 0 {
		out = append(out, Warning{Code: WarnSynthesized, Count: len(synth), Prefixes: head(synth),
			Message: fmt.Sprintf("%d synthesized more-specifics would be announced. They are NOT in the learned RIB and can cause hijack-like effects, RPKI-invalid announcements, and route leaks if misused", len(synth))})
	}
	if len(refused) > 0 {
		out = append(out, Warning{Code: WarnRefused, Count: len(refused), Prefixes: head(refused),
			Message: fmt.Sprintf("%d decided routes would be refused by the announcer", len(refused))})
	}
	for _, s := range rep.Providers {
		if s.InMbps <= 0 {
			continue
		}
		if s.LimitMbps > 0 && s.ProjectedMbps > s.LimitMbps {
			out = append(out, Warning{Code: WarnCapacity, Provider: s.Provider,
				Message: fmt.Sprintf("%s would carry about %.1f Mbps out, over its limit of %.1f Mbps (capacity %.1f Mbps)", s.Provider, s.ProjectedMbps, s.LimitMbps, s.CapacityMbps)})
		}
		if s.CommitMbps > 0 && s.ProjectedMbps > s.CommitMbps {
			out = append(out, Warning{Code: WarnCommit, Provider: s.Provider,
				Message: fmt.Sprintf("%s would carry about %.1f Mbps out, over its %.1f Mbps commit; a sustained rate above it raises the 95th percentile", s.Provider, s.ProjectedMbps, s.CommitMbps)})
		}
	}
	if !rep.Announces {
		return out
	}
	if len(p.Cfg.Allowlist) == 0 {
		out = append(out, Warning{Code: WarnNoAllowlist, Message: "the allowlist is empty, so inject announces nothing"})
	}
	var capped, outside []string
	for _, d := range p.What.Output.Decisions {
		switch {
		case d.Action == policy.ActionCapped:
			capped = append(capped, d.Prefix.String())
		case d.Recommended != "" && d.Recommended != d.Current && !netpfx.CoveredBy(p.Cfg.Allowlist, d.Prefix):
			outside = append(outside, d.Prefix.String())
		}
	}
	switch {
	case len(capped) > 0:
		out = append(out, Warning{Code: WarnCap, Count: len(capped), Prefixes: head(capped),
			Message: fmt.Sprintf("max_improvements (%d) is reached: %d more moves are wanted and would not be announced", p.Cfg.MaxImprovements, len(capped))})
	case p.Cfg.MaxImprovements > 0 && len(p.What.State.Improvements) >= p.Cfg.MaxImprovements:
		out = append(out, Warning{Code: WarnCap, Count: len(p.What.State.Improvements),
			Message: fmt.Sprintf("max_improvements (%d) would be fully used", p.Cfg.MaxImprovements)})
	}
	if len(outside) > 0 {
		out = append(out, Warning{Code: WarnAllowlist, Count: len(outside), Prefixes: head(outside),
			Message: fmt.Sprintf("%d better paths exist for prefixes outside the allowlist and would not be announced", len(outside))})
	}
	out = append(out, measurementWarnings(p)...)
	unknown := 0
	for _, list := range [][]Route{rep.Add, rep.Move, rep.Withdraw} {
		for _, r := range list {
			if r.VolumeMbps == nil {
				unknown++
			}
		}
	}
	if unknown > 0 {
		out = append(out, Warning{Code: WarnVolume, Count: unknown,
			Message: fmt.Sprintf("no flow volume for %d routes; the traffic estimate leaves them out", unknown)})
	}
	return out
}

// measurementWarnings flags allowlisted prefixes inject could not decide
// well: a measured prefix whose newest sample is older than the staleness
// window, and an allowlist entry that covers no measured prefix.
func measurementWarnings(p Params) []Warning {
	newest := map[netip.Prefix]time.Time{}
	for _, r := range p.What.Input.Results {
		if r.OK() && r.Time.After(newest[r.Prefix]) {
			newest[r.Prefix] = r.Time
		}
		if _, ok := newest[r.Prefix]; !ok {
			newest[r.Prefix] = time.Time{}
		}
	}
	var stale []string
	for _, pfx := range netpfx.SortedKeys(newest) {
		if !netpfx.CoveredBy(p.Cfg.Allowlist, pfx) {
			continue
		}
		if t := newest[pfx]; p.Cfg.MaxResultAge > 0 && p.Now.Sub(t) > p.Cfg.MaxResultAge {
			stale = append(stale, pfx.String())
		}
	}
	var out []Warning
	if len(stale) > 0 {
		out = append(out, Warning{Code: WarnStale, Count: len(stale), Prefixes: head(stale),
			Message: fmt.Sprintf("%d allowlisted prefixes lack a recent successful measurement and would stay on their native path", len(stale))})
	}
	var bare []string
	for _, a := range p.Cfg.Allowlist {
		covered := false
		for pfx := range newest {
			if netpfx.CoveredBy([]netip.Prefix{a}, pfx) {
				covered = true
				break
			}
		}
		if !covered {
			bare = append(bare, a.String())
		}
	}
	if len(bare) > 0 {
		sort.Strings(bare)
		out = append(out, Warning{Code: WarnUnmeasured, Count: len(bare), Prefixes: head(bare),
			Message: fmt.Sprintf("%d allowlist entries cover no measured prefix", len(bare))})
	}
	return out
}

func head(s []string) []string {
	if len(s) > maxListed {
		return s[:maxListed]
	}
	return s
}
