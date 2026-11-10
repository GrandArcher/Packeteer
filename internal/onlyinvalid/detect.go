// Package onlyinvalid spots RPKI-invalid routes that are the only route to
// a destination (#401). Strict route origin validation drops them, which
// black-holes the destination when the invalid route is a stale ROA rather
// than a hijack. Each case is classed from evidence (IRR, route age, the
// ROAs, the providers, hijack feeds) and reported. An accept-invalid
// exception is a SLURM (RFC 8416) entry that an admin approves; nothing is
// written without that approval. The package never announces, never
// withdraws, and never changes a decision or the learned RIB.
package onlyinvalid

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults and bounds.
const (
	DefaultStableAfter = 30 * 24 * time.Hour
	MinStableAfter     = time.Hour
	MaxStableAfter     = 365 * 24 * time.Hour
	// scanInterval is how often the learned RIB is scanned.
	scanInterval = 5 * time.Minute
	// firstScanDelay lets the RIB and the RPKI cache fill first.
	firstScanDelay = time.Minute
	// maxCases bounds the invalid selected routes one scan inspects.
	maxCases = 1000
	// feedTimeout bounds one hijack feed lookup.
	feedTimeout = 10 * time.Second
)

// Classes.
const (
	ClassStaleROA = "stale_roa"
	ClassHijack   = "hijack"
	ClassUnclear  = "unclear"
)

// Score thresholds: at least staleScore is a likely stale ROA when the IRR
// or the route age supports the origin, at most hijackScore a likely
// hijack.
const (
	staleScore  = 3
	hijackScore = -2
)

// Signal is one piece of evidence. Points count toward a stale ROA when
// positive and toward a hijack when negative; zero is shown but neutral.
type Signal struct {
	Name   string `json:"name"`
	Points int    `json:"points"`
	Detail string `json:"detail"`
}

// CasePath is one learned path of the prefix.
type CasePath struct {
	Provider string    `json:"provider,omitempty"`
	ASPath   []uint32  `json:"as_path"`
	Since    time.Time `json:"since,omitzero"`
}

// VRP is one payload covering the prefix.
type VRP struct {
	Prefix    netip.Prefix `json:"prefix"`
	MaxLength uint8        `json:"max_length"`
	ASN       uint32       `json:"asn"`
}

// Case is one prefix whose every learned path is RPKI-invalid and that no
// valid or not-found learned route covers.
type Case struct {
	Prefix netip.Prefix `json:"prefix"`
	// Origin is the origin AS of the selected route.
	Origin  uint32     `json:"origin"`
	Class   string     `json:"class"`
	Score   int        `json:"score"`
	Signals []Signal   `json:"signals"`
	Paths   []CasePath `json:"paths"`
	VRPs    []VRP      `json:"vrps"`
	// RPKISource is the rpki.sources entry that answered.
	RPKISource string `json:"rpki_source"`
	// Action is the suggested next step.
	Action string    `json:"action"`
	First  time.Time `json:"first"`
	Seen   time.Time `json:"seen"`
}

// Evidence is the case in one line for the audit log.
func (c Case) Evidence() string {
	parts := []string{fmt.Sprintf("%s AS%d class=%s score=%d rpki_source=%s", c.Prefix, c.Origin, c.Class, c.Score, c.RPKISource)}
	for _, v := range c.VRPs {
		parts = append(parts, fmt.Sprintf("vrp %s-%d AS%d", v.Prefix, v.MaxLength, v.ASN))
	}
	for _, s := range c.Signals {
		parts = append(parts, fmt.Sprintf("%s %+d: %s", s.Name, s.Points, s.Detail))
	}
	return strings.Join(parts, "; ")
}

// RIB is the learned view the scan reads: *rib.View.
type RIB interface {
	Ready() bool
	Find(keep func(rib.Route) bool, before func(a, b rib.Route) bool, limit int) ([]rib.Route, int)
	Paths(p netip.Prefix) []rib.Route
	Covering(p netip.Prefix) (rib.Route, bool)
}

// RPKI is the validation view: *rpki.Set.
type RPKI interface {
	Lookup(prefix netip.Prefix, origin uint32) plugin.RPKIAnswer
	Covering(prefix netip.Prefix) []plugin.RPKIVRP
	// Updated is zero while no source has fresh data.
	Updated() time.Time
}

// Feed is one hijack_feeds entry.
type Feed struct {
	Name   string
	Plugin plugin.HijackFeed
}

// Deps are what the detector reads.
type Deps struct {
	RIB  RIB
	RPKI RPKI
	// IRR is irr.Checker.Lookup, nil when irr is off.
	IRR   func(prefix netip.Prefix, origin uint32, provider string) plugin.IRRAnswer
	Feeds []Feed
	Emit  func(plugin.Event)
	Log   *slog.Logger
	Now   func() time.Time
}

// Status is the last scan.
type Status struct {
	Scanned time.Time `json:"scanned,omitzero"`
	// Note says why the last scan was skipped or cut short.
	Note  string `json:"note,omitempty"`
	Cases []Case `json:"cases"`
}

// Detector scans the learned RIB for invalid only paths.
type Detector struct {
	deps        Deps
	stableAfter time.Duration

	mu     sync.Mutex
	status Status
	open   map[netip.Prefix]Case
}

// NewDetector returns a detector. stableAfter zero is the default.
func NewDetector(deps Deps, stableAfter time.Duration) *Detector {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.New(slog.DiscardHandler)
	}
	if deps.Emit == nil {
		deps.Emit = func(plugin.Event) {}
	}
	if stableAfter == 0 {
		stableAfter = DefaultStableAfter
	}
	return &Detector{deps: deps, stableAfter: stableAfter, status: Status{Cases: []Case{}}, open: map[netip.Prefix]Case{}}
}

// Status returns a copy of the last scan.
func (d *Detector) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.status
	s.Cases = slices.Clone(s.Cases)
	return s
}

// Case returns the open case for prefix.
func (d *Detector) Case(prefix netip.Prefix) (Case, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.open[prefix.Masked()]
	return c, ok
}

// Scan reads the learned RIB once. Without a ready RIB or fresh RPKI data
// it changes nothing, so an outage is never read as every case clearing.
func (d *Detector) Scan(ctx context.Context) {
	now := d.deps.Now().UTC()
	switch {
	case !d.deps.RIB.Ready():
		d.skip(now, "the learned RIB is not ready")
		return
	case d.deps.RPKI.Updated().IsZero():
		d.skip(now, "no rpki.sources entry has fresh data")
		return
	}
	cands, matched := d.deps.RIB.Find(func(r rib.Route) bool {
		if r.Prefix.Bits() == 0 || len(r.ASPath) == 0 {
			return false
		}
		return d.deps.RPKI.Lookup(r.Prefix, netpfx.LastAS(r.ASPath)).State == plugin.RPKIInvalid
	}, func(a, b rib.Route) bool { return netpfx.Less(a.Prefix, b.Prefix) }, maxCases)
	note := ""
	if matched > len(cands) {
		note = fmt.Sprintf("%d invalid selected routes; the first %d were inspected", matched, len(cands))
	}
	found := map[netip.Prefix]Case{}
	for _, r := range cands {
		if ctx.Err() != nil {
			d.skip(now, "the scan was cancelled")
			return
		}
		if c, ok := d.inspect(ctx, r, now); ok {
			found[c.Prefix] = c
		}
	}
	// A scan cut short never reached the routes that sort after the last
	// one it inspected, so their cases neither clear nor count as gone.
	inspected := func(netip.Prefix) bool { return true }
	if matched > len(cands) && len(cands) > 0 {
		last := cands[len(cands)-1].Prefix
		inspected = func(p netip.Prefix) bool { return !netpfx.Less(last, p) }
	}
	d.mu.Lock()
	prev := d.open
	for p, c := range found {
		if old, ok := prev[p]; ok {
			c.First = old.First
			found[p] = c
		}
	}
	// Up to maxCases of those stay open as last seen, which keeps the
	// open set within twice maxCases.
	kept := 0
	for _, p := range netpfx.SortedKeys(prev) {
		if _, ok := found[p]; !ok && !inspected(p) && kept < maxCases {
			found[p] = prev[p]
			kept++
		}
	}
	d.open = found
	cases := make([]Case, 0, len(found))
	for _, p := range netpfx.SortedKeys(found) {
		cases = append(cases, found[p])
	}
	d.status = Status{Scanned: now, Note: note, Cases: cases}
	d.mu.Unlock()
	for _, c := range cases {
		if old, ok := prev[c.Prefix]; !ok || old.Class != c.Class || old.Origin != c.Origin {
			d.emitOpen(now, c)
		}
	}
	for _, p := range netpfx.SortedKeys(prev) {
		if _, ok := found[p]; !ok && inspected(p) {
			old := prev[p]
			d.deps.Emit(plugin.NewEvent(plugin.EventRPKIOnlyInvalidCleared, now,
				fmt.Sprintf("%s AS%d is no longer an RPKI-invalid only path", p, old.Origin),
				map[string]string{"prefix": p.String(), "origin": fmt.Sprint(old.Origin)}))
		}
	}
}

func (d *Detector) skip(now time.Time, why string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status.Scanned, d.status.Note = now, why
}

func (d *Detector) emitOpen(now time.Time, c Case) {
	d.deps.Log.Warn("rpki-invalid only path", "prefix", c.Prefix, "origin", c.Origin, "class", c.Class, "score", c.Score)
	d.deps.Emit(plugin.NewEvent(plugin.EventRPKIOnlyInvalid, now,
		fmt.Sprintf("%s AS%d: every learned route is RPKI-invalid and nothing valid covers it; %s (score %d). %s", c.Prefix, c.Origin, classText(c.Class), c.Score, c.Action),
		map[string]string{"prefix": c.Prefix.String(), "origin": fmt.Sprint(c.Origin), "class": c.Class,
			"score": fmt.Sprint(c.Score), "evidence": c.Evidence()}))
}

func classText(class string) string {
	switch class {
	case ClassStaleROA:
		return "likely a stale ROA or misconfiguration"
	case ClassHijack:
		return "likely a hijack"
	}
	return "unclear"
}

// inspect builds the case for one invalid selected route, or reports
// that it is not one: another path is not invalid, or a covering learned
// route that is valid or not found still reaches the destination.
func (d *Detector) inspect(ctx context.Context, sel rib.Route, now time.Time) (Case, bool) {
	prefix, origin := sel.Prefix, netpfx.LastAS(sel.ASPath)
	ans := d.deps.RPKI.Lookup(prefix, origin)
	c := Case{Prefix: prefix, Origin: origin, RPKISource: ans.Source, First: now, Seen: now, Paths: []CasePath{}, VRPs: []VRP{}, Signals: []Signal{}}
	if !d.allInvalid(prefix, &c) || d.coveredReachable(prefix) {
		return Case{}, false
	}
	for _, v := range d.deps.RPKI.Covering(prefix) {
		c.VRPs = append(c.VRPs, VRP{Prefix: v.Prefix, MaxLength: v.MaxLen, ASN: v.ASN})
	}
	c.Signals = append(c.Signals, d.irrSignals(prefix, origin, sel.Provider)...)
	c.Signals = append(c.Signals, d.ageSignal(c, now), roaSignal(c), providerSignal(c))
	c.Signals = append(c.Signals, d.feedSignal(ctx, prefix, origin))
	corroborated := false
	for _, s := range c.Signals {
		c.Score += s.Points
		corroborated = corroborated || (s.Points > 0 && (s.Name == "irr_route" || s.Name == "origin_stable"))
	}
	switch {
	case c.Score >= staleScore && corroborated:
		c.Class = ClassStaleROA
		c.Action = fmt.Sprintf("Contact the holder of %s to fix the ROA for AS%d. Until it is fixed, a SLURM exception can accept this route; an admin must approve it.", prefix, origin)
	case c.Score <= hijackScore:
		c.Class = ClassHijack
		c.Action = "Keep dropping it. Report it to the prefix holder and the providers that carry it. Do not add an exception."
	default:
		c.Class = ClassUnclear
		c.Action = fmt.Sprintf("Not enough evidence either way. Ask the holder of %s before accepting the route.", prefix)
	}
	return c, true
}

// allInvalid records every learned path of prefix in c and reports whether
// each one is RPKI-invalid. A path the edge originates (empty AS path) or
// one with no answer is not invalid.
func (d *Detector) allInvalid(prefix netip.Prefix, c *Case) bool {
	paths := d.deps.RIB.Paths(prefix)
	if len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		if len(p.ASPath) == 0 || d.deps.RPKI.Lookup(prefix, netpfx.LastAS(p.ASPath)).State != plugin.RPKIInvalid {
			return false
		}
		c.Paths = append(c.Paths, CasePath{Provider: p.Provider, ASPath: slices.Clone(p.ASPath), Since: p.Age})
	}
	return true
}

// coveredReachable reports whether a less specific learned route has a
// path that is valid or not found, so dropping prefix still leaves a way
// to the destination. Unknown counts as reachable: without data the
// prefix is not reported.
func (d *Detector) coveredReachable(prefix netip.Prefix) bool {
	for q := prefix; q.Bits() > 0; {
		cover, ok := d.deps.RIB.Covering(netip.PrefixFrom(q.Addr(), q.Bits()-1).Masked())
		if !ok {
			return false
		}
		for _, p := range d.deps.RIB.Paths(cover.Prefix) {
			if len(p.ASPath) == 0 || d.deps.RPKI.Lookup(cover.Prefix, netpfx.LastAS(p.ASPath)).State != plugin.RPKIInvalid {
				return true
			}
		}
		q = cover.Prefix
	}
	return false
}

// irrSignals: the origin in a route object for exactly the prefix, and in
// the provider's as-set from irr.as_sets.
func (d *Detector) irrSignals(prefix netip.Prefix, origin uint32, provider string) []Signal {
	if d.deps.IRR == nil {
		return []Signal{{Name: "irr_route", Detail: "irr is off"}}
	}
	a := d.deps.IRR(prefix, origin, provider)
	var out []Signal
	switch {
	case a.State == plugin.IRRRegistered:
		out = append(out, Signal{Name: "irr_route", Points: 2, Detail: fmt.Sprintf("AS%d has a route object for %s (%s %s)", origin, prefix, a.Source, a.Database)})
	case a.State == plugin.IRRNotRegistered && len(a.Origins) > 0:
		out = append(out, Signal{Name: "irr_route", Points: -2, Detail: fmt.Sprintf("route objects for %s name %s, not AS%d", prefix, asList(a.Origins), origin)})
	case a.State == plugin.IRRNotRegistered:
		out = append(out, Signal{Name: "irr_route", Points: -1, Detail: fmt.Sprintf("no route object for %s", prefix)})
	default:
		out = append(out, Signal{Name: "irr_route", Detail: "no fresh IRR answer yet"})
	}
	if a.ASSet != "" {
		switch a.ASSetState {
		case plugin.IRRRegistered:
			out = append(out, Signal{Name: "irr_as_set", Points: 1, Detail: fmt.Sprintf("AS%d is in %s", origin, a.ASSet)})
		case plugin.IRRNotRegistered:
			out = append(out, Signal{Name: "irr_as_set", Points: -1, Detail: fmt.Sprintf("AS%d is not in %s", origin, a.ASSet)})
		default:
			out = append(out, Signal{Name: "irr_as_set", Detail: fmt.Sprintf("no fresh answer for %s", a.ASSet)})
		}
	}
	return out
}

// ageSignal: how long the oldest learned path with the origin has been in
// the RIB. A young path is neutral, because a session reset or a restart
// makes every path young.
func (d *Detector) ageSignal(c Case, now time.Time) Signal {
	var oldest time.Time
	for _, p := range c.Paths {
		if netpfx.LastAS(p.ASPath) == c.Origin && !p.Since.IsZero() && (oldest.IsZero() || p.Since.Before(oldest)) {
			oldest = p.Since
		}
	}
	if oldest.IsZero() {
		return Signal{Name: "origin_stable", Detail: "no learn time"}
	}
	age := now.Sub(oldest).Truncate(time.Minute)
	if age >= d.stableAfter {
		return Signal{Name: "origin_stable", Points: 2, Detail: fmt.Sprintf("AS%d has originated it here for %s (stable_after %s)", c.Origin, age, d.stableAfter)}
	}
	return Signal{Name: "origin_stable", Detail: fmt.Sprintf("learned %s ago, under stable_after %s", age, d.stableAfter)}
}

// roaSignal: a ROA that authorizes the same origin for a covering prefix
// with a max length shorter than the route. The covering prefix is then
// valid for the origin and only the max length is wrong. It is weak alone:
// a forged-origin sub-prefix hijack (RFC 9319) looks the same, which is
// why a stale ROA class also needs the IRR or the route age.
func roaSignal(c Case) Signal {
	var others []uint32
	for _, v := range c.VRPs {
		if v.ASN == c.Origin {
			return Signal{Name: "roa_same_origin", Points: 1, Detail: fmt.Sprintf("ROA %s maxLength %d authorizes AS%d; %s is longer, so only the max length is short", v.Prefix, v.MaxLength, c.Origin, c.Prefix)}
		}
		if !slices.Contains(others, v.ASN) {
			others = append(others, v.ASN)
		}
	}
	slices.Sort(others)
	return Signal{Name: "roa_same_origin", Detail: fmt.Sprintf("no ROA names AS%d; covering ROAs name %s", c.Origin, asList(others))}
}

// providerSignal: several providers carrying the same origin agree on it;
// paths with another origin conflict.
func providerSignal(c Case) Signal {
	var agree []string
	var conflict []uint32
	for _, p := range c.Paths {
		o := netpfx.LastAS(p.ASPath)
		if o != c.Origin {
			if !slices.Contains(conflict, o) {
				conflict = append(conflict, o)
			}
			continue
		}
		if p.Provider != "" && !slices.Contains(agree, p.Provider) {
			agree = append(agree, p.Provider)
		}
	}
	slices.Sort(agree)
	slices.Sort(conflict)
	switch {
	case len(conflict) > 0:
		return Signal{Name: "providers", Points: -2, Detail: fmt.Sprintf("conflicting origin: paths also end in %s", asList(conflict))}
	case len(agree) >= 2:
		return Signal{Name: "providers", Points: 1, Detail: fmt.Sprintf("%d providers agree on AS%d (%s)", len(agree), c.Origin, strings.Join(agree, ", "))}
	}
	return Signal{Name: "providers", Detail: fmt.Sprintf("one provider carries it (%s)", strings.Join(agree, ", "))}
}

// feedSignal: an incident for the prefix with this origin, or with no
// origin named, points to a hijack; feeds that answered with none count a
// little toward a stale ROA; feeds that failed are no evidence.
func (d *Detector) feedSignal(ctx context.Context, prefix netip.Prefix, origin uint32) Signal {
	if len(d.deps.Feeds) == 0 {
		return Signal{Name: "hijack_feeds", Detail: "no hijack_feeds configured"}
	}
	answered := 0
	var failed []string
	for _, f := range d.deps.Feeds {
		fctx, cancel := context.WithTimeout(ctx, feedTimeout)
		list, err := f.Plugin.Incidents(fctx, prefix)
		cancel()
		if err != nil {
			d.deps.Log.Warn("hijack feed lookup failed", "feed", f.Name, "prefix", prefix, "err", err)
			failed = append(failed, f.Name)
			continue
		}
		answered++
		for _, in := range list {
			if in.Origin == 0 || in.Origin == origin {
				detail := fmt.Sprintf("%s reports an incident for %s", f.Name, in.Prefix)
				if in.Origin != 0 {
					detail += fmt.Sprintf(" from AS%d", in.Origin)
				}
				if in.Detail != "" {
					detail += ": " + in.Detail
				}
				return Signal{Name: "hijack_feeds", Points: -4, Detail: detail}
			}
		}
	}
	if answered == 0 {
		return Signal{Name: "hijack_feeds", Detail: "no feed answered: " + strings.Join(failed, ", ")}
	}
	return Signal{Name: "hijack_feeds", Points: 1, Detail: fmt.Sprintf("%d of %d feeds report no incident for AS%d", answered, len(d.deps.Feeds), origin)}
}

func asList(asns []uint32) string {
	if len(asns) == 0 {
		return "none"
	}
	parts := make([]string, len(asns))
	for i, a := range asns {
		parts[i] = fmt.Sprintf("AS%d", a)
	}
	return strings.Join(parts, ", ")
}
