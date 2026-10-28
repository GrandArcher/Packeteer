package replay

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// ErrNoRounds is returned when the window holds no stored round: round
// storage is off or the window is outside what was kept.
var ErrNoRounds = errors.New("no decision rounds are stored for that window; set round_retention on the storage plugin and let the controller run")

const (
	pageSize = 200
	// MaxListed bounds the moves and prefix differences a result lists.
	MaxListed = 200
)

// Side is one configuration to replay. Its Decide state starts empty.
type Side struct {
	Name   string
	Cfg    policy.Config
	Scorer plugin.Scorer
}

// Move is one change Decide made in the replay. From and To are the
// providers traffic leaves and arrives at; To is empty for a retire, which
// returns the prefix to its native path. LossDeltaPct and RTTDeltaMs are the
// from-path measurement minus the to-path measurement at that round
// (positive is better), set only when Measured.
type Move struct {
	At           time.Time    `json:"at"`
	Prefix       netip.Prefix `json:"prefix"`
	Action       string       `json:"action"`
	From         string       `json:"from"`
	To           string       `json:"to,omitempty"`
	Cause        string       `json:"cause,omitempty"`
	Reason       string       `json:"reason,omitempty"`
	Measured     bool         `json:"measured"`
	LossDeltaPct float64      `json:"loss_delta_pct,omitempty"`
	RTTDeltaMs   float64      `json:"rtt_delta_ms,omitempty"`
	VolumeMbps   float64      `json:"volume_mbps,omitempty"`
}

// Summary totals one replay.
type Summary struct {
	Improves int `json:"improves"`
	Switches int `json:"switches"`
	Retires  int `json:"retires"`
	// Prefixes is how many distinct prefixes were steered.
	Prefixes int `json:"prefixes"`
	// Active is the improvements standing after the last round, PeakActive
	// the most at once, and MaxImprovements the cap of this side.
	Active          int `json:"active"`
	PeakActive      int `json:"peak_active"`
	MaxImprovements int `json:"max_improvements"`
	// CappedRounds is the rounds in which max_improvements held back at
	// least one move, CappedPrefixes the distinct prefixes held back.
	CappedRounds   int `json:"capped_rounds"`
	CappedPrefixes int `json:"capped_prefixes"`
	// Flaps counts switches plus new improvements on a prefix that was
	// retired earlier in the window (events, not distinct prefixes);
	// Quarantines the flap quarantines that started.
	Flaps       int `json:"flaps"`
	Quarantines int `json:"quarantines"`
	// LossDeltaPct and RTTDeltaMs are the mean change per move taken
	// (improves and switches) that had both measurements. They are
	// weighted by the prefix volume when any such move has one (Weighted),
	// else plain. UnknownVolume counts the moves left out of a weighted mean.
	LossDeltaPct  float64 `json:"loss_delta_pct"`
	RTTDeltaMs    float64 `json:"rtt_delta_ms"`
	Weighted      bool    `json:"weighted"`
	UnknownVolume int     `json:"unknown_volume"`
	// MovedMbps is the volume of the moves taken, CommitMoves how many were
	// for a commit and CommitReliefMbps their volume: traffic taken off a
	// provider over its commit.
	MovedMbps        float64 `json:"moved_mbps"`
	CommitMoves      int     `json:"commit_moves"`
	CommitReliefMbps float64 `json:"commit_relief_mbps"`
}

// Report is the replay of one side.
type Report struct {
	Name         string  `json:"name"`
	Summary      Summary `json:"summary"`
	Moves        []Move  `json:"moves"`
	MovesOmitted int     `json:"moves_omitted,omitempty"`
}

// PrefixDiff is a prefix the two sides steered differently. Base and New are
// the providers it was steered to in order, "native" for a retire.
type PrefixDiff struct {
	Prefix netip.Prefix `json:"prefix"`
	Base   []string     `json:"base"`
	New    []string     `json:"new"`
}

// Result is a replay over one window.
type Result struct {
	Rounds int       `json:"rounds"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Sides  []Report  `json:"sides"`
	// Diff lists the prefixes the first two sides steered differently, in
	// prefix order. DiffOmitted counts those past MaxListed.
	Diff        []PrefixDiff `json:"diff"`
	DiffOmitted int          `json:"diff_omitted,omitempty"`
}

type tracker struct {
	side    Side
	state   policy.State
	sum     Summary
	moves   []Move
	omitted int
	steps   map[netip.Prefix][]string
	retired map[netip.Prefix]bool
	capped  map[netip.Prefix]bool

	lossW, rttW, weight float64
	n, volN             int
	plainLoss, plainRTT float64
}

func newTracker(s Side) *tracker {
	return &tracker{
		side: s, state: policy.NewState(), steps: map[netip.Prefix][]string{},
		retired: map[netip.Prefix]bool{}, capped: map[netip.Prefix]bool{},
		sum: Summary{MaxImprovements: s.Cfg.MaxImprovements},
	}
}

func (t *tracker) round(now time.Time, in policy.Input) {
	st, out := policy.Decide(t.state, in, t.side.Cfg, t.side.Scorer, now)
	t.state = st
	byPrefix := make(map[netip.Prefix]*policy.Decision, len(out.Decisions))
	cappedNow := false
	for i := range out.Decisions {
		d := &out.Decisions[i]
		byPrefix[d.Prefix] = d
		if d.Action == policy.ActionCapped {
			cappedNow = true
			t.capped[d.Prefix] = true
		}
	}
	if cappedNow {
		t.sum.CappedRounds++
	}
	for _, c := range out.Changes {
		t.change(now, c, byPrefix)
	}
	for _, q := range out.Quarantines {
		if q.Action == policy.QuarantineStart {
			t.sum.Quarantines++
		}
	}
	if n := len(st.Improvements); n > t.sum.PeakActive {
		t.sum.PeakActive = n
	}
}

func (t *tracker) change(now time.Time, c policy.Change, decisions map[netip.Prefix]*policy.Decision) {
	m := Move{At: now, Action: c.Action}
	switch c.Action {
	case policy.ActionRetire:
		m.Prefix, m.From, m.Cause, m.Reason = c.Old.Prefix, c.Old.Provider, c.Old.Cause, c.Old.Reason
		t.sum.Retires++
		t.retired[m.Prefix] = true
		t.steps[m.Prefix] = append(t.steps[m.Prefix], "native")
		t.add(m)
		return
	case policy.ActionImprove:
		m.From = c.New.Native
		t.sum.Improves++
		if t.retired[c.New.Prefix] {
			t.sum.Flaps++
		}
	case policy.ActionSwitch:
		m.From = c.Old.Provider
		t.sum.Switches++
		t.sum.Flaps++
	default:
		return
	}
	m.Prefix, m.To, m.Cause, m.Reason, m.VolumeMbps = c.New.Prefix, c.New.Provider, c.New.Cause, c.New.Reason, c.New.VolumeMbps
	if d := decisions[m.Prefix]; d != nil {
		var from, to *policy.Candidate
		for i := range d.Candidates {
			switch d.Candidates[i].Provider {
			case m.From:
				from = &d.Candidates[i]
			case m.To:
				to = &d.Candidates[i]
			}
		}
		if from != nil && to != nil {
			m.Measured = true
			m.LossDeltaPct = from.LossPct - to.LossPct
			m.RTTDeltaMs = float64(from.RTTAvg-to.RTTAvg) / float64(time.Millisecond)
		}
	}
	t.sum.MovedMbps += m.VolumeMbps
	if m.Cause == "commit" {
		t.sum.CommitMoves++
		t.sum.CommitReliefMbps += m.VolumeMbps
	}
	t.steps[m.Prefix] = append(t.steps[m.Prefix], m.To)
	t.accumulate(m)
	t.add(m)
}

func (t *tracker) accumulate(m Move) {
	if !m.Measured {
		return
	}
	t.n++
	t.plainLoss += m.LossDeltaPct
	t.plainRTT += m.RTTDeltaMs
	if m.VolumeMbps > 0 {
		t.weight += m.VolumeMbps
		t.volN++
		t.lossW += m.LossDeltaPct * m.VolumeMbps
		t.rttW += m.RTTDeltaMs * m.VolumeMbps
	}
}

func (t *tracker) add(m Move) {
	if len(t.moves) >= MaxListed {
		t.omitted++
		return
	}
	t.moves = append(t.moves, m)
}

func (t *tracker) report() Report {
	s := t.sum
	s.Prefixes = len(t.steps)
	s.Active = len(t.state.Improvements)
	s.CappedPrefixes = len(t.capped)
	switch {
	case t.weight > 0:
		s.Weighted = true
		s.LossDeltaPct, s.RTTDeltaMs = t.lossW/t.weight, t.rttW/t.weight
		s.UnknownVolume = t.n - t.volN
	case t.n > 0:
		s.LossDeltaPct, s.RTTDeltaMs = t.plainLoss/float64(t.n), t.plainRTT/float64(t.n)
	}
	return Report{Name: t.side.Name, Summary: s, Moves: t.moves, MovesOmitted: t.omitted}
}

// Run replays the stored rounds in [from, to) through every side. The sides
// see the same rounds in order, each from an empty state, so the first
// hold time of the window is decided without what was standing before it.
// It stops with ctx.
func Run(ctx context.Context, store plugin.RoundStore, from, to time.Time, sides []Side) (Result, error) {
	if len(sides) == 0 {
		return Result{}, errors.New("no settings to replay")
	}
	ts := make([]*tracker, len(sides))
	for i, s := range sides {
		ts[i] = newTracker(s)
	}
	var res Result
	cursor := from
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		page, err := store.Rounds(ctx, cursor, to, pageSize)
		if err != nil {
			return Result{}, err
		}
		for _, r := range page {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			now, in, err := Decode(r.Input)
			if err != nil {
				return Result{}, fmt.Errorf("round at %s: %w", r.At.UTC().Format(time.RFC3339), err)
			}
			if res.Rounds == 0 {
				res.From = now
			}
			res.To = now
			res.Rounds++
			for _, t := range ts {
				t.round(now, in)
			}
		}
		if len(page) < pageSize {
			break
		}
		cursor = page[len(page)-1].At.Add(time.Millisecond)
	}
	if res.Rounds == 0 {
		return Result{}, ErrNoRounds
	}
	for _, t := range ts {
		res.Sides = append(res.Sides, t.report())
	}
	if len(ts) >= 2 {
		res.Diff, res.DiffOmitted = diff(ts[0], ts[1])
	}
	return res, nil
}

func diff(a, b *tracker) ([]PrefixDiff, int) {
	seen := map[netip.Prefix]bool{}
	var ps []netip.Prefix
	for _, m := range []map[netip.Prefix][]string{a.steps, b.steps} {
		for p := range m {
			if !seen[p] {
				seen[p] = true
				ps = append(ps, p)
			}
		}
	}
	sort.Slice(ps, func(i, j int) bool { return netpfx.Less(ps[i], ps[j]) })
	var out []PrefixDiff
	omitted := 0
	for _, p := range ps {
		x, y := a.steps[p], b.steps[p]
		if equal(x, y) {
			continue
		}
		if len(out) >= MaxListed {
			omitted++
			continue
		}
		out = append(out, PrefixDiff{Prefix: p, Base: x, New: y})
	}
	return out, omitted
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// DefaultWindow is the span replayed when no start is given.
const DefaultWindow = 24 * time.Hour

// ParseWindow reads a replay window. from and to are RFC 3339 times or Go
// durations meaning that long before now. An empty from is DefaultWindow
// ago and an empty to is now.
func ParseWindow(from, to string, now time.Time) (time.Time, time.Time, error) {
	at := func(name, v string, def time.Duration) (time.Time, error) {
		switch {
		case v == "":
			return now.Add(-def), nil
		default:
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				return t, nil
			}
			d, err := time.ParseDuration(v)
			if err != nil || d < 0 {
				return time.Time{}, fmt.Errorf("%s %q is neither an RFC 3339 time nor a duration such as 6h", name, v)
			}
			return now.Add(-d), nil
		}
	}
	f, err := at("from", from, DefaultWindow)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	t, err := at("to", to, 0)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !f.Before(t) {
		return time.Time{}, time.Time{}, errors.New("from must be before to")
	}
	return f, t, nil
}
