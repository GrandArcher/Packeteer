package history

import (
	"cmp"
	"slices"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Scopes and bases of a value row (#583).
const (
	ValueTotal    = "total"
	ValueProvider = "provider"
	ValueDay      = "day"

	// BasisAnnounced rows come from improvements recorded in inject: the
	// routes were on the wire. BasisEstimate rows come from observe and
	// suggest (and from records that predate the mode column): the move was
	// only recommended, so traffic did not change path.
	BasisAnnounced = "announced"
	BasisEstimate  = "estimate"
)

// ValueRow is the loss and latency a set of moves avoided: the native
// path's figure minus the chosen path's, both taken when each move started.
// A positive value is better; a move onto a path that measured worse
// subtracts. The avoided and before/after fields are absent when no move in
// the row had both measurements, so a row never shows a gain it did not
// measure. The RTT figures leave out a move where either path had no reply
// (loss 100). Weighting is "flow" (the scorecard's word) when every measured
// move carried a prefix volume, so the means are weighted by it, and "equal"
// for an unweighted mean. Announced and estimate rows are never mixed.
type ValueRow struct {
	Scope    string `json:"scope"`
	Provider string `json:"provider,omitempty"`
	Day      string `json:"day,omitempty"`
	Basis    string `json:"basis"`
	// Improvements started in the range, as in the improvements and
	// providers reports; Measured is those with a before and an after.
	Improvements int `json:"improvements"`
	Measured     int `json:"measured"`
	// SteeredHours is the time inside the range of the counted moves. The
	// providers report also counts moves that started before the range.
	SteeredHours  float64  `json:"steered_hours"`
	Weighting     string   `json:"weighting,omitempty"`
	VolumeMbps    float64  `json:"volume_mbps"`
	BeforeLossPct *float64 `json:"before_loss_pct,omitempty"`
	AfterLossPct  *float64 `json:"after_loss_pct,omitempty"`
	LossAvoided   *float64 `json:"loss_avoided_pct,omitempty"`
	BeforeRTTMs   *float64 `json:"before_rtt_ms,omitempty"`
	AfterRTTMs    *float64 `json:"after_rtt_ms,omitempty"`
	RTTAvoidedMs  *float64 `json:"rtt_avoided_ms,omitempty"`
}

type valueKey struct {
	scope, provider, day, basis string
}

type valueCell struct {
	improvements int
	hours        float64
	measured     []plugin.ImprovementRecord
}

// value builds the value report from the improvements that started in the
// range. A provider is credited only for moves onto it, so a provider that
// no move chose has no row, and a move whose chosen path measured worse
// than the native one counts against it. With a provider filter only moves
// onto that provider are counted.
func (a *agg) value(rep *Report) {
	cells := map[valueKey]*valueCell{}
	for _, r := range a.imps {
		if !a.started(r) || r.Provider == "" || a.q.Provider != "" && r.Provider != a.q.Provider {
			continue
		}
		basis := BasisEstimate
		if r.Mode == config.ModeInject {
			basis = BasisAnnounced
		}
		h := a.hours(r)
		for _, k := range []valueKey{
			{ValueTotal, "", "", basis},
			{ValueProvider, r.Provider, "", basis},
			{ValueDay, "", r.Start.UTC().Format(time.DateOnly), basis},
		} {
			c := cells[k]
			if c == nil {
				c = &valueCell{}
				cells[k] = c
			}
			c.improvements++
			c.hours += h
			if r.HasBefore && r.HasAfter {
				c.measured = append(c.measured, r)
			}
		}
	}
	rows := make([]ValueRow, 0, len(cells))
	for k, c := range cells {
		rows = append(rows, valueRow(k, c))
	}
	scopeOrder := []string{ValueTotal, ValueProvider, ValueDay}
	basisOrder := []string{BasisAnnounced, BasisEstimate}
	slices.SortFunc(rows, func(x, y ValueRow) int {
		if c := cmp.Compare(slices.Index(scopeOrder, x.Scope), slices.Index(scopeOrder, y.Scope)); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Provider, y.Provider); c != 0 {
			return c
		}
		if c := cmp.Compare(x.Day, y.Day); c != 0 {
			return c
		}
		return cmp.Compare(slices.Index(basisOrder, x.Basis), slices.Index(basisOrder, y.Basis))
	})
	rep.Rows = rows
	for _, r := range rows {
		rep.lines = append(rep.lines, []string{r.Scope, r.Provider, r.Day, r.Basis, strconv.Itoa(r.Improvements), strconv.Itoa(r.Measured),
			f(r.SteeredHours), r.Weighting, f(r.VolumeMbps), optS(r.BeforeLossPct), optS(r.AfterLossPct), optS(r.LossAvoided),
			optS(r.BeforeRTTMs), optS(r.AfterRTTMs), optS(r.RTTAvoidedMs)})
	}
}

func valueRow(k valueKey, c *valueCell) ValueRow {
	row := ValueRow{Scope: k.scope, Provider: k.provider, Day: k.day, Basis: k.basis,
		Improvements: c.improvements, Measured: len(c.measured), SteeredHours: round(c.hours)}
	if len(c.measured) == 0 {
		return row
	}
	byVolume := !slices.ContainsFunc(c.measured, func(r plugin.ImprovementRecord) bool { return r.VolumeMbps <= 0 })
	row.Weighting = WeightEqual
	if byVolume {
		row.Weighting = WeightFlow
	}
	// A path with no reply has loss 100 and no RTT (the recorder stores it
	// as 0), so a move needs two answering paths to count toward RTT;
	// otherwise a dead chosen path would read as latency avoided.
	var w, rw, bl, al, br, ar float64
	for _, r := range c.measured {
		x := 1.0
		if byVolume {
			x = r.VolumeMbps
			row.VolumeMbps += x
		}
		w += x
		bl += x * r.BeforeLoss
		al += x * r.AfterLoss
		if r.BeforeLoss < 100 && r.AfterLoss < 100 {
			rw += x
			br += x * r.BeforeRTT
			ar += x * r.AfterRTT
		}
	}
	row.VolumeMbps = round(row.VolumeMbps)
	row.BeforeLossPct, row.AfterLossPct, row.LossAvoided = ptr(round(bl/w)), ptr(round(al/w)), ptr(round((bl-al)/w))
	if rw > 0 {
		row.BeforeRTTMs, row.AfterRTTMs, row.RTTAvoidedMs = ptr(round(br/rw)), ptr(round(ar/rw)), ptr(round((br-ar)/rw))
	}
	return row
}
