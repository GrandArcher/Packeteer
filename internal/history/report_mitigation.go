package history

import (
	"cmp"
	"slices"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// MitigationRow is one threat mitigation rule (#28).
type MitigationRow struct {
	ID        string    `json:"id"`
	Prefix    string    `json:"prefix"`
	Action    string    `json:"action"`
	Target    string    `json:"target,omitempty"`
	Match     string    `json:"match,omitempty"`
	Countries string    `json:"source_countries,omitempty"`
	RateMbps  float64   `json:"rate_mbps,omitempty"`
	Routes    int       `json:"routes"`
	Reason    string    `json:"reason,omitempty"`
	Mode      string    `json:"mode"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	Announced time.Time `json:"announced,omitzero"`
	End       time.Time `json:"end,omitzero"`
	EndReason string    `json:"end_reason,omitempty"`
	// Hours is how long the rule was on the wire inside the range (zero
	// when it was never announced).
	Hours float64 `json:"announced_hours"`
}

func mitigations(in []plugin.MitigationRecord, q Query, rep *Report) {
	ms := slices.Clone(in)
	slices.SortFunc(ms, func(x, y plugin.MitigationRecord) int {
		if c := y.Created.Compare(x.Created); c != 0 {
			return c
		}
		return cmp.Compare(x.ID, y.ID)
	})
	if len(ms) > q.Limit {
		ms = ms[:q.Limit]
	}
	rows := make([]MitigationRow, 0, len(ms))
	rep.head = []string{"id", "prefix", "action", "target", "match", "source_countries", "rate_mbps", "routes", "reason", "mode",
		"created", "expires", "announced", "end", "end_reason", "announced_hours"}
	for _, m := range ms {
		row := MitigationRow{ID: m.ID, Prefix: m.Prefix.String(), Action: m.Action, Target: m.Target, Match: m.Match, Countries: m.Countries,
			RateMbps: m.RateMbps, Routes: m.Routes, Reason: m.Reason, Mode: m.Mode, Created: m.Created.UTC(), Expires: m.Expires.UTC(),
			EndReason: m.EndReason}
		if !m.Announced.IsZero() {
			row.Announced = m.Announced.UTC()
			end := q.Now
			if !m.End.IsZero() && m.End.Before(end) {
				end = m.End
			}
			start := m.Announced
			if start.Before(q.From) {
				start = q.From
			}
			if end.After(start) {
				row.Hours = round(end.Sub(start).Hours())
			}
		}
		if !m.End.IsZero() {
			row.End = m.End.UTC()
		}
		rows = append(rows, row)
		rep.lines = append(rep.lines, []string{row.ID, row.Prefix, row.Action, row.Target, row.Match, row.Countries, f(row.RateMbps),
			strconv.Itoa(row.Routes), row.Reason, row.Mode, ts(row.Created), ts(row.Expires), ts(row.Announced), ts(row.End), row.EndReason, f(row.Hours)})
	}
	rep.Rows = rows
}
