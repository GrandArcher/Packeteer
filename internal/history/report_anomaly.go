package history

import (
	"cmp"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// AnomalyRow is one traffic anomaly (#33).
type AnomalyRow struct {
	ID           string    `json:"id"`
	Prefix       string    `json:"prefix"`
	Protocol     string    `json:"protocol"`
	PeakMbps     float64   `json:"peak_mbps"`
	BaselineMbps float64   `json:"baseline_mbps"`
	Reason       string    `json:"reason"`
	Rule         string    `json:"rule,omitempty"`
	Mitigation   string    `json:"mitigation,omitempty"`
	Action       string    `json:"action,omitempty"`
	Start        time.Time `json:"start"`
	End          time.Time `json:"end,omitzero"`
	EndReason    string    `json:"end_reason,omitempty"`
	// Minutes is how long the anomaly lasted inside the range.
	Minutes float64 `json:"minutes"`
}

func anomalies(in []plugin.AnomalyRecord, q Query, rep *Report) {
	as := slices.Clone(in)
	slices.SortFunc(as, func(x, y plugin.AnomalyRecord) int {
		if c := y.Start.Compare(x.Start); c != 0 {
			return c
		}
		return cmp.Compare(x.ID, y.ID)
	})
	if len(as) > q.Limit {
		as = as[:q.Limit]
	}
	rows := make([]AnomalyRow, 0, len(as))
	rep.head = []string{"id", "prefix", "protocol", "peak_mbps", "baseline_mbps", "reason", "rule", "mitigation", "action",
		"start", "end", "end_reason", "minutes"}
	for _, a := range as {
		row := AnomalyRow{ID: a.ID, Prefix: a.Prefix.String(), Protocol: a.Protocol, PeakMbps: round(a.PeakMbps), BaselineMbps: round(a.BaselineMbps),
			Reason: a.Reason, Rule: a.Rule, Mitigation: a.Mitigation, Action: a.Action, Start: a.Start.UTC(), EndReason: a.EndReason}
		end := q.Now
		if !a.End.IsZero() {
			row.End = a.End.UTC()
			if a.End.Before(end) {
				end = a.End
			}
		}
		start := a.Start
		if start.Before(q.From) {
			start = q.From
		}
		if end.After(start) {
			row.Minutes = round(end.Sub(start).Minutes())
		}
		rows = append(rows, row)
		rep.lines = append(rep.lines, []string{row.ID, row.Prefix, row.Protocol, f(row.PeakMbps), f(row.BaselineMbps), row.Reason, row.Rule,
			row.Mitigation, row.Action, ts(row.Start), ts(row.End), row.EndReason, f(row.Minutes)})
	}
	rep.Rows = rows
}
