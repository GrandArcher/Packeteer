package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SNMP 95th-percentile samples (#127). One row per binding and sample
// time. The open period is what a restart loads. A closed period stays
// until retention deletes it (prune, by period end). Backup copies the
// table with the rest of the file.

var _ plugin.SampleStore = (*Store)(nil)

// PutUsageSamples inserts samples. The same binding and timestamp replaces.
func (s *Store) PutUsageSamples(ctx context.Context, samples []plugin.UsageSample) error {
	if len(samples) == 0 {
		return nil
	}
	db, err := s.handle()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for i, sm := range samples {
		if sm.Provider == "" || sm.Host == "" || sm.Interface == "" || sm.At.IsZero() || sm.PeriodStart.IsZero() || sm.PeriodEnd.IsZero() {
			return fmt.Errorf("usage sample %d is missing a binding or a period", i)
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO usage_samples
(provider, host, iface, period_start_ms, period_end_ms, at_ms, in_bps, out_bps)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sm.Provider, sm.Host, sm.Interface, ms(sm.PeriodStart), ms(sm.PeriodEnd), ms(sm.At), sm.InBps, sm.OutBps)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UsageSamples returns samples for one binding in [From, To), oldest first.
func (s *Store) UsageSamples(ctx context.Context, q plugin.UsageSampleQuery) ([]plugin.UsageSample, error) {
	if q.Provider == "" {
		return nil, fmt.Errorf("provider is required")
	}
	if q.Limit < 0 {
		return nil, fmt.Errorf("limit %d must not be negative", q.Limit)
	}
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	qstr := `SELECT provider, host, iface, period_start_ms, period_end_ms, at_ms, in_bps, out_bps
FROM usage_samples
WHERE provider = ? AND host = ? AND iface = ? AND at_ms >= ? AND at_ms < ?
ORDER BY at_ms`
	args := []any{q.Provider, q.Host, q.Interface, ms(q.From), ms(q.To)}
	if q.Limit > 0 {
		qstr = `SELECT provider, host, iface, period_start_ms, period_end_ms, at_ms, in_bps, out_bps FROM (
SELECT provider, host, iface, period_start_ms, period_end_ms, at_ms, in_bps, out_bps
FROM usage_samples
WHERE provider = ? AND host = ? AND iface = ? AND at_ms >= ? AND at_ms < ?
ORDER BY at_ms DESC LIMIT ?
) ORDER BY at_ms`
		args = append(args, q.Limit)
	}
	rows, err := db.QueryContext(ctx, qstr, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.UsageSample
	for rows.Next() {
		var sm plugin.UsageSample
		var start, end, at int64
		if err := rows.Scan(&sm.Provider, &sm.Host, &sm.Interface, &start, &end, &at, &sm.InBps, &sm.OutBps); err != nil {
			return nil, err
		}
		sm.PeriodStart, sm.PeriodEnd, sm.At = fromMS(start), fromMS(end), fromMS(at)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// TrimUsageSamples drops samples inside the period that the open window
// has already forgotten. Rows outside [periodStart, periodEnd) stay.
func (s *Store) TrimUsageSamples(ctx context.Context, provider, host, iface string, periodStart, periodEnd, oldestKept time.Time) error {
	if oldestKept.IsZero() {
		return nil
	}
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM usage_samples
WHERE provider = ? AND host = ? AND iface = ? AND at_ms >= ? AND at_ms < ? AND at_ms < ?`,
		provider, host, iface, ms(periodStart), ms(periodEnd), ms(oldestKept))
	return err
}
