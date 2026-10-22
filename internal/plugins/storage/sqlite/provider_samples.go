package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Per-provider five-minute probe samples. One row per provider and slot;
// a newer write for the slot replaces the row. Rows older than retention
// are deleted by prune. Backup copies the table with the rest of the file.

var _ plugin.ProviderSampleStore = (*Store)(nil)

// PutProviderSamples inserts samples. The same provider and slot replaces.
func (s *Store) PutProviderSamples(ctx context.Context, samples []plugin.ProviderSample) error {
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
		if sm.Provider == "" || sm.Slot.IsZero() {
			return fmt.Errorf("provider sample %d is missing a provider or a slot", i)
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO provider_samples
(provider, slot_ms, probes, failed, measured, loss_sum, rtt_sum_ms, jitter_sum_ms)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sm.Provider, ms(sm.Slot), sm.Probes, sm.Failed, sm.Measured, sm.LossSum, sm.RTTSumMs, sm.JitterSum)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ProviderSamples returns the rows whose slot is in [from, to), oldest first.
func (s *Store) ProviderSamples(ctx context.Context, from, to time.Time) ([]plugin.ProviderSample, error) {
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT provider, slot_ms, probes, failed, measured, loss_sum, rtt_sum_ms, jitter_sum_ms
FROM provider_samples WHERE slot_ms >= ? AND slot_ms < ? ORDER BY slot_ms, provider`, ms(from), ms(to))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.ProviderSample
	for rows.Next() {
		var sm plugin.ProviderSample
		var slot int64
		if err := rows.Scan(&sm.Provider, &slot, &sm.Probes, &sm.Failed, &sm.Measured, &sm.LossSum, &sm.RTTSumMs, &sm.JitterSum); err != nil {
			return nil, err
		}
		sm.Slot = fromMS(slot)
		out = append(out, sm)
	}
	return out, rows.Err()
}
