package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Decision rounds for replay (#204). One row per round, keyed by its time.
// Rows older than round_retention are deleted on each write and by prune.
// Backup copies the table with the rest of the file.

var _ plugin.RoundStore = (*Store)(nil)

// RoundRetention is round_retention; zero means no rounds are kept.
func (s *Store) RoundRetention() time.Duration { return s.roundRetention }

// OpenReadOnly opens an existing database file for reading only: no schema
// change, no prune, no write. `packeteer whatif` uses it instead of Start,
// so replaying history never touches the file a running controller writes.
func (s *Store) OpenReadOnly(ctx context.Context) error {
	if _, err := os.Stat(s.path); err != nil {
		return fmt.Errorf("no history at %s: %w", s.path, err)
	}
	db, err := sql.Open("sqlite", "file:"+s.path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return err
	}
	s.mu.Lock()
	s.db = db
	s.mu.Unlock()
	return nil
}

// PutRounds inserts rounds. The same At replaces.
func (s *Store) PutRounds(ctx context.Context, rounds []plugin.RoundRecord) error {
	if len(rounds) == 0 {
		return nil
	}
	if s.roundRetention == 0 {
		return fmt.Errorf("round_retention is 0: decision rounds are not kept")
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
	for i, r := range rounds {
		if r.At.IsZero() || len(r.Input) == 0 {
			return fmt.Errorf("decision round %d is missing its time or input", i)
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO decision_rounds (at_ms, input) VALUES (?, ?)`, ms(r.At), r.Input); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.pruneRounds(ctx, db)
}

// pruneRounds deletes rounds older than round_retention.
func (s *Store) pruneRounds(ctx context.Context, db *sql.DB) error {
	if s.roundRetention == 0 {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM decision_rounds WHERE at_ms < ?`, s.now().Add(-s.roundRetention).UnixMilli())
	return err
}

// Rounds returns at most limit rounds whose time is in [from, to), oldest
// first.
func (s *Store) Rounds(ctx context.Context, from, to time.Time, limit int) ([]plugin.RoundRecord, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit %d must be positive", limit)
	}
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT at_ms, input FROM decision_rounds WHERE at_ms >= ? AND at_ms < ? ORDER BY at_ms LIMIT ?`, ms(from), ms(to), limit)
	if err != nil {
		// A database from before round storage has no table: no rounds.
		if strings.Contains(err.Error(), "no such table") {
			return nil, nil
		}
		return nil, err
	}
	defer rows.Close()
	var out []plugin.RoundRecord
	for rows.Next() {
		var at int64
		var in []byte
		if err := rows.Scan(&at, &in); err != nil {
			return nil, err
		}
		out = append(out, plugin.RoundRecord{At: fromMS(at), Input: in})
	}
	return out, rows.Err()
}
