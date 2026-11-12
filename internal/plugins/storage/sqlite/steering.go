package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The operator steering state (#565): one row, replaced on every change.
// Retention does not prune it; backup copies it with the rest of the file.

var _ plugin.SteeringStore = (*Store)(nil)

// SteeringState returns the saved document, or nil.
func (s *Store) SteeringState(ctx context.Context) ([]byte, error) {
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	var doc []byte
	err = db.QueryRowContext(ctx, `SELECT doc FROM steering_state WHERE id = 1`).Scan(&doc)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return doc, err
}

// PutSteeringState replaces the saved document.
func (s *Store) PutSteeringState(ctx context.Context, doc []byte) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO steering_state (id, doc) VALUES (1, ?)`, doc)
	return err
}
