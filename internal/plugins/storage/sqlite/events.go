package sqlite

import (
	"context"
	"encoding/json"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var _ plugin.EventStore = (*Store)(nil)

// AppendEvent adds one event. Retention prunes it with the other rows.
func (s *Store) AppendEvent(ctx context.Context, e plugin.Event) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	fields, err := json.Marshal(e.Fields)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO events (time_ms, kind, severity, message, fields) VALUES (?, ?, ?, ?, ?)`,
		ms(e.Time), e.Kind, string(e.Severity), e.Message, string(fields))
	return err
}

// Events returns events matching q, newest first. Time and severity are
// not filtered in SQL: the text match is shared with the in-memory log, so
// rows are read newest first and stop once Limit matches are found.
func (s *Store) Events(ctx context.Context, q plugin.EventQuery) ([]plugin.Event, error) {
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	from, to := int64(0), int64(1)<<62
	if !q.From.IsZero() {
		from = q.From.UnixMilli()
	}
	if !q.To.IsZero() {
		to = q.To.UnixMilli()
	}
	rows, err := db.QueryContext(ctx, `SELECT time_ms, kind, severity, message, fields
FROM events WHERE time_ms >= ? AND time_ms < ? ORDER BY time_ms DESC, seq DESC`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.Event
	for rows.Next() {
		var e plugin.Event
		var at int64
		var sev, fields string
		if err := rows.Scan(&at, &e.Kind, &sev, &e.Message, &fields); err != nil {
			return nil, err
		}
		e.Time, e.Severity = fromMS(at), plugin.Severity(sev)
		if fields != "" && fields != "null" {
			if err := json.Unmarshal([]byte(fields), &e.Fields); err != nil {
				return nil, err
			}
		}
		if !q.Match(e) {
			continue
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) == q.Limit {
			break
		}
	}
	return out, rows.Err()
}
