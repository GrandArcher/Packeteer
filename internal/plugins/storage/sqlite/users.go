package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Users, API tokens, and the audit log (#32). Passwords are stored as
// PBKDF2 hashes and tokens as SHA-256 hashes; neither secret is stored.

var (
	_ plugin.UserStore  = (*Store)(nil)
	_ plugin.AuditStore = (*Store)(nil)
)

const userCols = `name, role, source, password_hash, disabled, created_ms, updated_ms`

func scanUser(sc interface{ Scan(...any) error }) (plugin.User, error) {
	var u plugin.User
	var role string
	var disabled int
	var created, updated int64
	if err := sc.Scan(&u.Name, &role, &u.Source, &u.PasswordHash, &disabled, &created, &updated); err != nil {
		return u, err
	}
	u.Role, u.Disabled, u.Created, u.Updated = plugin.Role(role), disabled != 0, fromMS(created), fromMS(updated)
	return u, nil
}

// Users lists every user.
func (s *Store) Users(ctx context.Context) ([]plugin.User, error) {
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// User reads one user.
func (s *Store) User(ctx context.Context, name string) (plugin.User, bool, error) {
	db, err := s.handle()
	if err != nil {
		return plugin.User{}, false, err
	}
	u, err := scanUser(db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return plugin.User{}, false, nil
	}
	return u, err == nil, err
}

// PutUser creates or replaces a user.
func (s *Store) PutUser(ctx context.Context, u plugin.User) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO users (`+userCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.Name, string(u.Role), u.Source, u.PasswordHash, b2i(u.Disabled), ms(u.Created), ms(u.Updated))
	return err
}

// DeleteUser removes a user and the user's tokens.
func (s *Store) DeleteUser(ctx context.Context, name string) (bool, error) {
	db, err := s.handle()
	if err != nil {
		return false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM api_tokens WHERE user_name = ?`, name); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dashboards WHERE owner = ?`, name); err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, tx.Commit()
}

const tokenCols = `id, user_name, name, role, hash, created_ms, expires_ms`

func scanToken(sc interface{ Scan(...any) error }) (plugin.APIToken, error) {
	var t plugin.APIToken
	var role string
	var created, expires int64
	if err := sc.Scan(&t.ID, &t.User, &t.Name, &role, &t.Hash, &created, &expires); err != nil {
		return t, err
	}
	t.Role, t.Created, t.Expires = plugin.Role(role), fromMS(created), fromMS(expires)
	return t, nil
}

// Tokens lists every API token (hashes only).
func (s *Store) Tokens(ctx context.Context) ([]plugin.APIToken, error) {
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT `+tokenCols+` FROM api_tokens ORDER BY user_name, created_ms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.APIToken
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Token reads one token by id.
func (s *Store) Token(ctx context.Context, id string) (plugin.APIToken, bool, error) {
	db, err := s.handle()
	if err != nil {
		return plugin.APIToken{}, false, err
	}
	t, err := scanToken(db.QueryRowContext(ctx, `SELECT `+tokenCols+` FROM api_tokens WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return plugin.APIToken{}, false, nil
	}
	return t, err == nil, err
}

// PutToken creates or replaces a token.
func (s *Store) PutToken(ctx context.Context, t plugin.APIToken) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO api_tokens (`+tokenCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.User, t.Name, string(t.Role), t.Hash, ms(t.Created), ms(t.Expires))
	return err
}

// DeleteToken removes a token.
func (s *Store) DeleteToken(ctx context.Context, id string) (bool, error) {
	db, err := s.handle()
	if err != nil {
		return false, err
	}
	res, err := db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// AppendAudit adds one audit record.
func (s *Store) AppendAudit(ctx context.Context, r plugin.AuditRecord) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO audit (id, time_ms, actor, role, method, remote, action, target, result, status, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, ms(r.Time), r.Actor, string(r.Role), r.Method, r.Remote, r.Action, r.Target, r.Result, r.Status, r.Detail)
	return err
}

// Audit returns records in [From, To), newest first.
func (s *Store) Audit(ctx context.Context, q plugin.AuditQuery) ([]plugin.AuditRecord, error) {
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
	limit := q.Limit
	if limit <= 0 {
		limit = -1
	}
	rows, err := db.QueryContext(ctx, `SELECT id, time_ms, actor, role, method, remote, action, target, result, status, detail
FROM audit WHERE time_ms >= ? AND time_ms < ? ORDER BY time_ms DESC, seq DESC LIMIT ?`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.AuditRecord
	for rows.Next() {
		var r plugin.AuditRecord
		var role string
		var at int64
		if err := rows.Scan(&r.ID, &at, &r.Actor, &role, &r.Method, &r.Remote, &r.Action, &r.Target, &r.Result, &r.Status, &r.Detail); err != nil {
			return nil, err
		}
		r.Role, r.Time = plugin.Role(role), fromMS(at)
		out = append(out, r)
	}
	return out, rows.Err()
}
