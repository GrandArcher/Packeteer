package sqlite

import (
	"context"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Custom dashboards (#34), one row per owner and name. Retention does not
// prune them; deleting a user deletes the user's dashboards.

var _ plugin.DashboardStore = (*Store)(nil)

// Dashboards lists the owner's dashboards by name.
func (s *Store) Dashboards(ctx context.Context, owner string) ([]plugin.Dashboard, error) {
	db, err := s.handle()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT owner, name, spec, updated_ms FROM dashboards WHERE owner = ? ORDER BY name`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []plugin.Dashboard
	for rows.Next() {
		var d plugin.Dashboard
		var spec string
		var updated int64
		if err := rows.Scan(&d.Owner, &d.Name, &spec, &updated); err != nil {
			return nil, err
		}
		d.Spec, d.Updated = []byte(spec), fromMS(updated)
		out = append(out, d)
	}
	return out, rows.Err()
}

// PutDashboard creates or replaces a dashboard.
func (s *Store) PutDashboard(ctx context.Context, d plugin.Dashboard) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT OR REPLACE INTO dashboards (owner, name, spec, updated_ms) VALUES (?, ?, ?, ?)`,
		d.Owner, d.Name, string(d.Spec), ms(d.Updated))
	return err
}

// DeleteDashboard removes one dashboard.
func (s *Store) DeleteDashboard(ctx context.Context, owner, name string) (bool, error) {
	db, err := s.handle()
	if err != nil {
		return false, err
	}
	res, err := db.ExecContext(ctx, `DELETE FROM dashboards WHERE owner = ? AND name = ?`, owner, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
