package plugin

import (
	"context"
	"time"
)

// Dashboard is one user's saved custom dashboard (#34). Spec is its
// layout as JSON; the core validates it before it is stored and again
// when it is read.
type Dashboard struct {
	Owner   string
	Name    string
	Spec    []byte
	Updated time.Time
}

// DashboardStore is optional on a storage plugin: it keeps custom
// dashboards. The built-in sqlite storage implements it. Dashboards only
// choose what the UI shows; they never change a decision.
type DashboardStore interface {
	// Dashboards lists the owner's dashboards by name.
	Dashboards(ctx context.Context, owner string) ([]Dashboard, error)
	// PutDashboard creates or replaces the owner's dashboard with that
	// name.
	PutDashboard(ctx context.Context, d Dashboard) error
	DeleteDashboard(ctx context.Context, owner, name string) (bool, error)
}
