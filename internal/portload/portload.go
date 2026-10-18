// Package portload reads a shared exchange port's telemetry row (#151). The
// ops API and the commit and cost scorers judge the port by the same rules.
package portload

import (
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	// DefaultMaxAge is how old a port's telemetry row may be.
	DefaultMaxAge = 15 * time.Minute
	// MaxFutureSkew is how far ahead of the decision clock a row may be
	// stamped: it is read just after the clock, so a little is normal.
	MaxFutureSkew = time.Minute
)

// Fresh reports whether a reading stamped updated may be used at now. A zero
// stamp or clock, or a zero maxAge, is not aged out.
func Fresh(updated, now time.Time, maxAge time.Duration) bool {
	if updated.IsZero() || maxAge <= 0 || now.IsZero() {
		return true
	}
	age := now.Sub(updated)
	return age >= -MaxFutureSkew && age <= maxAge
}

// Read is a port row's load and billable 95th. load is the larger of the
// latest outbound rate and the 95th, the conservative figure for capacity.
// ok is false for a row that is stale or has no billable figure.
func Read(u plugin.Usage, now time.Time, maxAge time.Duration) (load, p95 float64, ok bool) {
	if !Fresh(u.Updated, now, maxAge) {
		return 0, 0, false
	}
	p95, ok = u.BillableMbps()
	if !ok {
		return 0, 0, false
	}
	return max(p95, u.OutMbps), p95, true
}

// Room is the Mbps a port still has under its capacity and, when commit is
// positive, under its commit.
func Room(capacity, commit, load, p95 float64) float64 {
	room := capacity - load
	if commit > 0 {
		room = min(room, commit-p95)
	}
	return room
}
