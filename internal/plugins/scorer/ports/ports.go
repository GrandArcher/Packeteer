// Package ports tracks a shared exchange port for the commit and cost
// scorers (#151). Every peer of an exchange with a port block draws from one
// port, so a planned move onto a peer is checked against the port's capacity
// and commit, not against the peer. The ledger fails closed: a port with no
// fresh telemetry row accepts no move, because its headroom is unknown.
package ports

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

	mbpsEps = 0.01
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

type port struct {
	capacity float64
	commit   float64
	ok       bool
	// load is for capacity and p95 for commit, as in Read.
	load float64
	p95  float64
}

// Ledger is the planned load of every port in one Plan call.
type Ledger struct {
	byPeer map[string]*port
}

// New builds the ledger from a plan snapshot. maxAge is the scorer's
// telemetry freshness limit.
func New(in plugin.PlanInput, maxAge time.Duration) *Ledger {
	l := &Ledger{byPeer: map[string]*port{}}
	byName := map[string]*port{}
	for _, pp := range in.Ports {
		if pp.Name == "" || byName[pp.Name] != nil {
			continue
		}
		pt := &port{capacity: pp.CapacityMbps, commit: pp.CommitMbps}
		if pp.HaveRow {
			pt.load, pt.p95, pt.ok = Read(pp.Usage, in.Now, maxAge)
		}
		byName[pp.Name] = pt
	}
	for _, p := range in.Providers {
		if pt := byName[p.Port]; pt != nil && p.Port != "" {
			l.byPeer[p.Name] = pt
		}
	}
	return l
}

// OnPort reports whether provider is a peer on a configured port.
func (l *Ledger) OnPort(provider string) bool { return l.byPeer[provider] != nil }

// Allows reports whether moving vol Mbps from one provider to another keeps
// the destination port inside its capacity and commit. A destination that is
// not on a port, or that shares the source's port, always passes. An unknown
// volume cannot be checked and does not pass onto a port.
func (l *Ledger) Allows(from, to string, vol float64) bool {
	dst := l.byPeer[to]
	if dst == nil || dst == l.byPeer[from] {
		return true
	}
	if !dst.ok || vol <= mbpsEps {
		return false
	}
	if dst.load+vol > dst.capacity+mbpsEps {
		return false
	}
	return dst.commit <= 0 || dst.p95+vol <= dst.commit+mbpsEps
}

// Move books vol Mbps leaving one provider and arriving on another.
func (l *Ledger) Move(from, to string, vol float64) {
	src, dst := l.byPeer[from], l.byPeer[to]
	if src == dst || vol <= 0 {
		return
	}
	if src != nil && src.ok {
		src.load = max(src.load-vol, 0)
		src.p95 = max(src.p95-vol, 0)
	}
	if dst != nil && dst.ok {
		dst.load += vol
		dst.p95 += vol
	}
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

// Headroom is Room for the provider's port. ok is false for a provider that is not on a
// port or whose port has no usable reading.
func (l *Ledger) Headroom(provider string) (float64, bool) {
	pt := l.byPeer[provider]
	if pt == nil || !pt.ok {
		return 0, false
	}
	return Room(pt.capacity, pt.commit, pt.load, pt.p95), true
}
