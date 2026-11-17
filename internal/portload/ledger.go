package portload

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const mbpsEps = 0.01

type port struct {
	name     string
	capacity float64
	commit   float64
	ok       bool
	// why says why the port has no usable reading when ok is false.
	why string
	// load is for capacity and p95 for commit, as in Read.
	load float64
	p95  float64
}

// Ledger is the planned load of every exchange port in one plan or one
// evaluation: the commit and cost scorers (#151) and the decision engine's
// check of performance moves and pins (#643). Every peer of an exchange with
// a port block draws from one port, so a move onto a peer is checked against
// the port's capacity and commit, not against the peer. The ledger fails
// closed: a port with no fresh telemetry row accepts no move, because its
// headroom is unknown.
type Ledger struct {
	byPeer map[string]*port
}

// NewLedger builds the ledger from a plan snapshot. maxAge is the
// telemetry freshness limit.
func NewLedger(in plugin.PlanInput, maxAge time.Duration) *Ledger {
	l := &Ledger{byPeer: map[string]*port{}}
	byName := map[string]*port{}
	for _, pp := range in.Ports {
		if pp.Name == "" || byName[pp.Name] != nil {
			continue
		}
		pt := &port{name: pp.Name, capacity: pp.CapacityMbps, commit: pp.CommitMbps, why: "no port telemetry"}
		if pp.HaveRow {
			pt.load, pt.p95, pt.ok = Read(pp.Usage, in.Now, maxAge)
			if !pt.ok {
				pt.why = "port reading is stale or has no billable figure"
			}
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
// the destination port inside its capacity and commit.
func (l *Ledger) Allows(from, to string, vol float64) bool { return l.Refusal(from, to, vol) == "" }

// Refusal says why moving vol Mbps from one provider to another would not
// keep the destination port inside its capacity and commit, "" when it
// would. A destination that is not on a port, or that shares the source's
// port, always passes. An unknown volume cannot be checked and does not pass
// onto a port. The reason starts with the port's name.
func (l *Ledger) Refusal(from, to string, vol float64) string {
	dst := l.byPeer[to]
	if dst == nil || dst == l.byPeer[from] {
		return ""
	}
	switch {
	case !dst.ok:
		return fmt.Sprintf("%s: %s, so no new steer goes onto %s", dst.name, dst.why, to)
	case vol <= mbpsEps:
		return fmt.Sprintf("%s: the prefix has no known volume, so the port's headroom cannot be checked for a steer onto %s", dst.name, to)
	case dst.load+vol > dst.capacity+mbpsEps:
		return fmt.Sprintf("%s would carry %s of its %s Mbps capacity with this %s Mbps steer onto %s",
			dst.name, mbps(dst.load+vol), mbps(dst.capacity), mbps(vol), to)
	case dst.commit > 0 && dst.p95+vol > dst.commit+mbpsEps:
		return fmt.Sprintf("%s 95th would reach %s of its %s Mbps commit with this %s Mbps steer onto %s",
			dst.name, mbps(dst.p95+vol), mbps(dst.commit), mbps(vol), to)
	}
	return ""
}

func mbps(v float64) string { return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0") }

// Move books vol Mbps leaving one provider and arriving on another. An
// empty from or to books only the other side.
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

// Headroom is Room for the provider's port. ok is false for a
// provider that is not on a port or whose port has no usable reading.
func (l *Ledger) Headroom(provider string) (float64, bool) {
	pt := l.byPeer[provider]
	if pt == nil || !pt.ok {
		return 0, false
	}
	return Room(pt.capacity, pt.commit, pt.load, pt.p95), true
}
