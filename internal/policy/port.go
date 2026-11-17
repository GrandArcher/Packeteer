package policy

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/portload"
)

// portRefused starts the reason of every decision an exchange port refused
// (#643); the explanation reads it to tell that the port was full.
const portRefused = "exchange port: "

// portRoom is one exchange port's load for this evaluation (#643). The
// peers of the port share it, so a steer onto any of them draws from it.
type portRoom struct {
	name     string
	capacity float64
	commit   float64
	// ok is false when the port's telemetry row is missing, stale, or has
	// no billable figure; why says which. Such a port takes no new steer.
	ok  bool
	why string
	// load is portload.Read's capacity figure and p95 its billable 95th,
	// each plus the volume of steers the sample does not hold yet, as for
	// providerLoad.used.
	load float64
	p95  float64
}

// readPorts fills g.ports from cfg.Ports and the port rows in in.Usage. A
// steer onto a peer of the port that the sample does not hold yet is
// added: all of them outside inject mode, where nothing is on the wire.
func (g *loadGate) readPorts(st State, in Input, cfg Config, now time.Time) {
	byName := map[string]*portRoom{}
	for _, pp := range cfg.Ports {
		if pp.Name == "" || byName[pp.Name] != nil {
			continue
		}
		byName[pp.Name] = &portRoom{name: pp.Name, capacity: pp.CapacityMbps, commit: pp.CommitMbps, why: "no port telemetry"}
	}
	for _, pp := range cfg.Providers {
		if r := byName[pp.Port]; r != nil && pp.Port != "" {
			g.ports[pp.Name] = r
		}
	}
	seen := map[string]bool{}
	for _, u := range in.Usage {
		r := byName[u.Provider]
		if r == nil || seen[u.Provider] {
			continue
		}
		seen[u.Provider] = true
		load, p95, ok := portload.Read(u, now, portload.DefaultMaxAge)
		if !ok {
			r.why = "port reading is stale or has no billable figure"
			continue
		}
		r.ok, r.why, r.load, r.p95 = true, "", load, p95
		for _, imp := range st.Improvements {
			if g.ports[imp.Provider] == r && g.ports[imp.Native] != r && (cfg.Mode != "inject" || imp.Since.After(u.Updated)) {
				r.load += g.vols[imp.Prefix]
				r.p95 += g.vols[imp.Prefix]
			}
		}
	}
}

// refusePort says why a steer of p from one provider onto another would
// not fit the destination's exchange port, the same rule the commit and
// cost planners apply to their moves: the port's load plus the prefix
// volume stays inside its capacity and, when set, its 95th inside its
// commit. A destination that is not on a port, or that shares the source's
// port, always fits. A port with no usable reading, or a prefix with no
// known volume, cannot be checked and does not fit.
func (g *loadGate) refusePort(from, to string, p netip.Prefix) (string, bool) {
	if g == nil {
		return "", false
	}
	r := g.ports[to]
	if r == nil || r == g.ports[from] {
		return "", false
	}
	vol := g.vols[p]
	switch {
	case !r.ok:
		return fmt.Sprintf("%s%s: %s, so no new steer goes onto %s", portRefused, r.name, r.why, to), true
	case vol <= overloadEps:
		return fmt.Sprintf("%s%s: %s has no known volume, so the port's headroom cannot be checked for a steer onto %s", portRefused, r.name, p, to), true
	case r.load+vol > r.capacity+overloadEps:
		return fmt.Sprintf("%s%s would carry %s of its %s Mbps capacity with this %s Mbps steer onto %s",
			portRefused, r.name, fnum(r.load+vol), fnum(r.capacity), fnum(vol), to), true
	case r.commit > 0 && r.p95+vol > r.commit+overloadEps:
		return fmt.Sprintf("%s%s 95th would reach %s of its %s Mbps commit with this %s Mbps steer onto %s",
			portRefused, r.name, fnum(r.p95+vol), fnum(r.commit), fnum(vol), to), true
	}
	return "", false
}

// movePort adds sign times the steer's volume to its provider's port. A
// steer between two peers of one port leaves the port's load unchanged.
func (g *loadGate) movePort(imp Improvement, sign float64) {
	r := g.ports[imp.Provider]
	if r == nil || !r.ok || r == g.ports[imp.Native] {
		return
	}
	r.load = max(r.load+sign*g.vols[imp.Prefix], 0)
	r.p95 = max(r.p95+sign*g.vols[imp.Prefix], 0)
}
