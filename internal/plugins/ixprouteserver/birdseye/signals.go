package birdseye

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// blackholeASN and blackholeValue are the RFC 7999 BLACKHOLE community
// 65535:666. A route that carries it is counted, and left out of the
// origin and more-specific checks: a member blackholing a /32 inside
// another network's space is expected.
const (
	blackholeASN   = 65535
	blackholeValue = 666
)

// spikeReasons are the rs-asn:1101:x tags watched for a jump in the number
// of filtered routes.
var spikeReasons = []struct {
	code  int
	label string
}{
	{9, "IRR filter"},
	{10, "IRR filter"},
	{13, "RPKI invalid"},
	{14, "transit-free ASN in the path"},
}

// scan is the accepted routes of one session and its blackhole count.
type scan struct {
	routes    map[netip.Prefix]uint32
	blackhole int
}

// scanSession lists a session's routes. Birdseye refuses a listing over
// its max_routes, so a larger session is not requested.
func (w *Watch) scanSession(ctx context.Context, s *server, name string, received, maxRoutes int) (*scan, error) {
	if maxRoutes > 0 && received > maxRoutes {
		return nil, fmt.Errorf("session has more routes than Birdseye api.max_routes (%d)", maxRoutes)
	}
	var doc struct {
		Routes []struct {
			Network string `json:"network"`
			BGP     struct {
				ASPath      []string    `json:"as_path"`
				Communities [][2]uint64 `json:"communities"`
				Large       [][3]uint64 `json:"large_communities"`
			} `json:"bgp"`
		} `json:"routes"`
	}
	if err := w.get(ctx, s.base, pathRoutes(name), &doc); err != nil {
		return nil, err
	}
	sc := &scan{routes: make(map[netip.Prefix]uint32, len(doc.Routes))}
	for _, r := range doc.Routes {
		if hasCommunity(r.BGP.Communities, blackholeASN, blackholeValue) {
			sc.blackhole++
			continue
		}
		if filteredByServer(r.BGP.Large, s.cfg.ASN) {
			continue
		}
		pfx, err := netip.ParsePrefix(r.Network)
		if err != nil {
			continue
		}
		origin, ok := originAS(r.BGP.ASPath)
		if !ok {
			continue
		}
		sc.routes[pfx.Masked()] = origin
	}
	return sc, nil
}

func hasCommunity(list [][2]uint64, asn, value uint64) bool {
	for _, c := range list {
		if c[0] == asn && c[1] == value {
			return true
		}
	}
	return false
}

// filteredByServer is true for a route tagged rs-asn:1101:x.
func filteredByServer(large [][3]uint64, asn uint32) bool {
	for _, c := range large {
		if c[0] == uint64(asn) && c[1] == reasonCommunity {
			return true
		}
	}
	return false
}

// originAS is the last AS of the path. A path that ends in an AS set, or
// is empty, has no single origin.
func originAS(path []string) (uint32, bool) {
	if len(path) == 0 {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(path[len(path)-1]), 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// owner is one session's accepted route for a prefix.
type owner struct {
	asn    uint32
	origin uint32
}

type routeIndex map[netip.Prefix][]owner

// index lists, per prefix, who announced it in the last poll.
func (s *server) index() routeIndex {
	idx := routeIndex{}
	for _, st := range s.sessions {
		for p, o := range st.routes {
			idx[p] = append(idx[p], owner{asn: st.view.ASN, origin: o})
		}
	}
	return idx
}

func (s *server) tracked() int {
	n := 0
	for _, st := range s.sessions {
		n += len(st.routes)
	}
	return n
}

// others reports whether another member announced the prefix, and whether
// one of them used the origin.
func others(list []owner, member, origin uint32) (other, same bool) {
	for _, o := range list {
		if o.asn == member {
			continue
		}
		other = true
		if o.origin == origin {
			same = true
		}
	}
	return other, same
}

// coveredByOther is true when a shorter prefix of the route is accepted
// from another member and none of them uses the route's origin.
func coveredByOther(idx routeIndex, p netip.Prefix, member, origin uint32) bool {
	for bits := p.Bits() - 1; bits >= 1; bits-- {
		cover, err := p.Addr().Prefix(bits)
		if err != nil {
			return false
		}
		if other, same := others(idx[cover], member, origin); other && !same {
			return true
		}
	}
	return false
}

// routeSignals judges a session's new routes against what the other
// members announced in the previous poll (idx). A route is new when the
// session did not announce that prefix with that origin last time. The
// first listing of a session that was there at the server's first poll is
// its baseline and raises nothing. A route that gives a prefix an origin no
// other member uses is an origin change. At least burst_min new routes
// inside another member's prefix, with another origin, are a burst. Both
// alerts stay open while the routes stay.
func (w *Watch) routeSignals(st *sess, row plugin.RouteServerSession, sc *scan, idx routeIndex, now time.Time) []plugin.Event {
	prev := st.routes
	st.routes = sc.routes
	if prev == nil && !st.fresh {
		return nil
	}
	if st.originFlag == nil {
		st.originFlag = map[netip.Prefix]uint32{}
		st.msFlag = map[netip.Prefix]uint32{}
	}
	hadOrigin, hadMS := len(st.originFlag) > 0, len(st.msFlag) > 0
	for p, o := range st.originFlag {
		if sc.routes[p] != o {
			delete(st.originFlag, p)
		}
	}
	for p, o := range st.msFlag {
		if sc.routes[p] != o {
			delete(st.msFlag, p)
		}
	}
	burst := map[netip.Prefix]uint32{}
	for p, o := range sc.routes {
		if po, ok := prev[p]; ok && po == o {
			continue
		}
		switch other, same := others(idx[p], row.ASN, o); {
		case other && !same:
			st.originFlag[p] = o
		case !other && coveredByOther(idx, p, row.ASN, o):
			burst[p] = o
		}
	}
	if len(burst) >= w.burstMin {
		for p, o := range burst {
			st.msFlag[p] = o
		}
	}
	var ev []plugin.Event
	if n := len(st.originFlag); n > 0 && !hadOrigin {
		p, o := firstRoute(st.originFlag)
		ev = append(ev, plugin.NewEvent(plugin.EventRSOriginChange, now,
			fmt.Sprintf("%s: %d prefixes announced with an origin AS no other member uses, such as %s from AS%d", label(row), n, p, o),
			fields(row, "count", strconv.Itoa(n), "prefix", p.String(), "origin", strconv.FormatUint(uint64(o), 10))))
	} else if n == 0 && hadOrigin {
		ev = append(ev, plugin.NewEvent(plugin.EventRSOriginChangeCleared, now,
			label(row)+": the conflicting origins are gone", fields(row)))
	}
	if n := len(st.msFlag); n > 0 && !hadMS {
		p, o := firstRoute(st.msFlag)
		ev = append(ev, plugin.NewEvent(plugin.EventRSMoreSpecific, now,
			fmt.Sprintf("%s: %d more-specifics of other members' prefixes, such as %s from AS%d", label(row), n, p, o),
			fields(row, "count", strconv.Itoa(n), "prefix", p.String(), "origin", strconv.FormatUint(uint64(o), 10))))
	} else if n == 0 && hadMS {
		ev = append(ev, plugin.NewEvent(plugin.EventRSMoreSpecificCleared, now,
			label(row)+": the more-specifics are gone", fields(row)))
	}
	return ev
}

// firstRoute is the lowest prefix of the set, so an event names the same
// example for the same data.
func firstRoute(m map[netip.Prefix]uint32) (netip.Prefix, uint32) {
	var best netip.Prefix
	for p := range m {
		if !best.IsValid() || p.Addr().Less(best.Addr()) || (p.Addr() == best.Addr() && p.Bits() < best.Bits()) {
			best = p
		}
	}
	return best, m[best]
}

// baseline is, per spike reason, the highest count in the last
// baselineSamples counted samples of the session. The bool is false
// before the session has one.
func (s *server) baseline(session string) (map[int]int, bool) {
	h := s.history[session]
	out := map[int]int{}
	n := 0
	for i := len(h) - 1; i >= 0 && n < baselineSamples; i-- {
		if h[i].flags&flagCounted == 0 || h[i].flags&flagEstablished == 0 {
			continue
		}
		n++
		for _, r := range h[i].reasons {
			out[r.Reason] = max(out[r.Reason], r.Count)
		}
	}
	return out, n > 0
}

func reasonCount(list []plugin.RouteServerReason, code int) int {
	for _, r := range list {
		if r.Reason == code {
			return r.Count
		}
	}
	return 0
}

// isSpike is true when n is at least spike_min above the level and at least
// spike_factor times it.
func (w *Watch) isSpike(n, level int) bool {
	return n-level >= w.spikeMin && n >= level*w.spikeX
}

// spikes opens an alert when a watched reason's count jumps above the
// level of the last polls, and closes it when the count falls back below
// the same threshold. The level is fixed while the alert is open.
func (w *Watch) spikes(st *sess, row plugin.RouteServerSession, base map[int]int, haveBase bool, now time.Time) []plugin.Event {
	var ev []plugin.Event
	for _, r := range spikeReasons {
		n := reasonCount(row.Reasons, r.code)
		f := fields(row, "reason", strconv.Itoa(r.code), "count", strconv.Itoa(n))
		if level, open := st.spike[r.code]; open {
			if !w.isSpike(n, level) {
				delete(st.spike, r.code)
				ev = append(ev, plugin.NewEvent(plugin.EventRSFilterSpikeCleared, now,
					fmt.Sprintf("%s: %d routes filtered as %s (1101:%d)", label(row), n, r.label, r.code), f))
			}
			continue
		}
		if haveBase && w.isSpike(n, base[r.code]) {
			if st.spike == nil {
				st.spike = map[int]int{}
			}
			st.spike[r.code] = base[r.code]
			f["baseline"] = strconv.Itoa(base[r.code])
			ev = append(ev, plugin.NewEvent(plugin.EventRSFilterSpike, now,
				fmt.Sprintf("%s: %d routes filtered as %s (1101:%d), up from %d", label(row), n, r.label, r.code, base[r.code]), f))
		}
	}
	return ev
}

// closeSignals resolves the spike, origin, and more-specific alerts of a
// session that is no longer visible. The route table is dropped and the
// session counts as new, so it is judged afresh if it comes back.
func (w *Watch) closeSignals(st *sess, now time.Time, why string) []plugin.Event {
	row := st.view
	var ev []plugin.Event
	codes := make([]int, 0, len(st.spike))
	for c := range st.spike {
		codes = append(codes, c)
	}
	sort.Ints(codes)
	for _, c := range codes {
		ev = append(ev, plugin.NewEvent(plugin.EventRSFilterSpikeCleared, now,
			label(row)+" "+why, fields(row, "reason", strconv.Itoa(c), "count", "0")))
	}
	if len(st.originFlag) > 0 {
		ev = append(ev, plugin.NewEvent(plugin.EventRSOriginChangeCleared, now, label(row)+" "+why, fields(row)))
	}
	if len(st.msFlag) > 0 {
		ev = append(ev, plugin.NewEvent(plugin.EventRSMoreSpecificCleared, now, label(row)+" "+why, fields(row)))
	}
	st.spike, st.originFlag, st.msFlag = nil, nil, nil
	st.routes, st.fresh = nil, true
	return ev
}
