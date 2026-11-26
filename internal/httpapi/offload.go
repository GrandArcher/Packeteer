package httpapi

import (
	"net/http"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/offload"
)

// OffloadControl is the offload_aware dry run (#738): per router, what the
// hardware routing budget would allow if the wanted fixes were installed. It
// only reports; nothing is announced, installed, or changed on a router.
type OffloadControl interface {
	Report() offload.DryRunReport
}

// SetOffload installs the dry-run source. It may be called after New, and
// only when offload_aware is enabled.
func (s *Server) SetOffload(o OffloadControl) {
	if s == nil {
		return
	}
	s.offload.Store(&o)
}

func (s *Server) offloadControl() OffloadControl {
	if o := s.offload.Load(); o != nil {
		return *o
	}
	return nil
}

// handleOffload answers with the dry-run report, or available false when
// offload_aware is off.
func (s *Server) handleOffload(w http.ResponseWriter, _ *http.Request) {
	o := s.offloadControl()
	if o == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": true, "report": o.Report()})
}

// OffloadMetrics renders the offload_aware readings: what each router
// reports, how old the reading is, and why installs are frozen.
func OffloadMetrics(rep offload.DryRunReport) []byte {
	var b strings.Builder
	var lpmUsed, lpmCap, nhUsed, nhCap, routes, shwp, queue, age, freeze, fixes []sample
	for _, r := range rep.Routers {
		router := lbl{"router", r.Neighbor}
		for _, d := range r.Dimensions {
			if d.ReadingAgeSeconds != nil {
				age = append(age, sample{labels: []lbl{router, {"dimension", string(d.Dimension)}}, value: *d.ReadingAgeSeconds})
			}
			if !d.Known {
				continue
			}
			switch d.Dimension {
			case offload.FIBv4:
				lpmUsed = append(lpmUsed, sample{labels: []lbl{router}, value: float64(d.Used)})
				lpmCap = append(lpmCap, sample{labels: []lbl{router}, value: float64(d.Cap)})
			case offload.NextHops:
				nhUsed = append(nhUsed, sample{labels: []lbl{router}, value: float64(d.Used)})
				nhCap = append(nhCap, sample{labels: []lbl{router}, value: float64(d.Cap)})
			}
		}
		if c := r.Counters; c != nil {
			for _, x := range []struct {
				family, place string
				n             int64
			}{{"ipv4", "hw", c.IPv4RoutesHW}, {"ipv4", "cpu", c.IPv4RoutesCPU}, {"ipv6", "hw", c.IPv6RoutesHW}, {"ipv6", "cpu", c.IPv6RoutesCPU}} {
				routes = append(routes, sample{labels: []lbl{router, {"family", x.family}, {"place", x.place}}, value: float64(x.n)})
			}
			shwp = append(shwp, sample{labels: []lbl{router}, value: float64(c.ShortestHWPrefix)})
			queue = append(queue,
				sample{labels: []lbl{router, {"bound", "high"}}, value: float64(c.RouteQueueLimitHigh)},
				sample{labels: []lbl{router, {"bound", "low"}}, value: float64(c.RouteQueueLimitLow)})
		}
		for _, f := range r.Freezes {
			freeze = append(freeze, sample{labels: []lbl{router, {"reason", string(f.Reason)}, {"dimension", string(f.Dimension)}}, value: 1})
		}
		count := map[offload.FixState]int{}
		for _, f := range r.Fixes {
			count[f.State]++
		}
		for _, st := range []offload.FixState{offload.FixOffload, offload.FixSoftware, offload.FixWithhold, offload.FixBlocked} {
			fixes = append(fixes, sample{labels: []lbl{router, {"state", string(st)}}, value: float64(count[st])})
		}
	}
	writeGauge(&b, "packeteer_offload_lpm_used", "Hardware LPM entries in use on the router (offload_aware dry run).", lpmUsed...)
	writeGauge(&b, "packeteer_offload_lpm_cap", "Hardware LPM entries the router can hold, capped at the profile's target.", lpmCap...)
	writeGauge(&b, "packeteer_offload_routes", "Routes the router reports in hardware or on the CPU, by family.", routes...)
	writeGauge(&b, "packeteer_offload_shortest_hw_prefix", "Shortest IPv4 prefix length in hardware (SHWP); above 0 the table is partly on the CPU.", shwp...)
	writeGauge(&b, "packeteer_offload_nexthop_used", "Hardware next-hop entries in use.", nhUsed...)
	writeGauge(&b, "packeteer_offload_nexthop_cap", "Hardware next-hop entries the chip has.", nhCap...)
	writeGauge(&b, "packeteer_offload_route_queue_limit", "The router's route queue limits (high and low), 0 when its advanced settings were not read.", queue...)
	writeGauge(&b, "packeteer_offload_reading_age_seconds", "Age of the reading of a budget dimension.", age...)
	writeGauge(&b, "packeteer_offload_freeze", "1 for each reason installs are frozen on the router: missing, stale, insane, pre_check_failed, known_bad_version, default_policy_violated, settling.", freeze...)
	writeGauge(&b, "packeteer_offload_fixes", "Wanted fixes by dry-run state: offload, software, withhold, blocked.", fixes...)
	return []byte(b.String())
}
