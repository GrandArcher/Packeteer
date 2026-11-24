package offload

import (
	"net/netip"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
)

// Verdicts classify one router in a report.
const (
	// VerdictFits: every wanted fix has room and nothing freezes.
	VerdictFits = "fits"
	// VerdictPartial: the chip already pushed short prefixes to the CPU, and
	// the default route rides the CPU path too.
	VerdictPartial = "partial_default_on_cpu"
	// VerdictNexthopExhausted: every next-hop entry of the chip is used.
	VerdictNexthopExhausted = "nexthop_exhausted"
	// VerdictFrozen: a pre-check, version rule or budget freeze stops installs.
	VerdictFrozen = "frozen"
	// VerdictUnavailable: no usable reading of the router.
	VerdictUnavailable = "unavailable"
)

// FixState is what the dry run says would happen to one wanted fix.
type FixState string

const (
	// FixOffload: the fix would be installed in hardware.
	FixOffload FixState = "offload"
	// FixSoftware: the platform does not offload the fix and the CPU carries it.
	FixSoftware FixState = "software"
	// FixWithhold: no room or no turn this round; the fix stays out of hardware.
	FixWithhold FixState = "withhold"
	// FixBlocked: a freeze or the run level stops it.
	FixBlocked FixState = "blocked"
)

// Wanted is a fix Decide wants and the provider it steers to.
type Wanted struct {
	Candidate
	Provider string
}

// Fix is the dry-run state of one wanted fix.
type Fix struct {
	Prefix     string   `json:"prefix"`
	Provider   string   `json:"provider"`
	Cause      string   `json:"cause,omitempty"`
	VolumeMbps *float64 `json:"volume_mbps,omitempty"`
	State      FixState `json:"state"`
	Reason     string   `json:"reason"`
}

// BuildFixes maps a plan onto the wanted fixes, ordered by prefix. A fix in
// software never entered the plan. When blockedReason is set the plan was not
// run and every other fix is blocked.
func BuildFixes(wanted []Wanted, software map[netip.Prefix]string, plan Plan, blockedReason string) []Fix {
	decided := make(map[netip.Prefix]Decision, len(plan.Decisions))
	for _, d := range plan.Decisions {
		decided[d.Prefix] = d
	}
	wanted = slices.SortedFunc(slices.Values(wanted), func(a, b Wanted) int {
		if netpfx.Less(a.Prefix, b.Prefix) {
			return -1
		}
		if netpfx.Less(b.Prefix, a.Prefix) {
			return 1
		}
		return 0
	})
	fixes := make([]Fix, 0, len(wanted))
	for _, w := range wanted {
		f := Fix{Prefix: w.Prefix.String(), Provider: w.Provider, Cause: w.Cause}
		if w.VolumeMbps > 0 {
			v := w.VolumeMbps
			f.VolumeMbps = &v
		}
		d, planned := decided[w.Prefix]
		switch why, soft := software[w.Prefix]; {
		case soft:
			f.State, f.Reason = FixSoftware, why
		case blockedReason != "":
			f.State, f.Reason = FixBlocked, blockedReason
		case !planned:
			f.State, f.Reason = FixBlocked, "not planned"
		case d.Action == Install:
			f.State, f.Reason = FixOffload, d.Reason
		case d.Reason == "frozen" || d.Reason == invalidReason:
			f.State, f.Reason = FixBlocked, d.Reason
		default:
			f.State, f.Reason = FixWithhold, d.Reason
		}
		fixes = append(fixes, f)
	}
	return fixes
}

// DimensionReport is one budget dimension: what the router reads, what is
// kept back and what is left to hand out, and how old the reading is.
type DimensionReport struct {
	Dimension Dimension `json:"dimension"`
	// Known is false when the router gave no reading. The numbers are 0
	// then and mean nothing.
	Known             bool         `json:"known"`
	Used              uint64       `json:"used"`
	Cap               uint64       `json:"cap"`
	Reserve           uint64       `json:"reserve"`
	Free              uint64       `json:"free"`
	ReadingAgeSeconds *float64     `json:"reading_age_seconds,omitempty"`
	Problem           FreezeReason `json:"problem,omitempty"`
}

// Dimensions reports each dimension of the budget at now. problems are the
// budget's freezes, so a dimension names why its reading is not trusted.
func Dimensions(b *Budget, now time.Time, dims []Dimension, samples map[Dimension]Sample, freezes []Freeze) []DimensionReport {
	out := make([]DimensionReport, 0, len(dims))
	for _, d := range dims {
		r := DimensionReport{Dimension: d}
		for _, f := range freezes {
			if f.Dimension == d && r.Problem == "" {
				r.Problem = f.Reason
			}
		}
		if s, ok := samples[d]; ok && s.Known {
			r.Known, r.Used, r.Cap = true, s.Used, s.Total
			if s.Used <= s.Total {
				r.Reserve, r.Free = b.Reserved(d, s.Total), b.Free(d, s.Reading)
			}
			if !s.At.IsZero() {
				age := max(now.Sub(s.At), 0).Seconds()
				r.ReadingAgeSeconds = &age
			}
		}
		out = append(out, r)
	}
	return out
}

// BlindSpot is something the report cannot see.
type BlindSpot struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Blind spot codes.
const (
	BlindTrafficFlow = "traffic_flow_blind"
	BlindNoVolume    = "no_volume"
)

// VolumeReport says where traffic volumes come from and how much of the
// traffic is already forwarded in hardware.
type VolumeReport struct {
	// Source is the configured volume_source; empty when none is named.
	Source string `json:"source"`
	// Prefixes is how many prefixes the source reported a rate for.
	Prefixes  int     `json:"prefixes"`
	TotalMbps float64 `json:"total_mbps"`
	// IGPMbps is the rate to destinations with no learned BGP route
	// (connected, IGP and static routes): the router already forwards these
	// in hardware.
	IGPMbps float64 `json:"igp_mbps"`
	// BGPMbps is the rate to destinations a learned BGP route covers. Any of
	// it may ride the CPU path, so it is the upper bound of that path.
	BGPMbps float64 `json:"bgp_mbps"`
	// HardwareShareMin is IGPMbps over TotalMbps, a lower bound of the
	// hardware-forwarded share: some BGP routes are in hardware too. Nil
	// when no rate is known.
	HardwareShareMin *float64    `json:"hardware_share_min,omitempty"`
	BlindSpots       []BlindSpot `json:"blind_spots"`
}

// BuildVolume splits the rates of the named source by whether a learned BGP
// route covers the destination. learned must treat a default route as no
// route.
func BuildVolume(source string, rates map[netip.Prefix]float64, learned func(netip.Prefix) bool) VolumeReport {
	v := VolumeReport{Source: source, BlindSpots: []BlindSpot{}}
	for p, mbps := range rates {
		v.Prefixes++
		v.TotalMbps += mbps
		if learned(p) {
			v.BGPMbps += mbps
		} else {
			v.IGPMbps += mbps
		}
	}
	if v.TotalMbps > 0 {
		share := v.IGPMbps / v.TotalMbps
		v.HardwareShareMin = &share
	}
	switch {
	case source == "":
		v.BlindSpots = append(v.BlindSpots, BlindSpot{BlindTrafficFlow,
			"RouterOS Traffic-Flow does not see hardware-forwarded traffic and no volume_source is named: fixes rank by path gain and the CPU path is not budgeted"})
	case v.Prefixes == 0:
		v.BlindSpots = append(v.BlindSpots, BlindSpot{BlindNoVolume,
			"volume source " + source + " reported no traffic: the CPU path cannot be measured and fixes rank by path gain"})
	}
	return v
}

// DefaultReport is the profile's default-route policy and whether the router
// meets it.
type DefaultReport struct {
	Policy PolicyKind `json:"policy"`
	Reason string     `json:"reason"`
	// Met is nil when no default route was read.
	Met    *bool  `json:"met,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Finding is one pre-check or threshold result.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// Counters are the route counts the router reports, when the profile has
// them.
type Counters struct {
	IPv4RoutesHW     int64 `json:"ipv4_routes_hw"`
	IPv4RoutesCPU    int64 `json:"ipv4_routes_cpu"`
	IPv6RoutesHW     int64 `json:"ipv6_routes_hw"`
	IPv6RoutesCPU    int64 `json:"ipv6_routes_cpu"`
	ShortestHWPrefix int64 `json:"shortest_hw_prefix"`
	// Hosts is reported, not budgeted.
	Hosts int64 `json:"hosts"`
	// RouteQueueLimitHigh and Low are the router's route queue limits; 0
	// when the advanced settings were not read.
	RouteQueueLimitHigh int64 `json:"route_queue_limit_high"`
	RouteQueueLimitLow  int64 `json:"route_queue_limit_low"`
}

// RouterReport is the dry-run report of one router. It decides nothing and
// changes nothing.
type RouterReport struct {
	Neighbor string `json:"neighbor"`
	Profile  string `json:"profile"`
	Status   Status `json:"status"`
	// Run is the configured run level, Level what the router allows now.
	Run   string `json:"run"`
	Level string `json:"level"`
	// Verdict is one of the Verdict constants.
	Verdict string `json:"verdict"`
	Version string `json:"version,omitempty"`
	// VersionVerdict is ok, warn, report_only, refused or unknown.
	VersionVerdict string            `json:"version_verdict"`
	Default        DefaultReport     `json:"default"`
	Dimensions     []DimensionReport `json:"dimensions"`
	Counters       *Counters         `json:"counters,omitempty"`
	Findings       []Finding         `json:"findings"`
	Freezes        []Freeze          `json:"freezes"`
	Fixes          []Fix             `json:"fixes"`
	Volume         VolumeReport      `json:"volume"`
	// ReadAt is when the router was last read; nil before the first read.
	ReadAt *time.Time `json:"read_at,omitempty"`
	// Error is why there is no reading, or why the plan failed.
	Error string `json:"error,omitempty"`
}

// DryRunReport is the dry-run report of every watched router.
type DryRunReport struct {
	At      time.Time      `json:"at"`
	Run     string         `json:"run"`
	Routers []RouterReport `json:"routers"`
}
