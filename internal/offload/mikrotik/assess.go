package mikrotik

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
)

// Severity is how a finding limits the profile.
type Severity string

const (
	// Warn is reported and limits nothing.
	Warn Severity = "warn"
	// Freeze stops installs and sheds until the cause is gone.
	Freeze Severity = "freeze"
	// Alarm freezes like Freeze and must be logged loudly: the profile's
	// default policy is violated.
	Alarm Severity = "alarm"
)

// Pre-check codes. Each has a fixture in the tests that triggers it.
const (
	CheckVRF           = "vrf"
	CheckRoutingRules  = "routing_rules"
	CheckMangleMarks   = "mangle_marks"
	CheckForwardBypass = "forward_bypass"
	CheckMultiBridge   = "multiple_bridges"
	CheckVLANOnPort    = "vlan_on_port_or_bond"
	CheckAsymmetric    = "asymmetric_l3hw"
	CheckBondMode      = "bond_mode"
	CheckVRRP          = "vrrp"
	CheckL3HWDisabled  = "l3hw_disabled"
)

var preChecks = []string{
	CheckVRF, CheckRoutingRules, CheckMangleMarks, CheckForwardBypass, CheckMultiBridge,
	CheckVLANOnPort, CheckAsymmetric, CheckBondMode, CheckVRRP, CheckL3HWDisabled,
}

// Other finding codes.
const (
	CodeNotApplicable     = "not_applicable"
	CodeVersionRefused    = "version_refused"
	CodeVersionReportOnly = "version_report_only"
	CodeVersionWarn       = "version_warn"
	CodeVersionUnknown    = "version_unknown"
	CodeDefaultInHW       = "default_in_hardware"
	CodeDefaultEligible   = "default_not_suppressed"
	CodeSHWP              = "shwp_above_zero"
	CodeNexthopWarn       = "nexthop_warn"
	CodeNexthopFull       = "nexthop_exhausted"
	CodeNoVolumeSource    = "no_volume_source"
	CodeRouteIndexDelay   = "route_index_delay"
)

// Finding is one thing Assess found.
type Finding struct {
	Code     string
	Severity Severity
	Detail   string
}

// Assessment is what a reading allows. MaxRun is the most the profile may do
// on this router now; Freezes are the reasons to stop installing and
// shedding, to be merged into the budget result with Gate.
type Assessment struct {
	MaxRun   offload.RunLevel
	Freezes  []offload.Freeze
	Findings []Finding
	// IPv4Hosts is the host-entry count from the monitor. It is reported
	// only: no host-table cap is published or read, so it is not budgeted.
	IPv4Hosts int64
}

func (a *Assessment) add(code string, sev Severity, reason offload.FreezeReason, dim offload.Dimension, format string, args ...any) {
	a.Findings = append(a.Findings, Finding{Code: code, Severity: sev, Detail: fmt.Sprintf(format, args...)})
	if sev == Warn {
		return
	}
	f := offload.Freeze{Reason: reason, Dimension: dim}
	for _, have := range a.Freezes {
		if have == f {
			return
		}
	}
	a.Freezes = append(a.Freezes, f)
}

// Assess applies the version rules, the default-route policy, the pre-checks
// and the thresholds to one reading. It does not need the budget readings.
func Assess(l routeros.L3HW, opts Options) Assessment {
	a := Assessment{MaxRun: offload.DryRun, IPv4Hosts: l.Monitor.IPv4Hosts}
	if !l.Applicable {
		a.add(CodeNotApplicable, Warn, "", "", "the router exposes no L3HW monitor (no switch chip, a CHR, or RouterOS older than 7.10)")
		// RouterOS before 7.10 has no monitor, so the version rules must run
		// here: they are the only place a 7.3 to 7.9 router is told apart.
		if _, ok := parseVersion(l.Version); ok {
			a.version(l.Version)
		}
		if a.MaxRun == offload.DryRun {
			a.MaxRun = offload.Refuse
		}
		return a
	}
	a.version(l.Version)
	if opts.VolumeSource == "" {
		a.add(CodeNoVolumeSource, Warn, "", "", "RouterOS Traffic-Flow does not see hardware-forwarded traffic and no external volume source is named: ranking by path gain, CPU path not budgeted")
	}
	a.defaults(l)
	a.preChecks(l)
	a.thresholds(l)
	return a
}

func (a *Assessment) version(raw string) {
	v, ok := parseVersion(raw)
	if !ok {
		a.MaxRun = min(a.MaxRun, offload.Report)
		a.add(CodeVersionUnknown, Freeze, offload.FreezeKnownBad, "", "RouterOS version %q cannot be read: report only", raw)
		return
	}
	r, bad := ruleFor(v)
	if !bad {
		return
	}
	a.MaxRun = min(a.MaxRun, r.level)
	if r.level < offload.DryRun {
		a.add(r.code, Freeze, offload.FreezeKnownBad, "", "RouterOS %s is %s (%s): %s", raw, r.label, r.level, r.reason)
		return
	}
	a.add(r.code, Warn, "", "", "RouterOS %s is %s: %s", raw, r.label, r.reason)
}

// defaults enforces the out-of-hardware default policy. A default that is
// in hardware captured suppressed more-specifics in a field report (G1).
func (a *Assessment) defaults(l routeros.L3HW) {
	for _, d := range l.DefaultRoutes {
		switch {
		case d.HFlag:
			a.add(CodeDefaultInHW, Alarm, offload.FreezeDefaultPolicy, "",
				"%s default route via %s has the H flag (eligible for hardware): it must carry suppress-hw-offload=yes", d.Family, d.Gateway)
		case !d.SuppressHWOffload:
			a.add(CodeDefaultEligible, Freeze, offload.FreezeDefaultPolicy, "",
				"%s default route via %s does not carry suppress-hw-offload=yes", d.Family, d.Gateway)
		}
	}
}

func (a *Assessment) preChecks(l routeros.L3HW) {
	fail := func(code, format string, args ...any) {
		a.add(code, Freeze, offload.FreezePreCheck, "", format, args...)
	}
	if l.VRFs > 0 {
		fail(CheckVRF, "%d VRF(s): only the main table is offloaded", l.VRFs)
	}
	if l.RoutingRules > 0 {
		fail(CheckRoutingRules, "%d routing rule(s): only the main table is offloaded", l.RoutingRules)
	}
	if l.MarkRoutingRules > 0 {
		fail(CheckMangleMarks, "%d mark-routing mangle rule(s): marked traffic leaves the main table", l.MarkRoutingRules)
	}
	if bypass := l.ForwardFilterRules + l.NATRules + l.MangleRules - l.MarkRoutingRules; bypass > 0 {
		fail(CheckForwardBypass, "%d enabled forward filter, NAT or mangle rule(s): hardware-forwarded traffic bypasses them", bypass)
	}
	if n := countEnabled(l.Bridges); n > 1 {
		fail(CheckMultiBridge, "%d enabled bridges: hardware offload needs one", n)
	}
	a.vlans(l, fail)
	a.ports(l, fail)
	for _, b := range l.Bonds {
		if !b.Disabled && b.Mode != "802.3ad" && b.Mode != "balance-xor" {
			fail(CheckBondMode, "bond %s mode %q: hardware offload needs 802.3ad or balance-xor", b.Name, b.Mode)
		}
	}
	if l.VRRPInterfaces > 0 {
		fail(CheckVRRP, "%d VRRP interface(s): VRRP is not supported with hardware offload", l.VRRPInterfaces)
	}
	// RouterOS 7.25.2 has no state field on the CCR2216. An absent state is
	// not "disabled" while the counters show the chip is offloading.
	switch st := l.Monitor.State; {
	case st == "" && !chipActive(l):
		fail(CheckL3HWDisabled, "L3HW monitor has no state field and shows no hardware routes, hosts or LPM capacity")
	case st != "" && st != "ok":
		fail(CheckL3HWDisabled, "L3HW monitor state is %q", st)
	}
	if adv := l.Advanced; adv != nil && adv.ErrorCode != "" && adv.ErrorCode != "0" {
		fail(CheckL3HWDisabled, "L3HW driver error code %s", adv.ErrorCode)
	}
}

// chipActive reports readings only an enabled chip produces: routes or host
// entries in hardware, or LPM capacity from the advanced monitor.
func chipActive(l routeros.L3HW) bool {
	m := l.Monitor
	return m.IPv4RoutesHW > 0 || m.IPv6RoutesHW > 0 || m.IPv4Hosts > 0 ||
		(l.Advanced != nil && l.Advanced.HasLPM && l.Advanced.LPMCap > 0)
}

func countEnabled(ifs []routeros.Iface) int {
	n := 0
	for _, i := range ifs {
		if !i.Disabled {
			n++
		}
	}
	return n
}

func (a *Assessment) vlans(l routeros.L3HW, fail func(string, string, ...any)) {
	under := map[string]bool{}
	for _, p := range l.Ports {
		under[p.Name] = true
	}
	for _, b := range l.Bonds {
		under[b.Name] = true
	}
	for _, v := range l.VLANs {
		if !v.Disabled && under[v.Parent] {
			fail(CheckVLANOnPort, "VLAN interface %s sits on %s, a port or bond: put it on the bridge", v.Name, v.Parent)
		}
	}
}

// ports finds L3HW off on some switch ports and on for others, and L3HW off
// everywhere. The switch's own CPU port ("switch1-cpu") has no offload flag.
func (a *Assessment) ports(l routeros.L3HW, fail func(string, string, ...any)) {
	var on, off []string
	for _, p := range l.Ports {
		switch {
		case strings.HasSuffix(p.Name, "-cpu"):
		case p.L3HW:
			on = append(on, p.Name)
		default:
			off = append(off, p.Name)
		}
	}
	switch {
	case len(on) > 0 && len(off) > 0:
		fail(CheckAsymmetric, "l3-hw-offloading is on for %s but off for %s: traffic can enter or leave the other way", strings.Join(on, ","), strings.Join(off, ","))
	case len(on) == 0 && len(off) > 0:
		fail(CheckL3HWDisabled, "l3-hw-offloading is off on every switch port")
	}
}

// thresholds applies the SHWP and next-hop rules. A shortest hardware
// prefix above 0 means the chip already dropped short prefixes to the CPU.
func (a *Assessment) thresholds(l routeros.L3HW) {
	m := l.Monitor
	if m.IPv4ShortestHWPrefix > 0 {
		a.add(CodeSHWP, Freeze, offload.FreezePreCheck, "", "shortest hardware prefix is /%d: the table is partly on the CPU", m.IPv4ShortestHWPrefix)
	}
	a.routeIndexDelay(l.Tuning)
	switch {
	case m.NexthopExhausted():
		a.add(CodeNexthopFull, Freeze, offload.FreezePreCheck, offload.NextHops, "next hops %d of %d", m.NexthopUsage, m.NexthopCap)
	case m.NexthopCap > 0 && float64(m.NexthopUsage) >= nexthopWarn*float64(m.NexthopCap):
		a.add(CodeNexthopWarn, Warn, "", "", "next hops %d of %d", m.NexthopUsage, m.NexthopCap)
	}
}

// routeIndexDelay freezes when the router re-indexes slower than the
// profile's settle timing assumes, or when the setting cannot be read: a
// reading would be trusted before RouterOS finished. Advanced settings that
// were not read (nil or empty) are reported by the reader, not here.
func (a *Assessment) routeIndexDelay(t *routeros.Tuning) {
	if t == nil || t.RouteIndexDelayMax == "" {
		return
	}
	d, err := time.ParseDuration(t.RouteIndexDelayMax)
	switch {
	case err != nil || d < 0:
		a.add(CodeRouteIndexDelay, Freeze, offload.FreezePreCheck, "", "route-index-delay-max %q cannot be read", t.RouteIndexDelayMax)
	case d > routeIndexSec*time.Second:
		a.add(CodeRouteIndexDelay, Freeze, offload.FreezePreCheck, "", "route-index-delay-max is %s: the profile settles for %d s", t.RouteIndexDelayMax, routeIndexSec)
	}
}

// Gate merges an assessment into a budget result. A frozen assessment
// leaves nothing to install or shed, as a budget freeze does.
func Gate(res offload.Result, a Assessment) offload.Result {
	if len(a.Freezes) == 0 {
		return res
	}
	return offload.Result{Freezes: append(append([]offload.Freeze(nil), res.Freezes...), a.Freezes...)}
}

// DefaultsChanged reports whether the default routes differ between two
// readings: a gateway, distance, local-pref, activity or suppression change,
// or a route added or removed. The evaluator then freezes installs and sheds
// as settling until a reading is taken after the profile's timing.
func DefaultsChanged(prev, cur routeros.L3HW) bool {
	// The key holds every compared field so equal sets sort the same way.
	order := func(a, b routeros.DefaultRoute) int {
		return strings.Compare(fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", b))
	}
	p := slices.SortedFunc(slices.Values(prev.DefaultRoutes), order)
	c := slices.SortedFunc(slices.Values(cur.DefaultRoutes), order)
	return !slices.Equal(p, c)
}
