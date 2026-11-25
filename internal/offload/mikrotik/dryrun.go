package mikrotik

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/offload"
	"github.com/GrandArcher/Packeteer/internal/plugins/routercheck/routeros"
)

// Evaluator is the dry run of the profile on one router. It reads a
// snapshot, never the router, and applies nothing: the result is a report.
type Evaluator struct {
	opts    Options
	profile offload.Profile
	recheck time.Duration

	mu      sync.Mutex
	ipv6HW  bool
	budget  *offload.Budget
	planner *offload.Planner
}

// NewEvaluator returns an evaluator polled every recheck.
func NewEvaluator(opts Options, recheck time.Duration) (*Evaluator, error) {
	p, err := Profile(opts, nil)
	if err != nil {
		return nil, err
	}
	e := &Evaluator{opts: opts, profile: p, recheck: recheck}
	if err := e.build(false); err != nil {
		return nil, err
	}
	return e, nil
}

// build makes the budget and planner for the router's ipv6-hw setting. The
// budget remembers the caps it saw, so it is kept while the setting holds.
func (e *Evaluator) build(ipv6HW bool) error {
	b, err := offload.NewBudget(BudgetConfig(e.opts, e.recheck, ipv6HW))
	if err != nil {
		return err
	}
	pl, err := offload.NewPlanner(e.profile, PlannerConfig(e.opts, ipv6HW))
	if err != nil {
		return err
	}
	e.ipv6HW, e.budget, e.planner = ipv6HW, b, pl
	return nil
}

// Input is one dry run.
type Input struct {
	Now      time.Time
	Neighbor string
	// Snap is the latest poll and At when it was read. Nil before the first
	// successful poll; Err is then why.
	Snap *Snapshot
	At   time.Time
	Err  string
	// Wanted are the fixes Decide wants, none of them in hardware yet.
	Wanted []offload.Wanted
	Volume offload.VolumeReport
}

// Evaluate reports what installing the wanted fixes would do on this router.
func (e *Evaluator) Evaluate(in Input) offload.RouterReport {
	e.mu.Lock()
	defer e.mu.Unlock()

	p := e.profile
	rep := offload.RouterReport{
		Neighbor: in.Neighbor, Profile: ID, Status: p.Status,
		Run: offload.DryRun.String(), Level: offload.Refuse.String(),
		Verdict: offload.VerdictUnavailable, VersionVerdict: "unknown",
		Default:  offload.DefaultReport{Policy: p.DefaultPolicy.Kind, Reason: p.DefaultPolicy.Reason},
		Findings: []offload.Finding{}, Freezes: []offload.Freeze{}, Fixes: []offload.Fix{},
		Volume: in.Volume, Error: in.Err,
	}
	snap := Snapshot{}
	ok := in.Snap != nil
	if ok {
		snap = *in.Snap
		rep.ReadAt = &in.At
		rep.Version = snap.L3HW.Version
		if snap.L3HW.Settings.IPv6HW != e.ipv6HW && snap.L3HW.Applicable {
			if err := e.build(snap.L3HW.Settings.IPv6HW); err != nil {
				rep.Error = err.Error()
				rep.Dimensions = []offload.DimensionReport{}
				rep.Fixes = offload.BuildFixes(in.Wanted, nil, offload.Plan{}, "the router profile could not be rebuilt")
				return rep
			}
		}
	}
	reader := newReader(e.opts, func() (Snapshot, bool) { return snap, ok })
	samples := offload.Collect(context.Background(), reader, dimensions(e.opts), in.At)
	res := e.budget.Evaluate(in.Now, offload.Identity{Profile: ID, Version: snap.L3HW.Version}, samples)

	a := Assessment{MaxRun: offload.Refuse}
	if ok {
		a = Assess(snap.L3HW, e.opts)
		res = Gate(res, a)
		rep.VersionVerdict = versionVerdict(snap.L3HW.Version)
		rep.Default = defaultReport(p.DefaultPolicy, snap.L3HW)
		rep.Counters = counters(snap.L3HW)
		for _, f := range a.Findings {
			rep.Findings = append(rep.Findings, offload.Finding{Code: f.Code, Severity: string(f.Severity), Detail: f.Detail})
		}
	}
	rep.Dimensions = offload.Dimensions(e.budget, in.Now, dimensions(e.opts), samples, res.Freezes)
	rep.Freezes = append(rep.Freezes, res.Freezes...)
	rep.Level = min(offload.DryRun, a.MaxRun).String()
	rep.Verdict = verdict(ok, snap.L3HW, res)

	software := map[netip.Prefix]string{}
	var cands []offload.Candidate
	var hosts []netip.Prefix
	for _, w := range in.Wanted {
		switch {
		case w.Prefix.Addr().Is6() && !e.ipv6HW:
			software[w.Prefix] = "IPv6 is not offloaded: ipv6-hw is off, so the CPU carries it"
		case isHostEntry(w.Prefix):
			hosts = append(hosts, w.Prefix)
		default:
			cands = append(cands, w.Candidate)
		}
	}
	blocked := ""
	var plan offload.Plan
	switch {
	case !ok:
		blocked = "no reading of the router yet"
	case a.MaxRun < offload.DryRun:
		blocked = "run level " + a.MaxRun.String() + ": nothing is planned on this router"
	default:
		var err error
		plan, err = e.planner.Plan(offload.Input{Now: in.Now, Candidates: cands, Budget: res})
		if err != nil {
			blocked, rep.Error = "the plan failed", err.Error()
		}
	}
	// A host entry has no published cap, so it takes no budget; it is still
	// held back by whatever freezes the plan.
	for _, h := range hosts {
		d := offload.Decision{Prefix: h, Action: offload.Install, Reason: hostReason}
		if len(plan.Freezes) > 0 {
			d.Action, d.Reason = offload.Withhold, "frozen"
		}
		plan.Decisions = append(plan.Decisions, d)
	}
	rep.Fixes = offload.BuildFixes(in.Wanted, software, plan, blocked)
	return rep
}

// hostReason is the fix reason for an IPv4 /32: RouterOS 7.25.2 on the
// CCR2216 installs it in ipv4-hosts and leaves lpm-usage unchanged.
const hostReason = "IPv4 /32 goes to the host table (ipv4-hosts), not LPM; no host cap is published, so it is not budgeted"

// isHostEntry reports whether the chip keeps p in the host table.
func isHostEntry(p netip.Prefix) bool {
	return p.Addr().Is4() && p.Bits() == 32
}

// verdict classifies the router: next hops used up first, then a table the
// chip already cut short, then any other freeze.
func verdict(read bool, l routeros.L3HW, res offload.Result) string {
	switch {
	case !read || !l.Applicable:
		return offload.VerdictUnavailable
	case l.Monitor.NexthopExhausted():
		return offload.VerdictNexthopExhausted
	case l.Monitor.IPv4ShortestHWPrefix > 0:
		return offload.VerdictPartial
	case res.Frozen():
		return offload.VerdictFrozen
	}
	return offload.VerdictFits
}

func versionVerdict(raw string) string {
	v, ok := parseVersion(raw)
	if !ok {
		return "unknown"
	}
	r, bad := ruleFor(v)
	switch {
	case !bad:
		return "ok"
	case r.level == offload.Refuse:
		return "refused"
	case r.level == offload.Report:
		return "report_only"
	}
	return "warn"
}

// defaultReport says whether every default route read carries
// suppress-hw-offload=yes and has no H flag. With none read, Met is unknown.
func defaultReport(p offload.DefaultPolicy, l routeros.L3HW) offload.DefaultReport {
	d := offload.DefaultReport{Policy: p.Kind, Reason: p.Reason}
	if len(l.DefaultRoutes) == 0 {
		d.Detail = "no default route was read"
		return d
	}
	met := true
	for _, r := range l.DefaultRoutes {
		if r.HFlag || !r.SuppressHWOffload {
			met = false
			d.Detail = r.Family + " default route via " + r.Gateway + " is eligible for hardware"
			break
		}
	}
	d.Met = &met
	return d
}

func counters(l routeros.L3HW) *offload.Counters {
	if !l.Applicable {
		return nil
	}
	m := l.Monitor
	c := &offload.Counters{
		IPv4RoutesHW: m.IPv4RoutesHW, IPv4RoutesCPU: m.IPv4RoutesCPU,
		IPv6RoutesHW: m.IPv6RoutesHW, IPv6RoutesCPU: m.IPv6RoutesCPU,
		ShortestHWPrefix: m.IPv4ShortestHWPrefix, Hosts: m.IPv4Hosts,
	}
	if t := l.Tuning; t != nil {
		c.RouteQueueLimitHigh, c.RouteQueueLimitLow = t.RouteQueueLimitHigh, t.RouteQueueLimitLow
	}
	return c
}
