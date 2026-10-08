package httpapi

import (
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Input is a point-in-time read of controller state. Routes must be the
// learned path for prefixes already in Results, Decisions, or Improvements.
// Assemble does not walk the RIB, so a full table is never exported.
type Input struct {
	Version string
	Mode    string
	Started bool
	At      time.Time

	Providers []config.Provider
	Status    []probe.ProviderStatus
	Results   []probe.Result

	Decisions    []policy.Decision
	DecidedAt    time.Time
	Improvements []policy.Improvement

	BGPConfigured bool
	RIBReady      bool
	RIBPrefixes   int // prefixes in the learned view
	Peers         []rib.PeerState
	Routes        map[netip.Prefix]rib.Route
	// Paths are every learned path for those same prefixes, including
	// inactive add-path and BMP paths. Assemble does not walk the RIB.
	Paths map[netip.Prefix][]rib.Route

	// Telemetry is interface usage. It is not a routing decision.
	Telemetry []plugin.Usage

	// Exchanges are Internet exchange statistics (#27), already built.
	Exchanges []exchange.Stats
}

// Snapshot is the read-only document the HTTP handlers serve.
type Snapshot struct {
	Version       string
	Mode          string
	Started       bool
	At            time.Time
	DecidedAt     time.Time
	BGPConfigured bool
	RIBReady      bool
	RIBPrefixes   int

	Providers    []Provider
	Probes       []Probe
	Prefixes     []Prefix
	Decisions    []Decision
	Improvements []Improvement
	Peers        []Peer
	Telemetry    []Telemetry
	Exchanges    []exchange.Stats
	// ASNMap groups measured prefixes by origin ASN and provider site.
	// It is display only and is not a routing decision.
	ASNMap []ASNNode
}

// Provider is one configured transit plus its probe-source health.
type Provider struct {
	Name       string `json:"name"`
	Source     string `json:"source,omitempty"`
	NextHop    string `json:"next_hop,omitempty"`
	Exclude    bool   `json:"exclude"`
	Group      string `json:"group,omitempty"`
	Precedence int    `json:"precedence,omitempty"`
	CCDisable  bool   `json:"cc_disable,omitempty"`
	// Domain is the provider's routing domain (#30), when configured.
	Domain string    `json:"domain,omitempty"`
	Up     bool      `json:"up"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since,omitempty"`
}

// Probe is the latest measurement of one provider toward one prefix.
type Probe struct {
	Provider string `json:"provider"`
	Prefix   string `json:"prefix"`
	Target   string `json:"target,omitempty"`
	// Targets is every address probed for this row. Target is the one
	// that defined the score. Empty when a single unnamed measurement
	// did not record the set.
	Targets  []string  `json:"targets,omitempty"`
	Prober   string    `json:"prober,omitempty"`
	OK       bool      `json:"ok"`
	LossPct  float64   `json:"loss_pct"`
	RTTMinMs float64   `json:"rtt_min_ms"`
	RTTAvgMs float64   `json:"rtt_avg_ms"`
	RTTMaxMs float64   `json:"rtt_max_ms"`
	JitterMs float64   `json:"jitter_ms"`
	Sent     int       `json:"sent"`
	Received int       `json:"received"`
	Error    string    `json:"error,omitempty"`
	Time     time.Time `json:"time,omitempty"`
}

// Prefix joins probe rows with the latest decision and, when the prefix
// was learned, the RIB exit.
type Prefix struct {
	Prefix      string  `json:"prefix"`
	Native      string  `json:"native,omitempty"`
	Current     string  `json:"current,omitempty"`
	Recommended string  `json:"recommended,omitempty"`
	Action      string  `json:"action,omitempty"`
	Reason      string  `json:"reason,omitempty"`
	InRIB       bool    `json:"in_rib"`
	NextHop     string  `json:"next_hop,omitempty"`
	RIBProvider string  `json:"rib_provider,omitempty"`
	Neighbor    string  `json:"neighbor,omitempty"`
	Probes      []Probe `json:"probes"`
	// Paths are the learned paths for this prefix, including inactive
	// add-path and BMP paths. MED on a path is display only.
	Paths []LearnedPath `json:"paths,omitempty"`
}

// LearnedPath is one path the edge advertised for a measured prefix.
// Selected is the path the RIB view published. The others are inactive
// (add-path or BMP). MED is not an input to the exit.
type LearnedPath struct {
	Provider string   `json:"provider,omitempty"`
	NextHop  string   `json:"next_hop,omitempty"`
	ASPath   []uint32 `json:"as_path,omitempty"`
	Neighbor string   `json:"neighbor,omitempty"`
	Source   string   `json:"source,omitempty"`
	Router   string   `json:"router,omitempty"`
	LocRIB   bool     `json:"loc_rib,omitempty"`
	PathID   uint32   `json:"path_id,omitempty"`
	Selected bool     `json:"selected,omitempty"`
	MED      *uint32  `json:"med,omitempty"`
	MEDFrom  string   `json:"med_from,omitempty"`
	// Via is route_server, bilateral, or unknown (#146). Display only.
	Via string `json:"via,omitempty"`
}

// ASNNode is one origin ASN on the map of measured prefixes.
type ASNNode struct {
	ASN   uint32    `json:"asn"`
	Sites []ASNSite `json:"sites"`
}

// ASNSite is one provider site (name and next hop) a measured prefix
// was learned through. Partial is set when another site of the same
// provider carries a measured prefix this site does not: a full table
// next to a partial route-server table.
type ASNSite struct {
	Provider string   `json:"provider,omitempty"`
	NextHop  string   `json:"next_hop,omitempty"`
	Prefixes []string `json:"prefixes"`
	Partial  bool     `json:"partial,omitempty"`
}

// Candidate is one provider's score toward a prefix.
type Candidate struct {
	Provider string  `json:"provider"`
	Score    float64 `json:"score"`
	LossPct  float64 `json:"loss_pct"`
	RTTAvgMs float64 `json:"rtt_avg_ms"`
	JitterMs float64 `json:"jitter_ms"`
	Usable   bool    `json:"usable"`
	Why      string  `json:"why,omitempty"`
}

// Decision is the latest evaluation of one prefix.
type Decision struct {
	Prefix      string `json:"prefix"`
	Native      string `json:"native,omitempty"`
	Current     string `json:"current,omitempty"`
	Recommended string `json:"recommended,omitempty"`
	Action      string `json:"action"`
	Cause       string `json:"cause,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Policy      string `json:"policy,omitempty"`
	// Weight is the improvement weight that ordered this move for the
	// max_improvements cap (#34); zero when weights are off.
	Weight     float64     `json:"weight,omitempty"`
	Candidates []Candidate `json:"candidates"`
}

// Improvement is an active steer (recommended in observe and suggest,
// announced only in inject).
type Improvement struct {
	Prefix   string    `json:"prefix"`
	Provider string    `json:"provider"`
	Native   string    `json:"native,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Cause    string    `json:"cause,omitempty"`
	// CostDelta is the native cost per Mbps minus the steered provider's;
	// EstSavings is that times the prefix volume. Estimates for reports.
	CostDelta  float64 `json:"cost_delta,omitempty"`
	EstSavings float64 `json:"est_savings,omitempty"`
}

// Telemetry is one provider's interface usage for the open billing period.
// Rates are decimal megabits per second. usage_mbps is omitted when the
// percentile mode keeps inbound and outbound apart, and when no sample
// has been stored yet.
type Telemetry struct {
	Provider    string     `json:"provider"`
	Host        string     `json:"host,omitempty"`
	Interface   string     `json:"interface,omitempty"`
	IfIndex     int        `json:"if_index,omitempty"`
	CommitMbps  float64    `json:"commit_mbps"`
	BillingDay  int        `json:"billing_day"`
	Percentile  string     `json:"percentile"`
	PeriodStart time.Time  `json:"period_start"`
	PeriodEnd   time.Time  `json:"period_end"`
	Samples     int        `json:"samples"`
	InMbps      float64    `json:"in_mbps"`
	OutMbps     float64    `json:"out_mbps"`
	InMbps95    float64    `json:"in_mbps_95"`
	OutMbps95   float64    `json:"out_mbps_95"`
	UsageMbps   *float64   `json:"usage_mbps,omitempty"`
	Updated     *time.Time `json:"updated,omitempty"`
	Polled      *time.Time `json:"polled,omitempty"`
	Error       string     `json:"error,omitempty"`
}

// Peer is one iBGP session.
type Peer struct {
	Address     string    `json:"address"`
	Description string    `json:"description,omitempty"`
	State       string    `json:"state"`
	Established bool      `json:"established"`
	Since       time.Time `json:"since,omitempty"`
	// AddPath: the router agreed to send additional paths (#26).
	AddPath bool `json:"add_path,omitempty"`
}

// Ready reports whether the process should receive traffic-steering work.
// BGP that is not configured does not block readiness. BGP that is
// configured does, until at least one session is established.
func (s Snapshot) Ready() bool {
	if !s.Started {
		return false
	}
	if s.BGPConfigured && !s.RIBReady {
		return false
	}
	return true
}

// Assemble builds a Snapshot. Nil slices in the result are replaced with
// empty slices so JSON encodes [] rather than null.
func Assemble(in Input) Snapshot {
	if in.At.IsZero() {
		in.At = time.Now().UTC()
	}
	snap := Snapshot{
		Version:       in.Version,
		Mode:          in.Mode,
		Started:       in.Started,
		At:            in.At.UTC(),
		DecidedAt:     in.DecidedAt,
		BGPConfigured: in.BGPConfigured,
		RIBReady:      in.RIBReady,
		RIBPrefixes:   in.RIBPrefixes,
		Providers:     assembleProviders(in),
		Probes:        assembleProbes(in.Results),
		Prefixes:      assemblePrefixes(in),
		Decisions:     assembleDecisions(in.Decisions),
		Improvements:  assembleImprovements(in.Improvements),
		Peers:         assemblePeers(in.Peers),
		Telemetry:     assembleTelemetry(in.Telemetry),
		Exchanges:     in.Exchanges,
	}
	snap.ASNMap = assembleASNMap(snap.Prefixes)
	snap.zeroNil()
	return snap
}

func (s *Snapshot) zeroNil() {
	s.Providers = nz(s.Providers)
	s.Probes = nz(s.Probes)
	s.Prefixes = nz(s.Prefixes)
	s.Decisions = nz(s.Decisions)
	s.Improvements = nz(s.Improvements)
	s.Peers = nz(s.Peers)
	s.Telemetry = nz(s.Telemetry)
	s.Exchanges = nz(s.Exchanges)
	for i := range s.Decisions {
		s.Decisions[i].Candidates = nz(s.Decisions[i].Candidates)
	}
	for i := range s.Prefixes {
		s.Prefixes[i].Probes = nz(s.Prefixes[i].Probes)
		s.Prefixes[i].Paths = nz(s.Prefixes[i].Paths)
	}
	s.ASNMap = nz(s.ASNMap)
	for i := range s.ASNMap {
		s.ASNMap[i].Sites = nz(s.ASNMap[i].Sites)
		for j := range s.ASNMap[i].Sites {
			s.ASNMap[i].Sites[j].Prefixes = nz(s.ASNMap[i].Sites[j].Prefixes)
		}
	}
}

func assembleProviders(in Input) []Provider {
	status := map[string]probe.ProviderStatus{}
	for _, st := range in.Status {
		status[st.Name] = st
	}
	seen := map[string]bool{}
	var out []Provider
	add := func(p Provider) {
		if p.Name == "" || seen[p.Name] {
			return
		}
		seen[p.Name] = true
		out = append(out, p)
	}
	for _, p := range in.Providers {
		row := Provider{
			Name: p.Name, Source: p.SourceIP, NextHop: p.NextHop, Exclude: p.Exclude,
			Group: p.Group, Precedence: p.Precedence, CCDisable: p.CCDisable, Domain: p.Domain,
		}
		if st, ok := status[p.Name]; ok {
			row.Up, row.Reason, row.Since = st.Up, st.Reason, st.Since
		} else if p.Domain != "" {
			// Not probed here: the peer in that domain measures it (#30).
			row.Reason = "measured by the peer in domain " + p.Domain + " (see /api/federation)"
		} else if !in.Started {
			row.Reason = "starting"
		} else {
			row.Reason = "unknown"
		}
		add(row)
	}
	var extra []string
	for name := range status {
		if !seen[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		st := status[name]
		row := Provider{Name: name, Up: st.Up, Reason: st.Reason, Since: st.Since}
		if st.Source.IsValid() {
			row.Source = st.Source.String()
		}
		add(row)
	}
	return out
}

func assembleProbes(results []probe.Result) []Probe {
	out := make([]Probe, 0, len(results))
	for _, r := range results {
		if !r.Prefix.IsValid() {
			continue
		}
		out = append(out, probeFrom(r))
	}
	sort.Slice(out, func(i, j int) bool {
		if c := lessPrefix(out[i].Prefix, out[j].Prefix); c != 0 {
			return c < 0
		}
		return out[i].Provider < out[j].Provider
	})
	return out
}

func assembleDecisions(in []policy.Decision) []Decision {
	out := make([]Decision, 0, len(in))
	for _, d := range in {
		if !d.Prefix.IsValid() {
			continue
		}
		row := Decision{
			Prefix:      d.Prefix.String(),
			Native:      d.Native,
			Current:     d.Current,
			Recommended: d.Recommended,
			Action:      d.Action,
			Cause:       d.Cause,
			Reason:      d.Reason,
			Policy:      d.Policy,
			Weight:      d.Weight,
			Candidates:  make([]Candidate, 0, len(d.Candidates)),
		}
		for _, c := range d.Candidates {
			row.Candidates = append(row.Candidates, Candidate{
				Provider: c.Provider,
				Score:    jsonFloat(c.Score),
				LossPct:  jsonFloat(c.LossPct),
				RTTAvgMs: millis(c.RTTAvg),
				JitterMs: millis(c.Jitter),
				Usable:   c.Usable,
				Why:      c.Why,
			})
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return lessPrefix(out[i].Prefix, out[j].Prefix) < 0 })
	return out
}

func assembleImprovements(in []policy.Improvement) []Improvement {
	out := make([]Improvement, 0, len(in))
	for _, im := range in {
		if !im.Prefix.IsValid() {
			continue
		}
		out = append(out, Improvement{
			Prefix:     im.Prefix.String(),
			Provider:   im.Provider,
			Native:     im.Native,
			Since:      im.Since,
			Reason:     im.Reason,
			Cause:      im.Cause,
			CostDelta:  im.CostDelta,
			EstSavings: im.EstSavings,
		})
	}
	sort.Slice(out, func(i, j int) bool { return lessPrefix(out[i].Prefix, out[j].Prefix) < 0 })
	return out
}

func assembleTelemetry(in []plugin.Usage) []Telemetry {
	out := make([]Telemetry, 0, len(in))
	for _, u := range in {
		if u.Provider == "" {
			continue
		}
		row := Telemetry{
			Provider:    u.Provider,
			Host:        u.Host,
			Interface:   u.Interface,
			IfIndex:     u.IfIndex,
			CommitMbps:  jsonFloat(u.CommitMbps),
			BillingDay:  u.BillingDay,
			Percentile:  string(u.Mode),
			PeriodStart: u.PeriodStart.UTC(),
			PeriodEnd:   u.PeriodEnd.UTC(),
			Samples:     u.Samples,
			InMbps:      jsonFloat(u.InMbps),
			OutMbps:     jsonFloat(u.OutMbps),
			InMbps95:    jsonFloat(u.InMbps95),
			OutMbps95:   jsonFloat(u.OutMbps95),
			Error:       u.Error,
		}
		if u.Single && u.Samples > 0 {
			v := jsonFloat(u.UsageMbps)
			row.UsageMbps = &v
		}
		if !u.Updated.IsZero() {
			t := u.Updated.UTC()
			row.Updated = &t
		}
		if !u.Polled.IsZero() {
			t := u.Polled.UTC()
			row.Polled = &t
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].Interface < out[j].Interface
	})
	return out
}

func assemblePeers(in []rib.PeerState) []Peer {
	out := make([]Peer, 0, len(in))
	for _, p := range in {
		row := Peer{Description: p.Description, State: p.State, Established: p.Established, Since: p.Since, AddPath: p.AddPath}
		if p.Address.IsValid() {
			row.Address = p.Address.String()
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out
}

func assemblePrefixes(in Input) []Prefix {
	rows := map[string]*Prefix{}
	var order []string
	add := func(p netip.Prefix) *Prefix {
		if !p.IsValid() {
			return nil
		}
		k := p.String()
		if row, ok := rows[k]; ok {
			return row
		}
		row := &Prefix{Prefix: k, Probes: []Probe{}}
		rows[k] = row
		order = append(order, k)
		return row
	}
	for _, r := range in.Results {
		row := add(r.Prefix)
		if row == nil {
			continue
		}
		row.Probes = append(row.Probes, probeFrom(r))
	}
	for _, d := range in.Decisions {
		row := add(d.Prefix)
		if row == nil {
			continue
		}
		row.Native, row.Current, row.Recommended = d.Native, d.Current, d.Recommended
		row.Action, row.Reason = d.Action, d.Reason
	}
	for _, im := range in.Improvements {
		row := add(im.Prefix)
		if row == nil {
			continue
		}
		if row.Current == "" {
			row.Current = im.Provider
		}
		if row.Native == "" {
			row.Native = im.Native
		}
		if row.Action == "" {
			row.Action = "keep"
		}
		if row.Reason == "" {
			row.Reason = im.Reason
		}
	}
	for k, row := range rows {
		p, err := netip.ParsePrefix(k)
		if err != nil || in.Routes == nil {
			continue
		}
		rt, ok := in.Routes[p]
		if !ok {
			rt, ok = in.Routes[p.Masked()]
		}
		if !ok {
			continue
		}
		row.InRIB = true
		if rt.NextHop.IsValid() {
			row.NextHop = rt.NextHop.String()
		}
		row.RIBProvider = rt.Provider
		if rt.Neighbor.IsValid() {
			row.Neighbor = rt.Neighbor.String()
		}
		if row.Current == "" {
			row.Current = rt.Provider
		}
		if row.Native == "" {
			row.Native = rt.Provider
		}
	}
	for k, row := range rows {
		p, err := netip.ParsePrefix(k)
		if err != nil {
			continue
		}
		paths := in.Paths[p]
		if paths == nil {
			paths = in.Paths[p.Masked()]
		}
		best, have := rib.Route{}, false
		if in.Routes != nil {
			if rt, ok := in.Routes[p]; ok {
				best, have = rt, true
			} else if rt, ok := in.Routes[p.Masked()]; ok {
				best, have = rt, true
			}
		}
		row.Paths = learnedPaths(best, have, paths)
	}
	sort.Slice(order, func(i, j int) bool { return lessPrefix(order[i], order[j]) < 0 })
	out := make([]Prefix, 0, len(order))
	for _, k := range order {
		row := rows[k]
		sort.Slice(row.Probes, func(i, j int) bool { return row.Probes[i].Provider < row.Probes[j].Provider })
		out = append(out, *row)
	}
	return out
}

func probeFrom(r probe.Result) Probe {
	p := Probe{
		Provider: r.Provider,
		Prober:   r.Prober,
		OK:       r.OK(),
		LossPct:  jsonFloat(r.Stats.LossPct),
		RTTMinMs: millis(r.Stats.RTTMin),
		RTTAvgMs: millis(r.Stats.RTTAvg),
		RTTMaxMs: millis(r.Stats.RTTMax),
		JitterMs: millis(r.Stats.Jitter),
		Sent:     r.Stats.Sent,
		Received: r.Stats.Received,
		Error:    r.Err,
		Time:     r.Time,
	}
	if r.Prefix.IsValid() {
		p.Prefix = r.Prefix.String()
	}
	if r.Target.IsValid() {
		p.Target = r.Target.String()
	}
	if len(r.Targets) > 0 {
		p.Targets = make([]string, len(r.Targets))
		for i, a := range r.Targets {
			p.Targets[i] = a.String()
		}
	}
	return p
}

func millis(d time.Duration) float64 {
	return jsonFloat(float64(d) / float64(time.Millisecond))
}

func jsonFloat(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}

// lessPrefix compares canonical prefix text. Invalid text sorts after
// valid prefixes, then lexicographically.
func lessPrefix(a, b string) int {
	pa, ea := netip.ParsePrefix(a)
	pb, eb := netip.ParsePrefix(b)
	switch {
	case ea != nil && eb != nil:
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
		return 0
	case ea != nil:
		return 1
	case eb != nil:
		return -1
	}
	if c := pa.Addr().Compare(pb.Addr()); c != 0 {
		return c
	}
	return pa.Bits() - pb.Bits()
}

func learnedPaths(best rib.Route, have bool, paths []rib.Route) []LearnedPath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]LearnedPath, 0, len(paths))
	for _, rt := range paths {
		lp := LearnedPath{
			Provider: rt.Provider,
			ASPath:   append([]uint32(nil), rt.ASPath...),
			Source:   rt.Source,
			LocRIB:   rt.LocRIB,
			PathID:   rt.PathID,
			MED:      rt.MED,
			MEDFrom:  rt.MEDFrom,
			Via:      rt.Via,
		}
		if rt.NextHop.IsValid() {
			lp.NextHop = rt.NextHop.String()
		}
		if rt.Neighbor.IsValid() {
			lp.Neighbor = rt.Neighbor.String()
		}
		if rt.Router.IsValid() {
			lp.Router = rt.Router.String()
		}
		if have && rt.Source == best.Source && rt.Neighbor == best.Neighbor && rt.PathID == best.PathID &&
			rt.Router == best.Router && rt.LocRIB == best.LocRIB && rt.NextHop == best.NextHop {
			lp.Selected = true
		}
		out = append(out, lp)
	}
	return out
}

// assembleASNMap groups measured prefixes by the last AS on each learned
// path, then by provider site (name and next hop). A site is partial when
// another site of the same provider carries a measured prefix this site
// does not. MED is not read.
func assembleASNMap(prefixes []Prefix) []ASNNode {
	type siteKey struct {
		provider string
		hop      string
	}
	type place struct {
		asn    uint32
		site   siteKey
		prefix string
	}
	var places []place
	siteSets := map[siteKey]map[string]struct{}{}
	for _, row := range prefixes {
		for _, path := range row.Paths {
			var asn uint32
			if n := len(path.ASPath); n > 0 {
				asn = path.ASPath[n-1]
			}
			k := siteKey{provider: path.Provider, hop: path.NextHop}
			places = append(places, place{asn: asn, site: k, prefix: row.Prefix})
			if siteSets[k] == nil {
				siteSets[k] = map[string]struct{}{}
			}
			siteSets[k][row.Prefix] = struct{}{}
		}
	}
	if len(places) == 0 {
		return nil
	}
	union := map[string]map[string]struct{}{}
	for k, set := range siteSets {
		if k.provider == "" {
			continue
		}
		if union[k.provider] == nil {
			union[k.provider] = map[string]struct{}{}
		}
		for p := range set {
			union[k.provider][p] = struct{}{}
		}
	}
	partial := map[siteKey]bool{}
	for k, set := range siteSets {
		u := union[k.provider]
		if k.provider == "" || u == nil {
			continue
		}
		for p := range u {
			if _, ok := set[p]; !ok {
				partial[k] = true
				break
			}
		}
	}
	type bucketKey struct {
		asn  uint32
		site siteKey
	}
	buckets := map[bucketKey]map[string]struct{}{}
	for _, pl := range places {
		bk := bucketKey{asn: pl.asn, site: pl.site}
		if buckets[bk] == nil {
			buckets[bk] = map[string]struct{}{}
		}
		buckets[bk][pl.prefix] = struct{}{}
	}
	byASN := map[uint32][]ASNSite{}
	var asns []uint32
	for bk, set := range buckets {
		prefs := make([]string, 0, len(set))
		for pfx := range set {
			prefs = append(prefs, pfx)
		}
		sort.Slice(prefs, func(i, j int) bool { return lessPrefix(prefs[i], prefs[j]) < 0 })
		if _, ok := byASN[bk.asn]; !ok {
			asns = append(asns, bk.asn)
		}
		byASN[bk.asn] = append(byASN[bk.asn], ASNSite{
			Provider: bk.site.provider,
			NextHop:  bk.site.hop,
			Prefixes: prefs,
			Partial:  partial[bk.site],
		})
	}
	sort.Slice(asns, func(i, j int) bool {
		if asns[i] == 0 {
			return false
		}
		if asns[j] == 0 {
			return true
		}
		return asns[i] < asns[j]
	})
	out := make([]ASNNode, 0, len(asns))
	for _, asn := range asns {
		sites := byASN[asn]
		sort.Slice(sites, func(i, j int) bool {
			if sites[i].Provider != sites[j].Provider {
				return sites[i].Provider < sites[j].Provider
			}
			return sites[i].NextHop < sites[j].NextHop
		})
		out = append(out, ASNNode{ASN: asn, Sites: sites})
	}
	return out
}
