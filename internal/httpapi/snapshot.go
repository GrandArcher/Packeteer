package httpapi

import (
	"math"
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
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
	Peers         []rib.PeerState
	Routes        map[netip.Prefix]rib.Route

	// Telemetry is interface usage. It is not a routing decision.
	Telemetry []plugin.Usage
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

	Providers    []Provider
	Probes       []Probe
	Prefixes     []Prefix
	Decisions    []Decision
	Improvements []Improvement
	Peers        []Peer
	Telemetry    []Telemetry
}

// Provider is one configured transit plus its probe-source health.
type Provider struct {
	Name    string    `json:"name"`
	Source  string    `json:"source,omitempty"`
	NextHop string    `json:"next_hop,omitempty"`
	Exclude bool      `json:"exclude"`
	Up      bool      `json:"up"`
	Reason  string    `json:"reason,omitempty"`
	Since   time.Time `json:"since,omitempty"`
}

// Probe is the latest measurement of one provider toward one prefix.
type Probe struct {
	Provider string    `json:"provider"`
	Prefix   string    `json:"prefix"`
	Target   string    `json:"target,omitempty"`
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
	Prefix      string      `json:"prefix"`
	Native      string      `json:"native,omitempty"`
	Current     string      `json:"current,omitempty"`
	Recommended string      `json:"recommended,omitempty"`
	Action      string      `json:"action"`
	Reason      string      `json:"reason,omitempty"`
	Candidates  []Candidate `json:"candidates"`
}

// Improvement is an active steer (recommended in observe and suggest,
// announced only in inject).
type Improvement struct {
	Prefix   string    `json:"prefix"`
	Provider string    `json:"provider"`
	Native   string    `json:"native,omitempty"`
	Since    time.Time `json:"since,omitempty"`
	Reason   string    `json:"reason,omitempty"`
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
		Providers:     assembleProviders(in),
		Probes:        assembleProbes(in.Results),
		Prefixes:      assemblePrefixes(in),
		Decisions:     assembleDecisions(in.Decisions),
		Improvements:  assembleImprovements(in.Improvements),
		Peers:         assemblePeers(in.Peers),
		Telemetry:     assembleTelemetry(in.Telemetry),
	}
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
	for i := range s.Decisions {
		s.Decisions[i].Candidates = nz(s.Decisions[i].Candidates)
	}
	for i := range s.Prefixes {
		s.Prefixes[i].Probes = nz(s.Prefixes[i].Probes)
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
		row := Provider{Name: p.Name, Source: p.SourceIP, NextHop: p.NextHop, Exclude: p.Exclude}
		if st, ok := status[p.Name]; ok {
			row.Up, row.Reason, row.Since = st.Up, st.Reason, st.Since
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
			Reason:      d.Reason,
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
			Prefix:   im.Prefix.String(),
			Provider: im.Provider,
			Native:   im.Native,
			Since:    im.Since,
			Reason:   im.Reason,
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
		row := Peer{Description: p.Description, State: p.State, Established: p.Established, Since: p.Since}
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
