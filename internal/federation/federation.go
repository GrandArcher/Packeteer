// Package federation turns peer snapshots from other POPs (routing
// domains, #30) into decision inputs, builds the snapshot this instance
// publishes, and reports the central view. It is pure: it never touches
// the network and never announces. What it adds to a decision is subject
// to the same allowlist, learned RIB, cap, hold time, and withdraw rules
// as any other path.
//
// A provider in another domain is measured by the peer in that domain.
// Its path to a prefix is the peer's measurement plus the configured
// inter-DC RTT. It is usable only while the peer is fresh, its RIB is
// ready, it reports the provider up, and its own traffic for that exact
// prefix leaves through that provider. When the peer goes stale the path
// disappears and an improvement onto it is retired and withdrawn: the
// instance behaves as if it ran standalone.
package federation

import (
	"math"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// ProberName marks results that came from a peer.
const ProberName = "federation"

// Config is the multi-POP view of the instance config.
type Config struct {
	Instance string
	Domain   string
	// InterDCRTT is the RTT from this domain to each other domain.
	InterDCRTT map[string]time.Duration
	// Remote maps each provider in another domain to its domain.
	Remote map[string]string
	// Local lists providers in this domain.
	Local         []string
	GlobalCommits []GlobalCommit
}

// GlobalCommit is one commit shared by providers in several domains.
type GlobalCommit struct {
	Name       string
	CommitMbps float64
	Providers  []string
}

// fresh returns, per domain, the first fresh peer (in config order) that
// serves it. A peer that claims this instance's own domain is ignored.
func fresh(cfg Config, peers []plugin.PeerState) map[string]*plugin.InstanceSnapshot {
	out := map[string]*plugin.InstanceSnapshot{}
	for i := range peers {
		p := &peers[i]
		d := p.Snapshot.Domain
		if !p.Fresh || d == "" || d == cfg.Domain {
			continue
		}
		if _, ok := out[d]; !ok {
			out[d] = &p.Snapshot
		}
	}
	return out
}

func ownProvider(s *plugin.InstanceSnapshot, name string) (plugin.FederatedProvider, bool) {
	for _, p := range s.Providers {
		if p.Name == name && p.Domain == s.Domain {
			return p, true
		}
	}
	return plugin.FederatedProvider{}, false
}

// Merge adds, for every prefix this instance probes, the paths that
// fresh peers measured through providers in their domain, with the
// inter-DC RTT added. It sets each remote provider's health, and marks a
// remote provider not routed (policy.Input.NoRoute) for a prefix whose
// peer does not send its own traffic for that exact prefix through it.
// Call it after in.Results, in.ProviderUp, and in.Native are filled.
func Merge(in *policy.Input, cfg Config, peers []plugin.PeerState) {
	if len(cfg.Remote) == 0 {
		return
	}
	if in.ProviderUp == nil {
		in.ProviderUp = map[string]bool{}
	}
	probed := map[netip.Prefix]bool{}
	for _, r := range in.Results {
		probed[r.Prefix] = true
	}
	byDomain := fresh(cfg, peers)
	local := map[string]bool{}
	for _, n := range cfg.Local {
		local[n] = true
	}
	names := make([]string, 0, len(cfg.Remote))
	for n := range cfg.Remote {
		names = append(names, n)
	}
	sort.Strings(names)
	var added []probe.Result
	for _, name := range names {
		domain := cfg.Remote[name]
		snap := byDomain[domain]
		up := false
		if snap != nil && snap.RIBReady {
			if fp, ok := ownProvider(snap, name); ok && fp.Up {
				up = true
			}
		}
		in.ProviderUp[name] = up
		routes := map[netip.Prefix]plugin.FederatedRoute{}
		if snap != nil {
			for _, rt := range snap.Routes {
				routes[rt.Prefix] = rt
			}
			for _, p := range snap.Paths {
				if p.Provider != name || !probed[p.Prefix] {
					continue
				}
				rtt := p.RTT + cfg.InterDCRTT[domain]
				recv := int(math.Round(float64(p.Sent) * (100 - p.LossPct) / 100))
				added = append(added, probe.Result{
					Provider: name, Prefix: p.Prefix, Prober: ProberName + ":" + snap.Instance,
					Stats: probe.Stats{Sent: p.Sent, Received: recv, LossPct: p.LossPct,
						RTTMin: rtt, RTTAvg: rtt, RTTMax: rtt, Jitter: p.Jitter},
					Time: p.Time,
				})
			}
		}
		for p := range probed {
			if routed(cfg, snap, routes[p], name, local) {
				continue
			}
			if in.NoRoute == nil {
				in.NoRoute = map[netip.Prefix]map[string]bool{}
			}
			if in.NoRoute[p] == nil {
				in.NoRoute[p] = map[string]bool{}
			}
			in.NoRoute[p][name] = true
		}
	}
	in.Results = append(in.Results, added...)
}

// routed reports whether the peer's traffic for the prefix leaves through
// provider name, so traffic this POP sends it over the backbone leaves
// there too and cannot loop. A peer whose exit is a provider in yet
// another domain is not a destination. When two POPs steered the same
// prefix at each other in the same interval, the POP whose domain sorts
// first keeps its steer and the other retires.
func routed(cfg Config, snap *plugin.InstanceSnapshot, rt plugin.FederatedRoute, name string, local map[string]bool) bool {
	if snap == nil || rt.Exit == "" {
		return false
	}
	if rt.Exit == name {
		return true
	}
	return local[rt.Exit] && rt.Native == name && cfg.Domain < snap.Domain
}

// CommitMember is one provider's share of a global commit.
type CommitMember struct {
	Provider string  `json:"provider"`
	Domain   string  `json:"domain"`
	Mbps     float64 `json:"usage_mbps"`
	Have     bool    `json:"have"`
	// CommitMbps is the commit this instance's commit control compares
	// the provider with: the global commit less every other member's
	// usage, and never more than the provider's own commit. Zero for a
	// member in another domain.
	CommitMbps float64 `json:"effective_commit_mbps,omitempty"`
}

// CommitStatus is one global commit as this instance sees it. Complete
// is false when a member's usage is missing or its peer is stale; commit
// control then uses each local provider's own commit, as standalone.
type CommitStatus struct {
	Name       string         `json:"name"`
	CommitMbps float64        `json:"commit_mbps"`
	TotalMbps  float64        `json:"total_mbps"`
	Complete   bool           `json:"complete"`
	Over       bool           `json:"over"`
	Members    []CommitMember `json:"members"`
}

// minCommit keeps an exhausted global commit billable: a zero commit
// would read as "no telemetry" and turn commit control off.
const minCommit = 0.001

// ApplyGlobalCommit adds fresh peers' usage rows for remote providers to
// usage, and lowers each local global-commit member's commit to what the
// other members leave of the global commit. It returns the new usage and
// each commit's status. A commit with a missing member is left alone.
func ApplyGlobalCommit(usage []plugin.Usage, cfg Config, peers []plugin.PeerState) ([]plugin.Usage, []CommitStatus) {
	byDomain := fresh(cfg, peers)
	out := slices.Clone(usage)
	idx := map[string]int{}
	for i, u := range out {
		if _, dup := idx[u.Provider]; !dup {
			idx[u.Provider] = i
		}
	}
	remote := func(name string) (plugin.Usage, bool) {
		snap := byDomain[cfg.Remote[name]]
		if snap == nil {
			return plugin.Usage{}, false
		}
		fp, ok := ownProvider(snap, name)
		if !ok || fp.Usage == nil {
			return plugin.Usage{}, false
		}
		return *fp.Usage, true
	}
	names := make([]string, 0, len(cfg.Remote))
	for n := range cfg.Remote {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, have := idx[n]; have {
			continue
		}
		if u, ok := remote(n); ok {
			u.Provider = n
			idx[n] = len(out)
			out = append(out, u)
		}
	}
	var status []CommitStatus
	for _, g := range cfg.GlobalCommits {
		st := CommitStatus{Name: g.Name, CommitMbps: g.CommitMbps, Complete: true}
		for _, name := range g.Providers {
			m := CommitMember{Provider: name, Domain: cfg.Domain}
			if d, ok := cfg.Remote[name]; ok {
				m.Domain = d
			}
			if i, ok := idx[name]; ok {
				if mbps, ok := out[i].BillableMbps(); ok {
					m.Mbps, m.Have = mbps, true
				}
			}
			if !m.Have {
				st.Complete = false
			}
			st.TotalMbps += m.Mbps
			st.Members = append(st.Members, m)
		}
		st.Over = st.Complete && st.TotalMbps > g.CommitMbps
		if st.Complete {
			for j, m := range st.Members {
				if _, isRemote := cfg.Remote[m.Provider]; isRemote {
					continue
				}
				i := idx[m.Provider]
				eff := g.CommitMbps - (st.TotalMbps - m.Mbps)
				if own := out[i].CommitMbps; own > 0 && own < eff {
					eff = own
				}
				if eff < minCommit {
					eff = minCommit
				}
				out[i].CommitMbps = eff
				st.Members[j].CommitMbps = eff
			}
		}
		status = append(status, st)
	}
	return out, status
}

// SnapshotInput is what the controller knows after one evaluation.
type SnapshotInput struct {
	Version         string
	Mode            string
	Now             time.Time
	RIBReady        bool
	MaxImprovements int
	MaxResultAge    time.Duration
	Input           policy.Input
	Improvements    []policy.Improvement
	Usage           []plugin.Usage
}

// Snapshot builds what this instance publishes: fresh measurements and
// health of its own providers only (never a peer's path it merged), how
// its traffic for each learned probed prefix leaves, and its improvements.
// Only in inject mode does an improvement change a prefix's exit.
func Snapshot(cfg Config, in SnapshotInput) plugin.InstanceSnapshot {
	s := plugin.InstanceSnapshot{
		Instance: cfg.Instance, Domain: cfg.Domain, Version: in.Version, Mode: in.Mode,
		Time: in.Now, RIBReady: in.RIBReady, MaxImprovements: in.MaxImprovements,
		Providers: []plugin.FederatedProvider{}, Paths: []plugin.FederatedPath{},
		Routes: []plugin.FederatedRoute{}, Improvements: []plugin.FederatedImprovement{},
	}
	local := map[string]bool{}
	usage := map[string]plugin.Usage{}
	for _, u := range in.Usage {
		if _, dup := usage[u.Provider]; !dup {
			usage[u.Provider] = u
		}
	}
	for _, n := range cfg.Local {
		local[n] = true
		fp := plugin.FederatedProvider{Name: n, Domain: cfg.Domain, Up: in.Input.ProviderUp[n]}
		if u, ok := usage[n]; ok {
			fp.Usage = &u
		}
		s.Providers = append(s.Providers, fp)
	}
	probed := map[netip.Prefix]bool{}
	for _, r := range in.Input.Results {
		if !local[r.Provider] || !r.OK() || r.Stats.Sent == 0 {
			continue
		}
		probed[r.Prefix] = true
		if in.MaxResultAge > 0 && in.Now.Sub(r.Time) > in.MaxResultAge {
			continue
		}
		s.Paths = append(s.Paths, plugin.FederatedPath{
			Prefix: r.Prefix, Provider: r.Provider, Sent: r.Stats.Sent, LossPct: r.Stats.LossPct,
			RTT: r.Stats.RTTAvg, Jitter: r.Stats.Jitter, Time: r.Time,
		})
	}
	steered := map[netip.Prefix]policy.Improvement{}
	for _, imp := range in.Improvements {
		s.Improvements = append(s.Improvements, plugin.FederatedImprovement{
			Prefix: imp.Prefix, Provider: imp.Provider, Native: imp.Native, Cause: imp.Cause, Since: imp.Since,
		})
		if in.Mode == "inject" {
			steered[imp.Prefix] = imp
		}
	}
	if in.RIBReady {
		for p := range probed {
			native := in.Input.Native[p]
			exit := native
			if imp, ok := steered[p]; ok {
				exit = imp.Provider
				if native == "" {
					native = imp.Native
				}
			}
			if exit == "" {
				continue
			}
			s.Routes = append(s.Routes, plugin.FederatedRoute{Prefix: p, Native: native, Exit: exit})
		}
	}
	sort.Slice(s.Paths, func(i, j int) bool {
		if s.Paths[i].Prefix != s.Paths[j].Prefix {
			return less(s.Paths[i].Prefix, s.Paths[j].Prefix)
		}
		return s.Paths[i].Provider < s.Paths[j].Provider
	})
	sort.Slice(s.Routes, func(i, j int) bool { return less(s.Routes[i].Prefix, s.Routes[j].Prefix) })
	return s
}

func less(a, b netip.Prefix) bool {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// PeerView is one peer in the central view.
type PeerView struct {
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	Fresh    bool      `json:"fresh"`
	LastSeen time.Time `json:"last_seen,omitzero"`
	Error    string    `json:"error,omitempty"`
	// InterDCRTTMs is the configured RTT to the peer's domain.
	InterDCRTTMs float64                  `json:"inter_dc_rtt_ms"`
	Snapshot     *plugin.InstanceSnapshot `json:"snapshot,omitempty"`
}

// Status is the central view of every instance: this one and its peers.
type Status struct {
	Enabled      bool                     `json:"enabled"`
	Instance     string                   `json:"instance,omitempty"`
	Domain       string                   `json:"domain,omitempty"`
	Local        *plugin.InstanceSnapshot `json:"local,omitempty"`
	Peers        []PeerView               `json:"peers"`
	GlobalCommit []CommitStatus           `json:"global_commit"`
}

// View builds the central view.
func View(cfg Config, local *plugin.InstanceSnapshot, peers []plugin.PeerState, commits []CommitStatus) Status {
	st := Status{Enabled: true, Instance: cfg.Instance, Domain: cfg.Domain, Local: local,
		Peers: []PeerView{}, GlobalCommit: commits}
	if st.GlobalCommit == nil {
		st.GlobalCommit = []CommitStatus{}
	}
	for _, p := range peers {
		v := PeerView{Name: p.Name, URL: p.URL, Fresh: p.Fresh, LastSeen: p.LastSeen, Error: p.Error}
		if !p.LastSeen.IsZero() {
			snap := p.Snapshot
			v.Snapshot = &snap
			v.InterDCRTTMs = float64(cfg.InterDCRTT[snap.Domain]) / float64(time.Millisecond)
		}
		st.Peers = append(st.Peers, v)
	}
	return st
}
