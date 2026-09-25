package outage

import (
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Sample is one probe measurement. The controller copies it out of the
// probe engine. Failed is a probe error, which counts as degraded even
// when LossPct is zero.
type Sample struct {
	Provider string
	Prefix   netip.Prefix
	LossPct  float64
	RTT      time.Duration
	Failed   bool
	Time     time.Time
}

// Route is one learned prefix. Provider is the native exit when the RIB
// matched a configured next hop. An empty ASPath cannot implicate an ASN.
type Route struct {
	Prefix   netip.Prefix
	ASPath   []uint32
	Provider string
}

// Incident is one detected AS or circuit problem.
type Incident struct {
	Kind      string // IncidentAS or IncidentCircuit
	ASN       uint32
	Provider  string
	Prefixes  []netip.Prefix // degraded prefixes that caused it, sorted
	Providers []string       // providers that saw that degradation, sorted
	Requeued  int            // prefixes returned in Outcome.Targets for this incident
}

// Outcome is the result of one correlation pass.
type Outcome struct {
	Incidents []Incident
	Targets   []plugin.Target
	Truncated bool
}

// Detect correlates samples inside the window with learned AS paths.
//
// A sample is degraded when the probe failed, loss is at least LossPct,
// or (when RTTMs is positive) average RTT is at least that many
// milliseconds. Per provider and prefix, the newest in-window sample wins.
// A zero timestamp is outside the window.
//
// An ASN is sick when at least MinPrefixes degraded prefixes contain it
// and every provider measured for those prefixes is degraded. A prefix
// that is still healthy on another provider does not count: that pattern
// is a circuit. IgnoreASNs are skipped, so an ASN that sits on every path
// is not the failure domain.
//
// A provider is sick when at least MinPrefixes prefixes are degraded on
// it and healthy on another provider, and those prefixes are not already
// explained by a sick ASN. When a prefix was measured on only one
// provider, it counts toward that provider only if no sick ASN explains
// it, so a dead circuit with mixed destinations still fires and a shared
// transit ASN is not reported twice.
//
// Targets are probe prefixes only. AS incidents include every learned
// prefix whose path contains the ASN, degraded ones first, up to
// MaxTargets. Circuit incidents include the prefixes that counted, then
// other prefixes sampled on that provider, then learned prefixes whose
// native provider is that circuit. A default route is never a target.
// Detect does not announce.
func Detect(now time.Time, samples []Sample, routes []Route, cfg Config) Outcome {
	cfg = cfg.normalized()
	ignore := map[uint32]struct{}{}
	for _, asn := range cfg.IgnoreASNs {
		if asn != 0 {
			ignore[asn] = struct{}{}
		}
	}

	type slot struct {
		sample Sample
	}
	latest := map[[2]string]slot{}
	keyOf := func(provider string, p netip.Prefix) [2]string {
		return [2]string{provider, p.String()}
	}
	for _, s := range samples {
		p := s.Prefix.Masked()
		if s.Provider == "" || !p.IsValid() || p.Bits() == 0 || s.Time.IsZero() {
			continue
		}
		if s.Time.After(now) || now.Sub(s.Time) > cfg.Window {
			continue
		}
		s.Prefix = p
		k := keyOf(s.Provider, p)
		if prev, ok := latest[k]; ok && !s.Time.After(prev.sample.Time) {
			continue
		}
		latest[k] = slot{sample: s}
	}

	path := map[netip.Prefix][]uint32{}
	native := map[netip.Prefix]string{}
	var routeOrder []netip.Prefix
	for _, rt := range routes {
		p := rt.Prefix.Masked()
		if !p.IsValid() || p.Bits() == 0 {
			continue
		}
		if _, ok := path[p]; ok {
			continue
		}
		path[p] = append([]uint32(nil), rt.ASPath...)
		native[p] = rt.Provider
		routeOrder = append(routeOrder, p)
	}

	type prefView struct {
		bad     map[string]struct{}
		healthy map[string]struct{}
	}
	views := map[netip.Prefix]*prefView{}
	viewOf := func(p netip.Prefix) *prefView {
		v := views[p]
		if v == nil {
			v = &prefView{bad: map[string]struct{}{}, healthy: map[string]struct{}{}}
			views[p] = v
		}
		return v
	}
	for _, sl := range latest {
		s := sl.sample
		v := viewOf(s.Prefix)
		if sampleDegraded(s, cfg) {
			v.bad[s.Provider] = struct{}{}
			continue
		}
		v.healthy[s.Provider] = struct{}{}
	}

	asEligible := func(v *prefView) bool {
		return len(v.bad) >= 1 && len(v.healthy) == 0
	}
	contains := func(p netip.Prefix, asn uint32) bool {
		for _, a := range path[p] {
			if a == asn {
				return true
			}
		}
		return false
	}

	type asnHit struct {
		prefixes map[netip.Prefix]struct{}
		provs    map[string]struct{}
	}
	byASN := map[uint32]*asnHit{}
	for p, v := range views {
		if !asEligible(v) {
			continue
		}
		seen := map[uint32]struct{}{}
		for _, asn := range path[p] {
			if asn == 0 {
				continue
			}
			if _, skip := ignore[asn]; skip {
				continue
			}
			if _, dup := seen[asn]; dup {
				continue
			}
			seen[asn] = struct{}{}
			h := byASN[asn]
			if h == nil {
				h = &asnHit{prefixes: map[netip.Prefix]struct{}{}, provs: map[string]struct{}{}}
				byASN[asn] = h
			}
			h.prefixes[p] = struct{}{}
			for prov := range v.bad {
				h.provs[prov] = struct{}{}
			}
		}
	}

	var asns []uint32
	for asn, h := range byASN {
		if len(h.prefixes) >= cfg.MinPrefixes {
			asns = append(asns, asn)
		}
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	sick := map[uint32]struct{}{}
	for _, asn := range asns {
		sick[asn] = struct{}{}
	}
	explained := func(p netip.Prefix) bool {
		for _, asn := range path[p] {
			if _, ok := sick[asn]; ok {
				return true
			}
		}
		return false
	}

	type circHit struct {
		prefixes map[netip.Prefix]struct{}
	}
	byProv := map[string]*circHit{}
	for p, v := range views {
		if explained(p) {
			continue
		}
		single := len(v.bad) >= 1 && len(v.healthy) == 0 && len(v.bad)+len(v.healthy) == 1
		for prov := range v.bad {
			specific := len(v.healthy) >= 1
			if !specific && !single {
				continue
			}
			h := byProv[prov]
			if h == nil {
				h = &circHit{prefixes: map[netip.Prefix]struct{}{}}
				byProv[prov] = h
			}
			h.prefixes[p] = struct{}{}
		}
	}
	var provs []string
	for prov, h := range byProv {
		if len(h.prefixes) >= cfg.MinPrefixes {
			provs = append(provs, prov)
		}
	}
	sort.Strings(provs)

	var incidents []Incident
	for _, asn := range asns {
		h := byASN[asn]
		incidents = append(incidents, Incident{
			Kind:      IncidentAS,
			ASN:       asn,
			Prefixes:  prefixKeys(h.prefixes),
			Providers: stringKeys(h.provs),
		})
	}
	for _, prov := range provs {
		h := byProv[prov]
		incidents = append(incidents, Incident{
			Kind:      IncidentCircuit,
			Provider:  prov,
			Prefixes:  prefixKeys(h.prefixes),
			Providers: []string{prov},
		})
	}

	// Nothing to re-queue. Skip the walk.
	if len(incidents) == 0 {
		return Outcome{}
	}

	sampledOn := map[string]map[netip.Prefix]struct{}{}
	for _, sl := range latest {
		s := sl.sample
		m := sampledOn[s.Provider]
		if m == nil {
			m = map[netip.Prefix]struct{}{}
			sampledOn[s.Provider] = m
		}
		m[s.Prefix] = struct{}{}
	}

	seen := map[netip.Prefix]struct{}{}
	var targets []plugin.Target
	truncated := false
	add := func(p netip.Prefix) {
		p = p.Masked()
		if !p.IsValid() || p.Bits() == 0 {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		if len(targets) >= cfg.MaxTargets {
			truncated = true
			return
		}
		seen[p] = struct{}{}
		targets = append(targets, plugin.Target{Prefix: p, Interval: cfg.Interval})
	}
	addSorted := func(ps []netip.Prefix) {
		sortPrefixes(ps)
		for _, p := range ps {
			add(p)
		}
	}

	// Triggering prefixes first, so the cap keeps the ones already failing.
	var triggered []netip.Prefix
	trigSeen := map[netip.Prefix]struct{}{}
	for _, inc := range incidents {
		for _, p := range inc.Prefixes {
			if _, ok := trigSeen[p]; ok {
				continue
			}
			trigSeen[p] = struct{}{}
			triggered = append(triggered, p)
		}
	}
	addSorted(triggered)

	for _, asn := range asns {
		var extra []netip.Prefix
		for _, p := range routeOrder {
			if _, ok := seen[p]; ok {
				continue
			}
			if contains(p, asn) {
				extra = append(extra, p)
			}
		}
		addSorted(extra)
	}
	for _, prov := range provs {
		var extra []netip.Prefix
		for p := range sampledOn[prov] {
			if _, ok := seen[p]; ok {
				continue
			}
			extra = append(extra, p)
		}
		addSorted(extra)
		extra = extra[:0]
		for _, p := range routeOrder {
			if _, ok := seen[p]; ok || native[p] != prov {
				continue
			}
			extra = append(extra, p)
		}
		addSorted(extra)
	}

	for i := range incidents {
		incidents[i].Requeued = requeued(incidents[i], targets, path, sampledOn, native)
	}
	return Outcome{Incidents: incidents, Targets: targets, Truncated: truncated}
}

func sampleDegraded(s Sample, cfg Config) bool {
	if s.Failed {
		return true
	}
	if cfg.LossPct > 0 && s.LossPct >= cfg.LossPct {
		return true
	}
	if cfg.RTTMs > 0 {
		limit := time.Duration(cfg.RTTMs * float64(time.Millisecond))
		if s.RTT >= limit {
			return true
		}
	}
	return false
}

func requeued(inc Incident, targets []plugin.Target, path map[netip.Prefix][]uint32, sampled map[string]map[netip.Prefix]struct{}, native map[netip.Prefix]string) int {
	n := 0
	for _, t := range targets {
		switch inc.Kind {
		case IncidentAS:
			for _, asn := range path[t.Prefix] {
				if asn == inc.ASN {
					n++
					break
				}
			}
		case IncidentCircuit:
			if _, ok := sampled[inc.Provider][t.Prefix]; ok || native[t.Prefix] == inc.Provider {
				n++
			}
		}
	}
	return n
}

func prefixKeys(m map[netip.Prefix]struct{}) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sortPrefixes(out)
	return out
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

func stringKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
