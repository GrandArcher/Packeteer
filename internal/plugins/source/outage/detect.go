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
	// Hops are stable traceroute hop addresses for this provider and
	// prefix, in TTL order, from a per-provider indirect trace. Nil when
	// no trace exists. Detect maps each hop to an origin ASN by longest
	// match over the learned routes and does not send packets.
	Hops []netip.Addr
}

// Alt is one provider's learned AS path for a prefix other than the
// native route (add-path or BMP). An empty ASPath cannot implicate an ASN.
type Alt struct {
	Provider string
	ASPath   []uint32
}

// Route is one learned prefix. Provider is the native exit when the RIB
// matched a configured next hop. An empty ASPath cannot implicate an ASN.
type Route struct {
	Prefix   netip.Prefix
	ASPath   []uint32
	Provider string
	// Alts are other providers' learned paths, and a different path for
	// the native provider when add-path or BMP showed one. Nil leaves
	// correlation on ASPath alone.
	Alts []Alt
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
// that is still healthy on another provider does not count toward that
// rule: that pattern is a circuit, unless the ASN appears only on the
// degraded provider's own path (an alternate learned path, or a hop
// origin that is not on the native path). That incident is attributed
// to the degraded provider. IgnoreASNs are skipped, so an ASN that sits
// on every path is not the failure domain.
//
// ASNs come from the native AS path, from each measured provider's
// alternate learned path, and from traceroute hops. A hop address maps
// to the origin ASN (the last ASN) of the longest matching learned
// prefix. A default route is not a match. No external data is used.
// With no hops and no alternate paths the result is the native-path
// correlation above.
//
// A provider is sick when at least MinPrefixes prefixes are degraded on
// it and healthy on another provider, and those prefixes are not already
// explained by a sick ASN. When a prefix was measured on only one
// provider, it counts toward that provider only if no sick ASN explains
// it, so a dead circuit with mixed destinations still fires and a shared
// transit ASN is not reported twice.
//
// Targets are probe prefixes only. AS incidents include every learned
// prefix whose native path, alternate path, or hop-ASN path contains the
// ASN, degraded ones first, up to MaxTargets. Circuit incidents include
// the prefixes that counted, then
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
	alts := map[netip.Prefix]map[string][]uint32{}
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
		if len(rt.Alts) == 0 {
			continue
		}
		m := map[string][]uint32{}
		for _, a := range rt.Alts {
			if a.Provider == "" {
				continue
			}
			if _, ok := m[a.Provider]; ok {
				continue
			}
			m[a.Provider] = append([]uint32(nil), a.ASPath...)
		}
		if len(m) > 0 {
			alts[p] = m
		}
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
	usable := func(asn uint32) bool {
		if asn == 0 {
			return false
		}
		_, skip := ignore[asn]
		return !skip
	}
	// originASN is the last non-zero ASN on the longest learned prefix
	// that covers addr. A default route is not a match. A learned prefix
	// with no usable origin stops the search.
	originASN := func(addr netip.Addr) (uint32, bool) {
		if !addr.IsValid() {
			return 0, false
		}
		addr = addr.Unmap()
		for bits := addr.BitLen(); bits >= 1; bits-- {
			p, err := addr.Prefix(bits)
			if err != nil {
				continue
			}
			as, ok := path[p]
			if !ok {
				continue
			}
			for i := len(as) - 1; i >= 0; i-- {
				if as[i] == 0 {
					continue
				}
				if !usable(as[i]) {
					return 0, false
				}
				return as[i], true
			}
			return 0, false
		}
		return 0, false
	}
	hopASN := map[[2]string][]uint32{}
	hopAll := map[netip.Prefix][]uint32{}
	for _, sl := range latest {
		s := sl.sample
		if len(s.Hops) == 0 {
			continue
		}
		var asns []uint32
		seenHop := map[uint32]struct{}{}
		for _, h := range s.Hops {
			asn, ok := originASN(h)
			if !ok {
				continue
			}
			if _, dup := seenHop[asn]; dup {
				continue
			}
			seenHop[asn] = struct{}{}
			asns = append(asns, asn)
		}
		if len(asns) == 0 {
			continue
		}
		hopASN[keyOf(s.Provider, s.Prefix)] = asns
		all := hopAll[s.Prefix]
		known := map[uint32]struct{}{}
		for _, asn := range all {
			known[asn] = struct{}{}
		}
		for _, asn := range asns {
			if _, ok := known[asn]; ok {
				continue
			}
			known[asn] = struct{}{}
			all = append(all, asn)
		}
		hopAll[s.Prefix] = all
	}
	onPath := func(as []uint32, asn uint32) bool {
		for _, a := range as {
			if a == asn {
				return true
			}
		}
		return false
	}
	// crosses reports whether any learned path or hop path for p contains
	// asn. Used to re-queue prefixes, including ones not yet degraded.
	crosses := func(p netip.Prefix, asn uint32) bool {
		if onPath(path[p], asn) {
			return true
		}
		for _, as := range alts[p] {
			if onPath(as, asn) {
				return true
			}
		}
		return onPath(hopAll[p], asn)
	}

	type asnHit struct {
		prefixes map[netip.Prefix]struct{}
		provs    map[string]struct{}
	}
	note := func(by map[uint32]*asnHit, asn uint32, p netip.Prefix, prov string) {
		if !usable(asn) {
			return
		}
		h := by[asn]
		if h == nil {
			h = &asnHit{prefixes: map[netip.Prefix]struct{}{}, provs: map[string]struct{}{}}
			by[asn] = h
		}
		h.prefixes[p] = struct{}{}
		if prov != "" {
			h.provs[prov] = struct{}{}
		}
	}
	// extraASNs is the alternate path plus the hop-ASN path for one
	// measured provider. The two lists are not joined, so neither is mutated.
	extraASNs := func(p netip.Prefix, prov string, fn func(uint32)) {
		seen := map[uint32]struct{}{}
		walk := func(as []uint32) {
			for _, asn := range as {
				if !usable(asn) {
					continue
				}
				if _, dup := seen[asn]; dup {
					continue
				}
				seen[asn] = struct{}{}
				fn(asn)
			}
		}
		if m := alts[p]; m != nil {
			walk(m[prov])
		}
		walk(hopASN[keyOf(prov, p)])
	}

	byASN := map[uint32]*asnHit{}
	for p, v := range views {
		if !asEligible(v) {
			continue
		}
		seen := map[uint32]struct{}{}
		for _, asn := range path[p] {
			if !usable(asn) {
				continue
			}
			if _, dup := seen[asn]; dup {
				continue
			}
			seen[asn] = struct{}{}
			for prov := range v.bad {
				note(byASN, asn, p, prov)
			}
		}
		for prov := range v.bad {
			extraASNs(p, prov, func(asn uint32) {
				if _, already := seen[asn]; already {
					return
				}
				note(byASN, asn, p, prov)
			})
		}
	}
	// A prefix that is healthy on another provider can still implicate an
	// ASN that exists only on the degraded provider's path.
	byScoped := map[uint32]*asnHit{}
	for p, v := range views {
		if asEligible(v) || len(v.bad) == 0 || len(v.healthy) == 0 {
			continue
		}
		nativeSeen := map[uint32]struct{}{}
		for _, asn := range path[p] {
			if usable(asn) {
				nativeSeen[asn] = struct{}{}
			}
		}
		for prov := range v.bad {
			extraASNs(p, prov, func(asn uint32) {
				if _, onNative := nativeSeen[asn]; onNative {
					return
				}
				note(byScoped, asn, p, prov)
			})
		}
	}

	qualify := func(by map[uint32]*asnHit) []uint32 {
		var out []uint32
		for asn, h := range by {
			if len(h.prefixes) >= cfg.MinPrefixes {
				out = append(out, asn)
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
		return out
	}
	globalASNs := qualify(byASN)
	scopedASNs := qualify(byScoped)
	asns := mergeASNs(globalASNs, scopedASNs)
	hits := map[uint32]*asnHit{}
	for _, asn := range globalASNs {
		hits[asn] = byASN[asn]
	}
	for _, asn := range scopedASNs {
		h := hits[asn]
		if h == nil {
			hits[asn] = byScoped[asn]
			continue
		}
		for p := range byScoped[asn].prefixes {
			h.prefixes[p] = struct{}{}
		}
		for prov := range byScoped[asn].provs {
			h.provs[prov] = struct{}{}
		}
	}
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
		v := views[p]
		if v == nil {
			return false
		}
		for prov := range v.bad {
			hit := false
			extraASNs(p, prov, func(asn uint32) {
				if _, ok := sick[asn]; ok {
					hit = true
				}
			})
			if hit {
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
		h := hits[asn]
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
			if crosses(p, asn) {
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
		incidents[i].Requeued = requeued(incidents[i], targets, crosses, sampledOn, native)
	}
	return Outcome{Incidents: incidents, Targets: targets, Truncated: truncated}
}

func mergeASNs(a, b []uint32) []uint32 {
	if len(b) == 0 {
		return a
	}
	if len(a) == 0 {
		return b
	}
	seen := map[uint32]struct{}{}
	out := make([]uint32, 0, len(a)+len(b))
	for _, asn := range append(append([]uint32{}, a...), b...) {
		if _, ok := seen[asn]; ok {
			continue
		}
		seen[asn] = struct{}{}
		out = append(out, asn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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

func requeued(inc Incident, targets []plugin.Target, crosses func(netip.Prefix, uint32) bool, sampled map[string]map[netip.Prefix]struct{}, native map[netip.Prefix]string) int {
	n := 0
	for _, t := range targets {
		switch inc.Kind {
		case IncidentAS:
			if crosses(t.Prefix, inc.ASN) {
				n++
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
