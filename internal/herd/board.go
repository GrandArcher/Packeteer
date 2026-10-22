package herd

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Dashboard limits (#296). Every view reads at most viewRows stored rows
// and says so when it hit that cap.
const (
	defaultLossPct = 5.0
	maxEvents      = 50
	maxMeshRows    = 40
	maxMeshCols    = 24
	maxSeriesPts   = 200
	maxHits        = 100
	mapSpan        = 24 * time.Hour
	freshMember    = time.Hour
	maxMonitorSpan = 7 * 24 * time.Hour
	minWindow      = time.Minute
)

// Basis says what the independent-vantage counts rest on. Identity proof
// by RPKI is not implemented, so a member is a configured peer with a
// pinned key, counted once per ASN; nothing here is called verified.
const Basis = "pinned_key"

// QueryError is a dashboard request the caller can fix; any other error is
// the store failing.
type QueryError struct{ Msg string }

func (e QueryError) Error() string { return e.Msg }

func bad(format string, args ...any) error { return QueryError{fmt.Sprintf(format, args...)} }

// Target is what a record measures: one origin ASN (pooled) or one learned
// route. The two are never mixed (docs/design/herd.md, Showing many
// vantages, item 4).
type Target struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

const (
	kindOrigin = "origin_asn"
	kindPrefix = "prefix"
)

func targetOf(r Record) (Target, bool) {
	switch {
	case r.Prefix != "":
		return Target{Kind: kindPrefix, Value: r.Prefix}, true
	case r.OriginASN != 0:
		v := strconv.FormatUint(uint64(r.OriginASN), 10)
		return Target{Kind: kindOrigin, Value: v}, true
	}
	return Target{}, false
}

func lessTarget(a, b Target) bool {
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.Value < b.Value
}

// Board builds the dashboard views from the stored records. It only reads:
// nothing it returns reaches a decision, and nothing is merged across
// vantages.
type Board struct {
	Store plugin.HerdStore
	// Self is this node's ASN; Peers maps a peer's key id to its ASN.
	Self      uint32
	Peers     map[string]uint32
	Retention time.Duration
	Now       time.Time
}

// boardQuery is one parsed dashboard request.
type boardQuery struct {
	vals   url.Values
	q      plugin.HerdQuery
	window time.Duration
	loss   float64
}

// parse reads a dashboard query. Only the allowed parameters are accepted;
// window and loss have the given default and, for window, maximum.
func (b Board) parse(raw string, allowed []string, defWindow, maxWindow time.Duration) (boardQuery, error) {
	bq := boardQuery{window: defWindow, loss: defaultLossPct}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return bq, bad("malformed query")
	}
	for k, v := range vals {
		if !slices.Contains(allowed, k) {
			return bq, bad("unknown parameter %q", k)
		}
		if len(v) != 1 {
			return bq, bad("parameter %q repeated", k)
		}
	}
	if s := vals.Get("window"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d < minWindow || d > maxWindow {
			return bq, bad("window %q is not a duration from %s to %s", s, minWindow, maxWindow)
		}
		bq.window = d
	}
	if s := vals.Get("loss"); s != "" {
		l, err := strconv.ParseFloat(s, 64)
		if err != nil || l <= 0 || l > 100 {
			return bq, bad("loss %q is not a percentage above 0 and up to 100", s)
		}
		bq.loss = l
	}
	bq.vals = vals
	bq.q = plugin.HerdQuery{AnyMember: true, Newest: true, Limit: viewRows + 1}
	if err := applyFilters(vals, &bq.q); err != nil {
		return bq, bad("%s", err)
	}
	return bq, nil
}

// load reads the rows of bq from span back and decodes them.
func (b Board) load(ctx context.Context, bq boardQuery, span time.Duration) ([]obs, bool, error) {
	bq.q.From = b.Now.Add(-span)
	rows, err := b.Store.HerdRecords(ctx, bq.q)
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > viewRows
	if truncated {
		rows = rows[:viewRows]
	}
	return decodeRows(rows, b.Self, b.Peers), truncated, nil
}

func (b Board) age(t time.Time) float64 { return max(b.Now.Sub(t).Seconds(), 0) }

// cell is one vantage measuring one target.
type cell struct {
	v vkey
	t Target
}

// latestCells keeps the newest measurement of each vantage and target. A
// failed round carries no measurement and is skipped.
func latestCells(all []obs) map[cell]obs {
	m := map[cell]obs{}
	for _, o := range all {
		t, ok := targetOf(o.rec)
		if !ok || o.rec.Failed || o.rec.LossPct == nil {
			continue
		}
		c := cell{o.vkey(), t}
		if prev, seen := m[c]; !seen || o.time.After(prev.time) {
			m[c] = o
		}
	}
	return m
}

func degraded(o obs, loss float64) bool { return *o.rec.LossPct >= loss }

// ---- Overview ----

// Sharing is this node's own sharing status, from NodeStatus.
type Sharing struct {
	PreviewOnly   bool     `json:"preview_only"`
	Serving       bool     `json:"serving"`
	KeyID         string   `json:"key_id"`
	Country       string   `json:"country"`
	Granularity   string   `json:"granularity"`
	Classes       []string `json:"classes"`
	Sources       []string `json:"sources"`
	Discovery     string   `json:"discovery"`
	RetentionDays int      `json:"retention_days"`
}

// MemberRow is one member of the herd as this node sees it.
type MemberRow struct {
	Member   string `json:"member"`
	Local    bool   `json:"local"`
	ASN      uint32 `json:"asn"`
	Identity string `json:"identity"`
	// Verified is false for every member: RPKI identity proof is not
	// implemented, so a member is only a pinned key.
	Verified  bool     `json:"verified"`
	Source    string   `json:"source"`
	Countries []string `json:"countries"`
	Vantages  int      `json:"vantages"`
	Records   int      `json:"records"`
	// NewestAgeSeconds is the age of the member's newest record in the
	// last 24 hours; absent when there is none.
	NewestAgeSeconds *float64   `json:"newest_age_seconds,omitempty"`
	LastOK           *time.Time `json:"last_ok,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
	Stale            bool       `json:"stale"`
}

// Overview is the herd page header: members, freshness, and own sharing.
type Overview struct {
	Enabled   bool        `json:"enabled"`
	AsOf      time.Time   `json:"as_of"`
	Sharing   Sharing     `json:"sharing"`
	Members   []MemberRow `json:"members"`
	Vantages  int         `json:"vantages"`
	Countries []string    `json:"countries"`
	Truncated bool        `json:"truncated,omitempty"`
}

// Overview lists the members and their freshness over the last 24 hours.
func (b Board) Overview(ctx context.Context, st NodeStatus) (Overview, error) {
	o := Overview{Enabled: true, AsOf: b.Now, Members: []MemberRow{}, Countries: []string{}, Sharing: Sharing{
		PreviewOnly: st.PreviewOnly, Serving: st.Serving, KeyID: st.KeyID, Country: st.Country, Granularity: st.Granularity,
		Classes: st.Classes, Sources: st.Sources, Discovery: st.Discovery, RetentionDays: st.RetentionDays,
	}}
	bq, err := b.parse("", nil, mapSpan, mapSpan)
	if err != nil {
		return o, err
	}
	all, trunc, err := b.load(ctx, bq, mapSpan)
	if err != nil {
		return o, err
	}
	o.Truncated = trunc
	type agg struct {
		vantages  map[vkey]bool
		countries map[string]bool
		records   int
		newest    time.Time
	}
	byMember := map[string]*agg{}
	for _, r := range all {
		a := byMember[r.member]
		if a == nil {
			a = &agg{vantages: map[vkey]bool{}, countries: map[string]bool{}}
			byMember[r.member] = a
		}
		a.records++
		a.vantages[r.vkey()] = true
		a.countries[r.rec.Vantage] = true
		a.newest = latest(a.newest, r.time)
	}
	row := func(member string, local bool, asn uint32, source string) MemberRow {
		m := MemberRow{Member: member, Local: local, ASN: asn, Identity: "pinned_key", Source: source, Countries: []string{}}
		if local {
			m.Identity = "local"
		}
		if a := byMember[member]; a != nil {
			m.Records, m.Vantages = a.records, len(a.vantages)
			for c := range a.countries {
				m.Countries = append(m.Countries, c)
			}
			sort.Strings(m.Countries)
			age := b.age(a.newest)
			m.NewestAgeSeconds = &age
		}
		return m
	}
	o.Members = append(o.Members, row("local", true, b.Self, "local"))
	o.Members[0].Stale = o.Members[0].NewestAgeSeconds == nil || *o.Members[0].NewestAgeSeconds > freshMember.Seconds()
	for _, p := range st.Peers {
		m := row(p.KeyID, false, p.ASN, p.Source)
		if !p.LastOK.IsZero() {
			ok := p.LastOK
			m.LastOK = &ok
		}
		m.LastError = p.LastError
		m.Stale = m.LastOK == nil || b.Now.Sub(*m.LastOK) > freshMember
		o.Members = append(o.Members, m)
	}
	sort.SliceStable(o.Members[1:], func(i, j int) bool { return o.Members[1+i].Member < o.Members[1+j].Member })
	seen := map[string]bool{}
	for _, a := range byMember {
		o.Vantages += len(a.vantages)
		for c := range a.countries {
			if !seen[c] {
				seen[c] = true
				o.Countries = append(o.Countries, c)
			}
		}
	}
	sort.Strings(o.Countries)
	return o, nil
}

func sortedASNs(set map[uint32]bool) []uint32 {
	if len(set) == 0 {
		return nil
	}
	out := make([]uint32, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

func latest(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// ---- Events ----

// ProviderCount is the agreement for one provider ASN.
type ProviderCount struct {
	ProviderASN uint32 `json:"provider_asn"`
	Reporting   int    `json:"reporting"`
	Degraded    int    `json:"degraded"`
}

// EventVantage is one vantage's latest measurement of an event's target.
type EventVantage struct {
	VantageRef
	LossPct    float64  `json:"loss_pct"`
	RTTAvgMs   *float64 `json:"rtt_avg_ms,omitempty"`
	AgeSeconds float64  `json:"age_seconds"`
	Degraded   bool     `json:"degraded"`
}

// EventRow is one target where at least one member sees loss at or above
// the threshold. Reporting and Degraded count members (one per ASN), not
// records: "5 of 7 vantages".
type EventRow struct {
	Target
	Reporting int `json:"reporting"`
	Degraded  int `json:"degraded"`
	// Origins are the origin ASNs members report for a route; more than one
	// is worth a look. Absent for an origin-ASN target.
	Origins    []uint32        `json:"origins,omitempty"`
	ByProvider []ProviderCount `json:"by_provider"`
	Vantages   []EventVantage  `json:"vantages"`
}

// Events is the world view: where several members see degradation now.
type Events struct {
	Enabled       bool       `json:"enabled"`
	AsOf          time.Time  `json:"as_of"`
	WindowSeconds float64    `json:"window_seconds"`
	LossPct       float64    `json:"loss_pct"`
	Basis         string     `json:"basis"`
	Targets       int        `json:"targets"`
	Events        []EventRow `json:"events"`
	Truncated     bool       `json:"truncated,omitempty"`
}

// Events groups the latest measurement of every vantage and target in the
// window. A target is listed when any member sees loss at or above loss.
// It is not limited to routes in the local RIB: this is display only.
func (b Board) Events(ctx context.Context, raw string) (Events, error) {
	ev := Events{Enabled: true, AsOf: b.Now, Basis: Basis, Events: []EventRow{}}
	bq, err := b.parse(raw, []string{"window", "loss"}, 15*time.Minute, 24*time.Hour)
	if err != nil {
		return ev, err
	}
	ev.WindowSeconds, ev.LossPct = bq.window.Seconds(), bq.loss
	all, trunc, err := b.load(ctx, bq, bq.window)
	if err != nil {
		return ev, err
	}
	ev.Truncated = trunc
	byTarget := map[Target][]obs{}
	for c, o := range latestCells(all) {
		byTarget[c.t] = append(byTarget[c.t], o)
	}
	ev.Targets = len(byTarget)
	for t, list := range byTarget {
		row := EventRow{Target: t, ByProvider: []ProviderCount{}, Vantages: []EventVantage{}}
		seen, lossy, origins := map[uint32]bool{}, map[uint32]bool{}, map[uint32]bool{}
		type pk struct{ provider, asn uint32 }
		pAll, pBad := map[pk]bool{}, map[pk]bool{}
		for _, o := range list {
			d := degraded(o, bq.loss)
			seen[o.asn] = true
			if t.Kind == kindPrefix && o.rec.OriginASN != 0 {
				origins[o.rec.OriginASN] = true
			}
			pAll[pk{o.rec.ProviderASN, o.asn}] = true
			if d {
				lossy[o.asn] = true
				pBad[pk{o.rec.ProviderASN, o.asn}] = true
			}
			row.Vantages = append(row.Vantages, EventVantage{VantageRef: o.ref(), LossPct: *o.rec.LossPct, RTTAvgMs: o.rec.RTTAvgMs, AgeSeconds: b.age(o.time), Degraded: d})
		}
		if len(lossy) == 0 {
			continue
		}
		row.Reporting, row.Degraded, row.Origins = len(seen), len(lossy), sortedASNs(origins)
		counts := map[uint32]*ProviderCount{}
		for k := range pAll {
			pc := counts[k.provider]
			if pc == nil {
				pc = &ProviderCount{ProviderASN: k.provider}
				counts[k.provider] = pc
			}
			pc.Reporting++
		}
		for k := range pBad {
			counts[k.provider].Degraded++
		}
		for _, pc := range counts {
			row.ByProvider = append(row.ByProvider, *pc)
		}
		sort.Slice(row.ByProvider, func(i, j int) bool { return row.ByProvider[i].ProviderASN < row.ByProvider[j].ProviderASN })
		sort.Slice(row.Vantages, func(i, j int) bool { return lessRef(row.Vantages[i].VantageRef, row.Vantages[j].VantageRef) })
		ev.Events = append(ev.Events, row)
	}
	sort.Slice(ev.Events, func(i, j int) bool {
		a, c := ev.Events[i], ev.Events[j]
		if a.Degraded != c.Degraded {
			return a.Degraded > c.Degraded
		}
		if a.Reporting != c.Reporting {
			return a.Reporting > c.Reporting
		}
		return lessTarget(a.Target, c.Target)
	})
	if len(ev.Events) > maxEvents {
		ev.Events, ev.Truncated = ev.Events[:maxEvents], true
	}
	return ev, nil
}

// ---- Mesh ----

// MeshCell is one vantage's latest measurement of one target.
type MeshCell struct {
	LossPct    float64  `json:"loss_pct"`
	RTTAvgMs   *float64 `json:"rtt_avg_ms,omitempty"`
	AgeSeconds float64  `json:"age_seconds"`
	Degraded   bool     `json:"degraded"`
}

// MeshRow is one vantage; Cells lines up with Mesh.Targets and holds null
// where the vantage has no measurement of that target.
type MeshRow struct {
	VantageRef
	Cells []*MeshCell `json:"cells"`
}

// Mesh is a grid of vantages against targets.
type Mesh struct {
	Enabled       bool      `json:"enabled"`
	AsOf          time.Time `json:"as_of"`
	WindowSeconds float64   `json:"window_seconds"`
	LossPct       float64   `json:"loss_pct"`
	Targets       []Target  `json:"targets"`
	Rows          []MeshRow `json:"rows"`
	Truncated     bool      `json:"truncated,omitempty"`
}

// Mesh builds the grid. Columns are the targets measured by the most
// members, capped; rows are vantages, capped. Cells are never combined.
func (b Board) Mesh(ctx context.Context, raw string) (Mesh, error) {
	m := Mesh{Enabled: true, AsOf: b.Now, Targets: []Target{}, Rows: []MeshRow{}}
	bq, err := b.parse(raw, []string{"window", "loss"}, time.Hour, 24*time.Hour)
	if err != nil {
		return m, err
	}
	m.WindowSeconds, m.LossPct = bq.window.Seconds(), bq.loss
	all, trunc, err := b.load(ctx, bq, bq.window)
	if err != nil {
		return m, err
	}
	m.Truncated = trunc
	cells := latestCells(all)
	members := map[Target]map[uint32]bool{}
	refs := map[vkey]VantageRef{}
	for c, o := range cells {
		if members[c.t] == nil {
			members[c.t] = map[uint32]bool{}
		}
		members[c.t][o.asn] = true
		refs[c.v] = o.ref()
	}
	for t := range members {
		m.Targets = append(m.Targets, t)
	}
	sort.Slice(m.Targets, func(i, j int) bool {
		a, c := m.Targets[i], m.Targets[j]
		if len(members[a]) != len(members[c]) {
			return len(members[a]) > len(members[c])
		}
		return lessTarget(a, c)
	})
	if len(m.Targets) > maxMeshCols {
		m.Targets, m.Truncated = m.Targets[:maxMeshCols], true
	}
	rows := make([]VantageRef, 0, len(refs))
	keys := map[VantageRef]vkey{}
	for k, r := range refs {
		rows = append(rows, r)
		keys[r] = k
	}
	sort.Slice(rows, func(i, j int) bool { return lessRef(rows[i], rows[j]) })
	if len(rows) > maxMeshRows {
		rows, m.Truncated = rows[:maxMeshRows], true
	}
	for _, r := range rows {
		row := MeshRow{VantageRef: r, Cells: make([]*MeshCell, len(m.Targets))}
		for i, t := range m.Targets {
			if o, ok := cells[cell{keys[r], t}]; ok {
				row.Cells[i] = &MeshCell{LossPct: *o.rec.LossPct, RTTAvgMs: o.rec.RTTAvgMs, AgeSeconds: b.age(o.time), Degraded: degraded(o, bq.loss)}
			}
		}
		m.Rows = append(m.Rows, row)
	}
	return m, nil
}

// ---- Monitors ----

// Point is one round of a series. Loss and RTT are the record's own
// numbers.
type Point struct {
	Time     time.Time `json:"time"`
	LossPct  *float64  `json:"loss_pct,omitempty"`
	RTTMinMs *float64  `json:"rtt_min_ms,omitempty"`
	RTTAvgMs *float64  `json:"rtt_avg_ms,omitempty"`
	RTTMaxMs *float64  `json:"rtt_max_ms,omitempty"`
	Failed   bool      `json:"failed,omitempty"`
}

// Series is one vantage's rounds toward one target, oldest first.
type Series struct {
	VantageRef
	Target Target  `json:"target"`
	Points []Point `json:"points"`
}

// PathChange is the AS paths a vantage saw from Time on. Origin-ASN
// records carry every distinct path of the round; route records one.
type PathChange struct {
	Time  time.Time  `json:"time"`
	Paths [][]uint32 `json:"paths"`
}

// PathTrack is one vantage's AS paths toward one target: the first path
// seen, then one entry per change. It is empty when the member does not
// share the paths class.
type PathTrack struct {
	VantageRef
	Target  Target       `json:"target"`
	Changes []PathChange `json:"changes"`
}

// Monitor is the latency series and AS path changes for one target.
type Monitor struct {
	Enabled       bool        `json:"enabled"`
	AsOf          time.Time   `json:"as_of"`
	WindowSeconds float64     `json:"window_seconds"`
	Series        []Series    `json:"series"`
	Paths         []PathTrack `json:"paths"`
	Truncated     bool        `json:"truncated,omitempty"`
}

func pathsOf(r Record) [][]uint32 {
	if len(r.ASPath) > 0 {
		return [][]uint32{r.ASPath}
	}
	return r.ASPaths
}

func samePaths(a, b [][]uint32) bool {
	if len(a) != len(b) {
		return false
	}
	key := func(ps [][]uint32) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = fmt.Sprint(p)
		}
		sort.Strings(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}

// Monitor builds the series for the origin_asn or prefix in raw. Each
// series keeps its newest 200 rounds.
func (b Board) Monitor(ctx context.Context, raw string) (Monitor, error) {
	m := Monitor{Enabled: true, AsOf: b.Now, Series: []Series{}, Paths: []PathTrack{}}
	bq, err := b.parse(raw, []string{"origin_asn", "prefix", "match", "provider_asn", "window"}, 6*time.Hour, maxMonitorSpan)
	if err != nil {
		return m, err
	}
	if bq.q.OriginASN == 0 && !bq.q.Prefix.IsValid() {
		return m, bad("name an origin_asn or a prefix")
	}
	m.WindowSeconds = bq.window.Seconds()
	all, trunc, err := b.load(ctx, bq, bq.window)
	if err != nil {
		return m, err
	}
	m.Truncated = trunc
	groups := map[cell][]obs{}
	for _, o := range all {
		t, ok := targetOf(o.rec)
		if !ok {
			continue
		}
		k := cell{o.vkey(), t}
		groups[k] = append(groups[k], o)
	}
	for k, list := range groups {
		sort.Slice(list, func(i, j int) bool { return list[i].time.Before(list[j].time) })
		ref := list[0].ref()
		track := PathTrack{VantageRef: ref, Target: k.t, Changes: []PathChange{}}
		var prev [][]uint32
		for _, o := range list {
			ps := pathsOf(o.rec)
			if len(ps) == 0 || (prev != nil && samePaths(prev, ps)) {
				continue
			}
			track.Changes = append(track.Changes, PathChange{Time: o.time, Paths: ps})
			prev = ps
		}
		if len(track.Changes) > 0 {
			m.Paths = append(m.Paths, track)
		}
		if len(list) > maxSeriesPts {
			list, m.Truncated = list[len(list)-maxSeriesPts:], true
		}
		s := Series{VantageRef: ref, Target: k.t, Points: make([]Point, len(list))}
		for i, o := range list {
			r := o.rec
			s.Points[i] = Point{Time: o.time, LossPct: r.LossPct, RTTMinMs: r.RTTMinMs, RTTAvgMs: r.RTTAvgMs, RTTMaxMs: r.RTTMaxMs, Failed: r.Failed}
		}
		m.Series = append(m.Series, s)
	}
	byRef := func(a, c VantageRef, ta, tc Target) bool {
		if ta != tc {
			return lessTarget(ta, tc)
		}
		return lessRef(a, c)
	}
	sort.Slice(m.Series, func(i, j int) bool {
		return byRef(m.Series[i].VantageRef, m.Series[j].VantageRef, m.Series[i].Target, m.Series[j].Target)
	})
	sort.Slice(m.Paths, func(i, j int) bool {
		return byRef(m.Paths[i].VantageRef, m.Paths[j].VantageRef, m.Paths[i].Target, m.Paths[j].Target)
	})
	return m, nil
}

// ---- Map ----

// Country is what the vantages in one country see. Only the country the
// member declared is used.
type Country struct {
	Country  string `json:"country"`
	Members  int    `json:"members"`
	Vantages int    `json:"vantages"`
	// Measured counts the vantage and target pairs with a measurement in
	// the window; Degraded counts those at or above the loss threshold.
	Measured     int      `json:"measured"`
	Degraded     int      `json:"degraded"`
	WorstLossPct *float64 `json:"worst_loss_pct,omitempty"`
	// Condition is degraded, ok, or no_data (vantages known from the last
	// 24 hours, none measuring in the window).
	Condition string `json:"condition"`
}

// Map is the vantages by country.
type Map struct {
	Enabled       bool      `json:"enabled"`
	AsOf          time.Time `json:"as_of"`
	WindowSeconds float64   `json:"window_seconds"`
	LossPct       float64   `json:"loss_pct"`
	Countries     []Country `json:"countries"`
	Truncated     bool      `json:"truncated,omitempty"`
}

// Map groups the vantages seen in the last 24 hours by declared country.
func (b Board) Map(ctx context.Context, raw string) (Map, error) {
	m := Map{Enabled: true, AsOf: b.Now, Countries: []Country{}}
	bq, err := b.parse(raw, []string{"window", "loss"}, 15*time.Minute, mapSpan)
	if err != nil {
		return m, err
	}
	m.WindowSeconds, m.LossPct = bq.window.Seconds(), bq.loss
	all, trunc, err := b.load(ctx, bq, mapSpan)
	if err != nil {
		return m, err
	}
	m.Truncated = trunc
	type agg struct {
		members  map[uint32]bool
		vantages map[vkey]bool
		c        Country
	}
	byCountry := map[string]*agg{}
	get := func(code string) *agg {
		a := byCountry[code]
		if a == nil {
			a = &agg{members: map[uint32]bool{}, vantages: map[vkey]bool{}, c: Country{Country: code, Condition: "no_data"}}
			byCountry[code] = a
		}
		return a
	}
	for _, o := range all {
		a := get(o.rec.Vantage)
		a.members[o.asn] = true
		a.vantages[o.vkey()] = true
	}
	cutoff := b.Now.Add(-bq.window)
	var inWindow []obs
	for _, o := range all {
		if !o.time.Before(cutoff) {
			inWindow = append(inWindow, o)
		}
	}
	for c, o := range latestCells(inWindow) {
		a := get(c.v.country)
		a.c.Measured++
		if a.c.Condition == "no_data" {
			a.c.Condition = "ok"
		}
		if degraded(o, bq.loss) {
			a.c.Degraded++
			a.c.Condition = "degraded"
		}
		if a.c.WorstLossPct == nil || *o.rec.LossPct > *a.c.WorstLossPct {
			l := *o.rec.LossPct
			a.c.WorstLossPct = &l
		}
	}
	for _, a := range byCountry {
		a.c.Members, a.c.Vantages = len(a.members), len(a.vantages)
		m.Countries = append(m.Countries, a.c)
	}
	sort.Slice(m.Countries, func(i, j int) bool { return m.Countries[i].Country < m.Countries[j].Country })
	return m, nil
}

// ---- Search ----

// Hit is one target found in the stored records.
type Hit struct {
	Target
	Members   int      `json:"members"`
	Vantages  int      `json:"vantages"`
	Records   int      `json:"records"`
	Providers []uint32 `json:"providers"`
	// Origins are the origin ASNs reported for a route; absent for an
	// origin-ASN target.
	Origins   []uint32  `json:"origins,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Search is the targets that match, within retention.
type Search struct {
	Enabled   bool      `json:"enabled"`
	AsOf      time.Time `json:"as_of"`
	Days      int       `json:"days"`
	Hits      []Hit     `json:"hits"`
	Truncated bool      `json:"truncated,omitempty"`
}

func matchMember(o obs, want string) bool {
	if want == "" {
		return true
	}
	if n, err := strconv.ParseUint(want, 10, 32); err == nil {
		return o.asn == uint32(n)
	}
	return o.member == want
}

// Search finds targets by origin_asn, provider_asn, prefix with match, or
// member (a key id or an ASN), over the retention period.
func (b Board) Search(ctx context.Context, raw string) (Search, error) {
	s := Search{Enabled: true, AsOf: b.Now, Hits: []Hit{}, Days: int(b.Retention / (24 * time.Hour))}
	bq, err := b.parse(raw, []string{"origin_asn", "provider_asn", "prefix", "match", "member"}, 0, 0)
	if err != nil {
		return s, err
	}
	member := bq.vals.Get("member")
	if bq.q.OriginASN == 0 && bq.q.ProviderASN == 0 && !bq.q.Prefix.IsValid() && member == "" {
		return s, bad("name an origin_asn, provider_asn, prefix, or member")
	}
	// A key id (or "local") is selected in the store, so an older member's
	// rows are not pushed out of the newest-rows window by other members.
	// An ASN can name several key ids and is matched after decoding.
	if _, err := strconv.ParseUint(member, 10, 32); member != "" && err != nil {
		bq.q.AnyMember = false
		if member != "local" {
			bq.q.Member = member
		}
	}
	all, trunc, err := b.load(ctx, bq, b.Retention)
	if err != nil {
		return s, err
	}
	s.Truncated = trunc
	type agg struct {
		hit       Hit
		members   map[uint32]bool
		vantages  map[vkey]bool
		providers map[uint32]bool
		origins   map[uint32]bool
	}
	byTarget := map[Target]*agg{}
	for _, o := range all {
		t, ok := targetOf(o.rec)
		if !ok || !matchMember(o, member) {
			continue
		}
		a := byTarget[t]
		if a == nil {
			a = &agg{hit: Hit{Target: t, FirstSeen: o.time, LastSeen: o.time}, members: map[uint32]bool{}, vantages: map[vkey]bool{}, providers: map[uint32]bool{}, origins: map[uint32]bool{}}
			byTarget[t] = a
		}
		if t.Kind == kindPrefix && o.rec.OriginASN != 0 {
			a.origins[o.rec.OriginASN] = true
		}
		a.hit.Records++
		a.members[o.asn] = true
		a.vantages[o.vkey()] = true
		a.providers[o.rec.ProviderASN] = true
		if o.time.Before(a.hit.FirstSeen) {
			a.hit.FirstSeen = o.time
		}
		a.hit.LastSeen = latest(a.hit.LastSeen, o.time)
	}
	for _, a := range byTarget {
		a.hit.Members, a.hit.Vantages = len(a.members), len(a.vantages)
		a.hit.Providers, a.hit.Origins = sortedASNs(a.providers), sortedASNs(a.origins)
		s.Hits = append(s.Hits, a.hit)
	}
	sort.Slice(s.Hits, func(i, j int) bool {
		a, c := s.Hits[i], s.Hits[j]
		if !a.LastSeen.Equal(c.LastSeen) {
			return a.LastSeen.After(c.LastSeen)
		}
		return lessTarget(a.Target, c.Target)
	})
	if len(s.Hits) > maxHits {
		s.Hits, s.Truncated = s.Hits[:maxHits], true
	}
	return s, nil
}
