package onlyinvalid

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	t0      = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	fixture = netip.MustParsePrefix("198.51.100.0/24")
)

// fakeRIB holds every learned path per prefix; the first is selected.
type fakeRIB struct {
	paths map[netip.Prefix][]rib.Route
	ready bool
}

func newRIB() *fakeRIB { return &fakeRIB{paths: map[netip.Prefix][]rib.Route{}, ready: true} }

func (f *fakeRIB) add(prefix, provider string, since time.Time, asPath ...uint32) {
	p := netip.MustParsePrefix(prefix)
	f.paths[p] = append(f.paths[p], rib.Route{Prefix: p, Provider: provider, ASPath: asPath, Age: since})
}

func (f *fakeRIB) Ready() bool { return f.ready }

func (f *fakeRIB) Find(keep func(rib.Route) bool, before func(a, b rib.Route) bool, limit int) ([]rib.Route, int) {
	var out []rib.Route
	for _, p := range netpfx.SortedKeys(f.paths) {
		if r := f.paths[p][0]; keep(r) {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b rib.Route) int {
		if before(a, b) {
			return -1
		}
		return 1
	})
	n := len(out)
	return out[:min(limit, n)], n
}

func (f *fakeRIB) Paths(p netip.Prefix) []rib.Route { return slices.Clone(f.paths[p]) }

func (f *fakeRIB) Covering(p netip.Prefix) (rib.Route, bool) {
	for bits := p.Bits(); bits >= 0; bits-- {
		q := netip.PrefixFrom(p.Addr(), bits).Masked()
		if rs, ok := f.paths[q]; ok {
			return rs[0], true
		}
	}
	return rib.Route{}, false
}

// fakeRPKI validates against real VRPs, as one fresh rpki.sources entry.
type fakeRPKI struct {
	vrps    *rpki.VRPs
	updated time.Time
}

func newRPKI(vrps ...plugin.RPKIVRP) *fakeRPKI {
	r := &fakeRPKI{vrps: rpki.NewVRPs(), updated: t0}
	for _, v := range vrps {
		r.vrps.Apply([]rpki.Change{{Prefix: v.Prefix, MaxLen: v.MaxLen, ASN: v.ASN}})
	}
	return r
}

func (r *fakeRPKI) Lookup(p netip.Prefix, origin uint32) plugin.RPKIAnswer {
	return plugin.RPKIAnswer{State: r.vrps.Validate(p, origin), Source: "routinator", Updated: r.updated}
}
func (r *fakeRPKI) Covering(p netip.Prefix) []plugin.RPKIVRP { return r.vrps.Covering(p) }
func (r *fakeRPKI) Updated() time.Time                       { return r.updated }

type fakeFeed struct {
	plugin.Base
	list []plugin.HijackIncident
	err  error
}

func (f fakeFeed) Incidents(_ context.Context, p netip.Prefix) ([]plugin.HijackIncident, error) {
	var out []plugin.HijackIncident
	for _, in := range f.list {
		if in.Prefix.Overlaps(p) {
			out = append(out, in)
		}
	}
	return out, f.err
}

type events struct {
	mu   sync.Mutex
	list []plugin.Event
}

func (e *events) emit(ev plugin.Event) { e.mu.Lock(); e.list = append(e.list, ev); e.mu.Unlock() }

func (e *events) kinds() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.list {
		out = append(out, ev.Kind)
	}
	return out
}

// irrAnswers registers origins per prefix; as-set membership per origin.
func irrAnswers(registered map[netip.Prefix][]uint32, setMembers ...uint32) func(netip.Prefix, uint32, string) plugin.IRRAnswer {
	return func(p netip.Prefix, origin uint32, _ string) plugin.IRRAnswer {
		a := plugin.IRRAnswer{State: plugin.IRRNotRegistered, Source: "radb-file", Database: "RADB", Origins: registered[p],
			ASSet: "AS-EXAMPLE", ASSetState: plugin.IRRNotRegistered}
		if slices.Contains(registered[p], origin) {
			a.State = plugin.IRRRegistered
		}
		if slices.Contains(setMembers, origin) {
			a.ASSetState = plugin.IRRRegistered
		}
		return a
	}
}

// staleFixture: AS64500 holds a ROA for 198.51.100.0/22 with maxLength 22
// and announces the /24, which is therefore invalid. Two transits carry
// it, it has been learned for 90 days, and IRR registers AS64500.
func staleFixture() (*fakeRIB, *fakeRPKI, func(netip.Prefix, uint32, string) plugin.IRRAnswer) {
	r := newRIB()
	r.add("198.51.100.0/24", "transit-a", t0.Add(-90*24*time.Hour), 64496, 64500)
	r.add("198.51.100.0/24", "transit-b", t0.Add(-80*24*time.Hour), 64497, 64500)
	r.add("192.0.2.0/24", "transit-a", t0.Add(-time.Hour), 64496, 64501)
	v := newRPKI(plugin.RPKIVRP{Prefix: netip.MustParsePrefix("198.51.100.0/22"), MaxLen: 22, ASN: 64500},
		plugin.RPKIVRP{Prefix: netip.MustParsePrefix("192.0.2.0/24"), MaxLen: 24, ASN: 64501})
	return r, v, irrAnswers(map[netip.Prefix][]uint32{fixture: {64500}}, 64500)
}

func newDetector(r RIB, v RPKI, irr func(netip.Prefix, uint32, string) plugin.IRRAnswer, ev *events, feeds ...Feed) *Detector {
	return NewDetector(Deps{RIB: r, RPKI: v, IRR: irr, Feeds: feeds, Emit: ev.emit, Now: func() time.Time { return t0 }}, 30*24*time.Hour)
}

func signal(c Case, name string) Signal {
	for _, s := range c.Signals {
		if s.Name == name {
			return s
		}
	}
	return Signal{Name: "missing " + name}
}

// #401 acceptance: an invalid only path whose IRR and history agree is a
// likely stale ROA, the alert fires once with the evidence, and the case
// lists its paths and ROAs.
func TestStaleROA(t *testing.T) {
	r, v, irr := staleFixture()
	ev := &events{}
	d := newDetector(r, v, irr, ev, Feed{Name: "radar-export", Plugin: fakeFeed{}})
	d.Scan(t.Context())
	st := d.Status()
	if len(st.Cases) != 1 {
		t.Fatalf("cases = %+v", st.Cases)
	}
	c := st.Cases[0]
	if c.Prefix != fixture || c.Origin != 64500 || c.Class != ClassStaleROA || c.RPKISource != "routinator" || len(c.Paths) != 2 || len(c.VRPs) != 1 {
		t.Fatalf("case = %+v", c)
	}
	// irr_route 2 + irr_as_set 1 + origin_stable 2 + roa_same_origin 1 + providers 1 + hijack_feeds 1
	if c.Score != 8 {
		t.Fatalf("score = %d, signals %+v", c.Score, c.Signals)
	}
	for name, pts := range map[string]int{"irr_route": 2, "irr_as_set": 1, "origin_stable": 2, "roa_same_origin": 1, "providers": 1, "hijack_feeds": 1} {
		if s := signal(c, name); s.Points != pts || s.Detail == "" {
			t.Errorf("%s = %+v, want %d points", name, s, pts)
		}
	}
	if !strings.Contains(signal(c, "roa_same_origin").Detail, "ROA 198.51.100.0/22 maxLength 22 authorizes AS64500") {
		t.Errorf("roa detail: %s", signal(c, "roa_same_origin").Detail)
	}
	if !strings.Contains(c.Action, "Contact the holder of 198.51.100.0/24") {
		t.Errorf("action: %s", c.Action)
	}
	if k := ev.kinds(); !slices.Equal(k, []string{plugin.EventRPKIOnlyInvalid}) {
		t.Fatalf("events = %v", k)
	}
	f := ev.list[0].Fields
	if f["prefix"] != "198.51.100.0/24" || f["class"] != ClassStaleROA || !strings.Contains(f["evidence"], "irr_route +2: AS64500 has a route object") {
		t.Fatalf("event fields = %v", f)
	}
	d.Scan(t.Context())
	if k := ev.kinds(); len(k) != 1 {
		t.Fatalf("a second scan re-fired: %v", k)
	}
}

// #401 acceptance: the same prefix from a conflicting origin, with a
// hijack feed hit, is a likely hijack.
func TestHijack(t *testing.T) {
	r, v, irr := staleFixture()
	r.paths[fixture] = nil
	r.add("198.51.100.0/24", "transit-a", t0.Add(-2*time.Hour), 64496, 64511)
	r.add("198.51.100.0/24", "transit-b", t0.Add(-90*24*time.Hour), 64497, 64500)
	ev := &events{}
	feed := fakeFeed{list: []plugin.HijackIncident{{Prefix: fixture, Origin: 64511, Detail: "possible origin hijack"}}}
	d := newDetector(r, v, irr, ev, Feed{Name: "radar-export", Plugin: feed})
	d.Scan(t.Context())
	c, ok := d.Case(fixture)
	if !ok || c.Origin != 64511 || c.Class != ClassHijack {
		t.Fatalf("case = %+v %v", c, ok)
	}
	if s := signal(c, "hijack_feeds"); s.Points != -4 || !strings.Contains(s.Detail, "radar-export reports an incident for 198.51.100.0/24 from AS64511: possible origin hijack") {
		t.Fatalf("feed signal = %+v", s)
	}
	if s := signal(c, "providers"); s.Points != -2 || !strings.Contains(s.Detail, "conflicting origin: paths also end in AS64500") {
		t.Fatalf("providers signal = %+v", s)
	}
	if s := signal(c, "irr_route"); s.Points != -2 || !strings.Contains(s.Detail, "name AS64500, not AS64511") {
		t.Fatalf("irr signal = %+v", s)
	}
	if !strings.Contains(c.Action, "Do not add an exception") {
		t.Fatalf("action: %s", c.Action)
	}
}

// #401 acceptance: an invalid route with a valid alternative path, or
// under a valid covering route, is no alert.
func TestValidAlternativeNoAlert(t *testing.T) {
	r, v, irr := staleFixture()
	r.add("198.51.100.0/24", "transit-c", t0, 64498, 64502)
	v.vrps.Apply([]rpki.Change{{Prefix: fixture, MaxLen: 24, ASN: 64502}})
	ev := &events{}
	d := newDetector(r, v, irr, ev)
	d.Scan(t.Context())
	if st := d.Status(); len(st.Cases) != 0 || len(ev.kinds()) != 0 {
		t.Fatalf("valid alternative path alerted: %+v %v", st.Cases, ev.kinds())
	}

	r, v, irr = staleFixture()
	r.add("198.51.100.0/22", "transit-a", t0, 64496, 64500)
	d = newDetector(r, v, irr, ev)
	d.Scan(t.Context())
	if st := d.Status(); len(st.Cases) != 0 || len(ev.kinds()) != 0 {
		t.Fatalf("valid covering route alerted: %+v %v", st.Cases, ev.kinds())
	}

	// An invalid covering route does not reach the destination either.
	r, v, irr = staleFixture()
	r.add("198.51.100.0/23", "transit-a", t0, 64496, 64500)
	d = newDetector(r, v, irr, ev)
	d.Scan(t.Context())
	if _, ok := d.Case(fixture); !ok {
		t.Fatal("an invalid covering route hid the case")
	}
	if _, ok := d.Case(netip.MustParsePrefix("198.51.100.0/23")); !ok {
		t.Fatal("the invalid /23 is its own case")
	}
}

// A case clears when the route becomes valid, and a RIB or RPKI outage is
// never read as the case clearing.
func TestClearsOnlyOnFreshData(t *testing.T) {
	r, v, irr := staleFixture()
	ev := &events{}
	d := newDetector(r, v, irr, ev)
	d.Scan(t.Context())
	v.updated = time.Time{}
	d.Scan(t.Context())
	r.ready = false
	v.updated = t0
	d.Scan(t.Context())
	if _, ok := d.Case(fixture); !ok || d.Status().Note != "the learned RIB is not ready" {
		t.Fatalf("outage cleared the case: %+v", d.Status())
	}
	r.ready = true
	v.vrps.Apply([]rpki.Change{{Prefix: fixture, MaxLen: 24, ASN: 64500}})
	d.Scan(t.Context())
	if k := ev.kinds(); !slices.Equal(k, []string{plugin.EventRPKIOnlyInvalid, plugin.EventRPKIOnlyInvalidCleared}) {
		t.Fatalf("events = %v", k)
	}
}

// A scan cut short at maxCases does not reach the routes past the last one
// it inspects, so their cases stay open and nothing clears.
func TestCutShortScanKeepsUninspectedCases(t *testing.T) {
	r := newRIB()
	v := newRPKI()
	for i := range maxCases {
		p := netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 6: byte(i >> 8), 7: byte(i)}), 64)
		r.add(p.String(), "transit-a", t0.Add(-time.Hour), 64496, 64501)
		v.vrps.Apply([]rpki.Change{{Prefix: p, MaxLen: 64, ASN: 64499}})
	}
	last := netip.MustParsePrefix("2001:db8:ffff::/48")
	r.add(last.String(), "transit-a", t0.Add(-time.Hour), 64496, 64502)
	v.vrps.Apply([]rpki.Change{{Prefix: last, MaxLen: 48, ASN: 64499}})
	ev := &events{}
	d := newDetector(r, v, nil, ev)
	d.Scan(t.Context())
	if _, ok := d.Case(last); ok || d.Status().Note == "" {
		t.Fatalf("first scan inspected past maxCases: %q", d.Status().Note)
	}
	delete(r.paths, netip.MustParsePrefix("2001:db8::/64"))
	d.Scan(t.Context())
	if _, ok := d.Case(last); !ok || len(d.Status().Cases) != maxCases || d.Status().Note != "" {
		t.Fatalf("the case moved into range is not open: %d cases, note %q", len(d.Status().Cases), d.Status().Note)
	}

	// A new invalid prefix that sorts first (IPv4 before IPv6) pushes the
	// last case past the cut; it stays open and no cleared event is sent.
	first := netip.MustParsePrefix("192.0.2.0/24")
	r.add(first.String(), "transit-a", t0.Add(-time.Hour), 64496, 64503)
	v.vrps.Apply([]rpki.Change{{Prefix: first, MaxLen: 24, ASN: 64499}})
	before := len(ev.kinds())
	d.Scan(t.Context())
	if _, ok := d.Case(last); !ok || d.Status().Note == "" {
		t.Fatalf("the uninspected case was dropped: note %q", d.Status().Note)
	}
	if _, ok := d.Case(first); !ok {
		t.Fatal("the new case is not open")
	}
	if k := ev.kinds()[before:]; !slices.Equal(k, []string{plugin.EventRPKIOnlyInvalid}) {
		t.Fatalf("events = %v", k)
	}

	// Once the route is inspected again and is valid, it clears.
	delete(r.paths, first)
	v.vrps.Apply([]rpki.Change{{Prefix: last, MaxLen: 48, ASN: 64502}})
	before = len(ev.kinds())
	d.Scan(t.Context())
	if _, ok := d.Case(last); ok {
		t.Fatal("a valid route stayed open")
	}
	if k := ev.kinds()[before:]; !slices.Contains(k, plugin.EventRPKIOnlyInvalidCleared) {
		t.Fatalf("events = %v", k)
	}
}

// Without IRR, history, or feeds the evidence is thin: the case is still
// reported, as unclear, and each missing source says so.
func TestUnclearWithoutEvidence(t *testing.T) {
	r := newRIB()
	r.add("198.51.100.0/24", "transit-a", t0.Add(-time.Hour), 64496, 64500)
	v := newRPKI(plugin.RPKIVRP{Prefix: fixture, MaxLen: 24, ASN: 64499})
	ev := &events{}
	d := newDetector(r, v, nil, ev, Feed{Name: "down", Plugin: fakeFeed{err: errors.New("unreachable")}})
	d.Scan(t.Context())
	c, ok := d.Case(fixture)
	if !ok || c.Class != ClassUnclear || c.Score != 0 {
		t.Fatalf("case = %+v", c)
	}
	for name, want := range map[string]string{"irr_route": "irr is off", "hijack_feeds": "no feed answered: down",
		"roa_same_origin": "no ROA names AS64500; covering ROAs name AS64499", "origin_stable": "under stable_after"} {
		if s := signal(c, name); !strings.Contains(s.Detail, want) {
			t.Errorf("%s = %+v, want %q", name, s, want)
		}
	}
}

// A same-origin ROA with a short max length, provider agreement, and a
// quiet feed reach the score but not the class: a forged-origin
// sub-prefix hijack looks the same until the IRR or the route age agrees.
func TestStaleNeedsIRROrHistory(t *testing.T) {
	r, v, _ := staleFixture()
	for i := range r.paths[fixture] {
		r.paths[fixture][i].Age = t0.Add(-time.Hour)
	}
	d := newDetector(r, v, nil, &events{}, Feed{Name: "f", Plugin: fakeFeed{}})
	d.Scan(t.Context())
	c, _ := d.Case(fixture)
	if c.Score != 3 || c.Class != ClassUnclear {
		t.Fatalf("case = %+v", c)
	}
	r.paths[fixture][0].Age = t0.Add(-60 * 24 * time.Hour)
	d.Scan(t.Context())
	if c, _ = d.Case(fixture); c.Score != 5 || c.Class != ClassStaleROA {
		t.Fatalf("with history: %+v", c)
	}
}
