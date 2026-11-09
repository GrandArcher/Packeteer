package registry

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

type fakeIRR struct {
	plugin.Base
	byOrigin map[uint32][]netip.Prefix
	routes   map[netip.Prefix][]plugin.IRRRoute
	sets     map[string][]uint32
	// texts is the stored object text by database; unset ones get a short
	// object.
	texts     map[string]string
	err       error
	routesErr error
	noOrigin  bool
	noText    bool
}

func (f *fakeIRR) Routes(_ context.Context, p netip.Prefix) ([]plugin.IRRRoute, time.Time, error) {
	return f.routes[p], time.Time{}, cmp.Or(f.routesErr, f.err)
}

func (f *fakeIRR) RouteObjects(ctx context.Context, p netip.Prefix) ([]plugin.IRRObject, time.Time, error) {
	if f.noText {
		return nil, time.Time{}, plugin.ErrIRRUnsupported
	}
	routes, at, err := f.Routes(ctx, p)
	var out []plugin.IRRObject
	for _, rt := range routes {
		text := f.texts[rt.Database]
		if text == "" {
			text = fmt.Sprintf("route: %s\norigin: AS%d\nsource: %s\n", rt.Prefix, rt.Origin, rt.Database)
		}
		out = append(out, plugin.IRRObject{IRRRoute: rt, Text: text})
	}
	return out, at, err
}

func (f *fakeIRR) OriginPrefixes(_ context.Context, asn uint32) ([]netip.Prefix, time.Time, error) {
	if f.noOrigin {
		return nil, time.Time{}, plugin.ErrIRRUnsupported
	}
	return f.byOrigin[asn], time.Time{}, f.err
}

func (f *fakeIRR) ASSetMembers(_ context.Context, name string) ([]uint32, time.Time, error) {
	return f.sets[name], time.Time{}, f.err
}

func (f *fakeIRR) ASName(context.Context, uint32) (string, time.Time, error) {
	return "", time.Time{}, nil
}

type fakeRPKI struct {
	state map[netip.Prefix]plugin.RPKIValidity
	vrps  []plugin.RPKIVRP
}

func (f *fakeRPKI) Enabled() bool { return true }
func (f *fakeRPKI) Lookup(p netip.Prefix, _ uint32) plugin.RPKIAnswer {
	return plugin.RPKIAnswer{State: f.state[p]}
}
func (f *fakeRPKI) Covering(netip.Prefix) []plugin.RPKIVRP { return f.vrps }

type fakeChecker struct {
	plugin.Base
	findings []plugin.RegistryFinding
	err      error
	facts    plugin.RegistryFacts
	pushed   []plugin.RegistryChange
	pushErr  error
}

func (f *fakeChecker) Check(_ context.Context, facts plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	f.facts = facts
	return f.findings, f.err
}

func (f *fakeChecker) Push(_ context.Context, c plugin.RegistryChange) error {
	if f.pushErr != nil {
		return f.pushErr
	}
	f.pushed = append(f.pushed, c)
	return nil
}

func observed() Observed {
	return Observed{
		Ready: true,
		Announced: map[netip.Prefix]uint32{
			pfx("198.51.100.0/24"): 64496,
			pfx("203.0.113.0/24"):  64496,
			pfx("2001:db8::/32"):   64496,
		},
		Downstream: map[uint32]bool{64510: true, 64511: true},
	}
}

func byKind(r Report) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range r.Findings {
		out[f.Kind] = append(out[f.Kind], f)
	}
	return out
}

func section(r Report, name string) Section {
	for _, s := range r.Sections {
		if s.Name == name {
			return s
		}
	}
	return Section{}
}

func newService(cfg Config, deps Deps) *Service {
	if cfg.ASNs == nil {
		cfg.ASNs = []uint32{64496}
	}
	if deps.Observe == nil {
		deps.Observe = observed
	}
	return New(cfg, deps)
}

// #289: a prefix announced with no route object is a finding with the exact
// RPSL to submit; an object for a prefix no longer announced is stale; a
// foreign origin and a copy left in a second database are flagged. In the
// RIPE database the fixes are pushable only when push is on and a ripe
// plugin exists.
func TestScanIRR(t *testing.T) {
	ripe := &fakeIRR{
		byOrigin: map[uint32][]netip.Prefix{64496: {pfx("198.51.100.0/24"), pfx("2001:db8::/32"), pfx("192.0.2.0/24")}},
		routes: map[netip.Prefix][]plugin.IRRRoute{
			pfx("198.51.100.0/24"): {{Prefix: pfx("198.51.100.0/24"), Origin: 64496, Database: "RIPE"}, {Prefix: pfx("198.51.100.0/24"), Origin: 64496, Database: "RADB"}, {Prefix: pfx("198.51.100.0/24"), Origin: 64499, Database: "RADB"}},
			pfx("192.0.2.0/24"):    {{Prefix: pfx("192.0.2.0/24"), Origin: 64496, Database: "RIPE"}},
		},
	}
	chk := &fakeChecker{}
	svc := newService(Config{IRRSource: "ripe", PushDB: "RIPE", MntBy: "EXAMPLE-MNT", PushEnabled: true}, Deps{
		IRR:      []IRRSource{{Name: "ripe", Plugin: ripe}},
		Checkers: []Checker{{Name: "ripe", Type: "ripe", Plugin: chk}},
	})
	svc.Scan(context.Background())
	r := svc.Report()
	got := byKind(r)

	if sec := section(r, "irr"); sec.Status != "ok" {
		t.Fatalf("irr section = %+v", sec)
	}
	miss := got["irr_missing"]
	if len(miss) != 1 || miss[0].Subject != "203.0.113.0/24 AS64496" || miss[0].Severity != plugin.RegistryWarning {
		t.Fatalf("irr_missing = %+v", miss)
	}
	wantObj := "route:          203.0.113.0/24\ndescr:          Announced by AS64496\norigin:         AS64496\nmnt-by:         EXAMPLE-MNT\nsource:         RIPE\n"
	c := miss[0].Change
	if c == nil || c.Registry != "ripe" || c.Op != "create_object" || c.Class != "route" || c.Key != "203.0.113.0/24AS64496" || c.Object != wantObj {
		t.Fatalf("irr_missing change = %+v", c)
	}
	if !miss[0].Pushable || miss[0].Digest == "" {
		t.Fatalf("missing is not pushable: %+v", miss[0])
	}
	if !strings.HasPrefix(miss[0].Diff, "+ route:") || !strings.Contains(miss[0].Diff, "\n+ origin:         AS64496") {
		t.Fatalf("diff = %q", miss[0].Diff)
	}

	stale := got["irr_stale"]
	if len(stale) != 1 || stale[0].Subject != "192.0.2.0/24 AS64496 RIPE" || stale[0].Diff == "" {
		t.Fatalf("irr_stale = %+v", stale)
	}
	if stale[0].Change != nil || stale[0].Pushable || stale[0].Note == "" {
		t.Fatalf("a delete seen once must not be offered: %+v", stale[0])
	}
	svc.Scan(context.Background())
	stale = byKind(svc.Report())["irr_stale"]
	if len(stale) != 1 || !stale[0].Pushable || stale[0].Change == nil || stale[0].Change.Op != "delete_object" || stale[0].Change.Key != "192.0.2.0/24AS64496" {
		t.Fatalf("a delete seen in two scans is offered: %+v", stale)
	}
	conf := got["irr_conflict"]
	if len(conf) != 1 || conf[0].Subject != "198.51.100.0/24 AS64499 RADB" || conf[0].Change != nil {
		t.Fatalf("irr_conflict = %+v", conf)
	}
	dup := got["irr_duplicate"]
	if len(dup) != 1 || dup[0].Subject != "198.51.100.0/24 AS64496 RADB" || dup[0].Change != nil || dup[0].Pushable {
		t.Fatalf("irr_duplicate = %+v (a RADB copy is text to submit, not a push)", dup)
	}
	if dup[0].Diff != "- route: 198.51.100.0/24\n- origin: AS64496\n- source: RADB" {
		t.Fatalf("duplicate diff = %q", dup[0].Diff)
	}
}

// #289: with push off, or without a ripe plugin, or with another IRR
// source, the diff is still shown and nothing is pushable.
func TestIRRFindingsNotPushable(t *testing.T) {
	src := &fakeIRR{byOrigin: map[uint32][]netip.Prefix{64496: {pfx("198.51.100.0/24"), pfx("2001:db8::/32")}}}
	cases := map[string]struct {
		cfg      Config
		checkers []Checker
	}{
		"push off":  {Config{IRRSource: "RIPE"}, []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}}},
		"no plugin": {Config{IRRSource: "RIPE", PushDB: "RIPE", PushEnabled: true}, nil},
		"radb":      {Config{IRRSource: "RADB", PushDB: "RIPE", PushEnabled: true}, []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}}},
		"other db":  {Config{IRRSource: "RIPE", PushDB: "TEST", PushEnabled: true}, []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}}},
	}
	for name, tc := range cases {
		svc := newService(tc.cfg, Deps{IRR: []IRRSource{{Name: "x", Plugin: src}}, Checkers: tc.checkers})
		svc.Scan(context.Background())
		miss := byKind(svc.Report())["irr_missing"]
		if len(miss) != 1 || miss[0].Pushable || miss[0].Change != nil || miss[0].Digest != "" || miss[0].Diff == "" {
			t.Errorf("%s: %+v", name, miss)
		}
	}
}

// #289: a source that fails, or cannot list by origin, never produces a
// finding: an unreachable registry is not a clean one.
func TestIRRSourceFailure(t *testing.T) {
	good := &fakeIRR{byOrigin: map[uint32][]netip.Prefix{}}
	bad := &fakeIRR{err: errors.New("connection refused")}
	svc := newService(Config{}, Deps{IRR: []IRRSource{{Name: "good", Plugin: good}, {Name: "bad", Plugin: bad}}})
	svc.Scan(context.Background())
	r := svc.Report()
	if sec := section(r, "irr"); sec.Status != "error" || !strings.Contains(sec.Detail, "source bad did not answer") {
		t.Fatalf("section = %+v", sec)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("findings from a partial view: %+v", r.Findings)
	}

	svc = newService(Config{}, Deps{IRR: []IRRSource{{Name: "file", Plugin: &fakeIRR{noOrigin: true}}}})
	svc.Scan(context.Background())
	if sec := section(svc.Report(), "irr"); sec.Status != "skipped" {
		t.Fatalf("unsupported-only section = %+v", sec)
	}
}

// #289: before the RIB is ready, or when it holds no route of the ASNs,
// nothing is compared.
func TestScanNeedsRIB(t *testing.T) {
	for name, obs := range map[string]Observed{
		"not ready": {},
		"empty":     {Ready: true},
	} {
		svc := newService(Config{}, Deps{Observe: func() Observed { return obs }, IRR: []IRRSource{{Name: "x", Plugin: &fakeIRR{}}}})
		svc.Scan(context.Background())
		r := svc.Report()
		if sec := section(r, "network"); sec.Status != "skipped" || len(r.Findings) != 0 || section(r, "irr").Name != "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

// #289: RPKI findings say whether no ROA covers the prefix, a ROA's
// maxLength is too short, or no ROA names the origin; they are never
// pushable.
func TestScanRPKI(t *testing.T) {
	rp := &fakeRPKI{
		state: map[netip.Prefix]plugin.RPKIValidity{
			pfx("198.51.100.0/24"): plugin.RPKIValid,
			pfx("203.0.113.0/24"):  plugin.RPKINotFound,
			pfx("2001:db8::/32"):   plugin.RPKIInvalid,
		},
		vrps: []plugin.RPKIVRP{{Prefix: pfx("2001:db8::/32"), MaxLen: 31, ASN: 64496}},
	}
	svc := newService(Config{PushEnabled: true}, Deps{RPKI: rp, Checkers: []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}}})
	svc.Scan(context.Background())
	r := svc.Report()
	got := byKind(r)
	if m := got["rpki_missing"]; len(m) != 1 || m[0].Diff != "+ ROA prefix 203.0.113.0/24, origin AS64496, maxLength 24" || m[0].Pushable {
		t.Fatalf("rpki_missing = %+v", m)
	}
	ml := got["rpki_maxlength"]
	if len(ml) != 1 || ml[0].Severity != plugin.RegistryError || ml[0].Pushable ||
		ml[0].Diff != "- ROA prefix 2001:db8::/32, origin AS64496, maxLength 31\n+ ROA prefix 2001:db8::/32, origin AS64496, maxLength 32" {
		t.Fatalf("rpki_maxlength = %+v", ml)
	}
	if len(got) != 2 {
		t.Fatalf("valid prefix produced a finding: %+v", got)
	}

	rp.vrps = []plugin.RPKIVRP{{Prefix: pfx("2001:db8::/32"), MaxLen: 48, ASN: 64499}}
	svc.Scan(context.Background())
	if o := byKind(svc.Report())["rpki_origin"]; len(o) != 1 || o[0].Message != "ROAs cover 2001:db8::/32 but none authorizes AS64496" {
		t.Fatalf("rpki_origin = %+v", o)
	}

	// Every answer unknown (no fresh cache): skipped, not clean.
	rp.state = nil
	svc.Scan(context.Background())
	r = svc.Report()
	if sec := section(r, "rpki"); sec.Status != "skipped" || len(r.Findings) != 0 {
		t.Fatalf("unknown rpki = %+v %+v", sec, r.Findings)
	}
}

// #289: ASNs seen after ours on learned paths that the as-set lacks are
// missing members; members never seen are listed as info only.
func TestScanASSet(t *testing.T) {
	src := &fakeIRR{
		byOrigin: map[uint32][]netip.Prefix{64496: {pfx("198.51.100.0/24"), pfx("203.0.113.0/24"), pfx("2001:db8::/32")}},
		sets:     map[string][]uint32{"AS-EXAMPLE": {64496, 64510, 64520}},
	}
	svc := newService(Config{ASSet: "AS-EXAMPLE"}, Deps{IRR: []IRRSource{{Name: "x", Plugin: src}}})
	svc.Scan(context.Background())
	got := byKind(svc.Report())
	miss := got["asset_missing"]
	if len(miss) != 1 || miss[0].Subject != "AS-EXAMPLE AS64511" || miss[0].Diff != "as-set: AS-EXAMPLE\n+ members: AS64511\n" {
		t.Fatalf("asset_missing = %+v", miss)
	}
	un := got["asset_unseen"]
	if len(un) != 1 || un[0].Subject != "AS-EXAMPLE AS64520" || un[0].Severity != plugin.RegistryInfo || un[0].Diff != "as-set: AS-EXAMPLE\n- members: AS64520\n" {
		t.Fatalf("asset_unseen = %+v", un)
	}

	// An unknown customer cone would call every member unseen: skipped.
	svc = newService(Config{ASSet: "AS-EXAMPLE"}, Deps{IRR: []IRRSource{{Name: "x", Plugin: src}}, Observe: func() Observed {
		o := observed()
		o.NoCone = "provider transit-a has no asn"
		return o
	}})
	svc.Scan(context.Background())
	r := svc.Report()
	if sec := section(r, "as-set"); sec.Status != "skipped" || sec.Detail != "provider transit-a has no asn" || len(byKind(r)["asset_unseen"]) != 0 {
		t.Fatalf("as-set without a cone = %+v %+v", sec, r.Findings)
	}
}

// #289: plugin findings are merged, a failing plugin is a section error,
// and findings sort by severity.
func TestScanCheckers(t *testing.T) {
	ok := &fakeChecker{findings: []plugin.RegistryFinding{
		{Kind: "pdb_contact", Severity: plugin.RegistryInfo, Subject: "AS64496 contact"},
		{Kind: "pdb_maxprefix", Severity: plugin.RegistryError, Subject: "AS64496 info_prefixes4"},
	}}
	bad := &fakeChecker{err: errors.New("HTTP 503")}
	svc := newService(Config{Headroom: 25}, Deps{Checkers: []Checker{{Name: "peeringdb", Type: "peeringdb", Plugin: ok}, {Name: "other", Type: "other", Plugin: bad}}})
	svc.Scan(context.Background())
	r := svc.Report()
	if len(r.Findings) != 2 || r.Findings[0].Kind != "pdb_maxprefix" || r.Findings[1].Kind != "pdb_contact" {
		t.Fatalf("findings = %+v", r.Findings)
	}
	if sec := section(r, "other"); sec.Status != "error" || sec.Detail != "HTTP 503" {
		t.Fatalf("section = %+v", sec)
	}
	if ok.facts.Announced4[64496] != 2 || ok.facts.Announced6[64496] != 1 || ok.facts.Headroom != 25 || !slices.Equal(ok.facts.ASNs, []uint32{64496}) {
		t.Fatalf("facts = %+v", ok.facts)
	}
}

func pushService(t *testing.T, pushEnabled bool) (*Service, *fakeChecker, string) {
	t.Helper()
	chk := &fakeChecker{findings: []plugin.RegistryFinding{{
		Kind: "pdb_maxprefix", Severity: plugin.RegistryWarning, Subject: "AS64496 info_prefixes4",
		Change: &plugin.RegistryChange{Registry: "peeringdb", Op: "update_field", Class: "net", Key: "42", Field: "info_prefixes4", Old: "1", New: "3"},
	}}}
	svc := newService(Config{PushEnabled: pushEnabled}, Deps{Checkers: []Checker{{Name: "peeringdb", Type: "peeringdb", Plugin: chk}}})
	svc.Scan(context.Background())
	r := svc.Report()
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %+v", r.Findings)
	}
	return svc, chk, r.Findings[0].ID
}

// #289: a push needs push_enabled, the digest of the diff that was shown,
// and happens once; the plugin gets exactly the shown change.
func TestPush(t *testing.T) {
	ctx := context.Background()

	svc, chk, id := pushService(t, false)
	if f := svc.Report().Findings[0]; f.Pushable || f.Change != nil || f.Digest != "" {
		t.Fatalf("push off yet pushable: %+v", f)
	}
	if _, err := svc.Push(ctx, id, "x"); !errors.Is(err, ErrPushOff) || len(chk.pushed) != 0 {
		t.Fatalf("push off: %v, pushed %v", err, chk.pushed)
	}

	svc, chk, id = pushService(t, true)
	f := svc.Report().Findings[0]
	if !f.Pushable || f.Digest == "" || f.Change == nil {
		t.Fatalf("not pushable: %+v", f)
	}
	if _, err := svc.Push(ctx, id, "0000"); !errors.Is(err, ErrDigestChanged) {
		t.Fatalf("wrong digest: %v", err)
	}
	if _, err := svc.Push(ctx, "nope", f.Digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if len(chk.pushed) != 0 {
		t.Fatalf("pushed before a valid confirm: %v", chk.pushed)
	}
	c, err := svc.Push(ctx, id, f.Digest)
	if err != nil || len(chk.pushed) != 1 || chk.pushed[0] != *f.Change || c != *f.Change {
		t.Fatalf("push = %+v %v, plugin got %v", c, err, chk.pushed)
	}
	if p := svc.Report().Findings[0].Pushed; p == nil {
		t.Fatal("report does not show the push")
	}
	if _, err := svc.Push(ctx, id, f.Digest); !errors.Is(err, ErrAlreadyPushed) || len(chk.pushed) != 1 {
		t.Fatalf("second push: %v, pushed %v", err, chk.pushed)
	}

	// A failing plugin leaves the finding open.
	svc, chk, id = pushService(t, true)
	chk.pushErr = errors.New("HTTP 403")
	if _, err = svc.Push(ctx, id, svc.Report().Findings[0].Digest); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("plugin error = %v", err)
	}
	if svc.Report().Findings[0].Pushed != nil {
		t.Fatal("a failed push is shown as done")
	}
}

// #289: a finding with no change is suggest-only.
func TestPushNotPushable(t *testing.T) {
	chk := &fakeChecker{findings: []plugin.RegistryFinding{{Kind: "pdb_facility", Severity: plugin.RegistryWarning, Subject: "AS64496 facilities"}}}
	svc := newService(Config{PushEnabled: true}, Deps{Checkers: []Checker{{Name: "peeringdb", Type: "peeringdb", Plugin: chk}}})
	svc.Scan(context.Background())
	f := svc.Report().Findings[0]
	if _, err := svc.Push(context.Background(), f.ID, f.Digest); !errors.Is(err, ErrNotPushable) {
		t.Fatalf("err = %v", err)
	}
}

// #289: a copy of our object is "left over" only beside the object in the
// configured home database. With objects in RADB and ARIN and home RIPE,
// following both delete diffs would remove every registration.
func TestDuplicateNeedsHomeObject(t *testing.T) {
	p := pfx("198.51.100.0/24")
	src := &fakeIRR{
		byOrigin: map[uint32][]netip.Prefix{64496: {p, pfx("203.0.113.0/24"), pfx("2001:db8::/32")}},
		routes: map[netip.Prefix][]plugin.IRRRoute{p: {
			{Prefix: p, Origin: 64496, Database: "RADB"}, {Prefix: p, Origin: 64496, Database: "ARIN"},
		}},
	}
	svc := newService(Config{IRRSource: "RIPE"}, Deps{IRR: []IRRSource{{Name: "x", Plugin: src}}})
	svc.Scan(context.Background())
	if dup := byKind(svc.Report())["irr_duplicate"]; len(dup) != 0 {
		t.Fatalf("duplicates without an object in the home database: %+v", dup)
	}
	src.routes[p] = append(src.routes[p], plugin.IRRRoute{Prefix: p, Origin: 64496, Database: "RIPE"})
	svc.Scan(context.Background())
	if dup := byKind(svc.Report())["irr_duplicate"]; len(dup) != 2 {
		t.Fatalf("duplicates beside the home object = %+v", dup)
	}
}

// #289: registry.irr.source TEST with a ripe source writing to TEST makes a
// pushable object.
func TestTestDatabaseChange(t *testing.T) {
	src := &fakeIRR{byOrigin: map[uint32][]netip.Prefix{64496: {pfx("198.51.100.0/24"), pfx("2001:db8::/32")}}}
	svc := newService(Config{IRRSource: "test", PushDB: "TEST", MntBy: "EXAMPLE-MNT", PushEnabled: true}, Deps{
		IRR: []IRRSource{{Name: "x", Plugin: src}}, Checkers: []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}},
	})
	svc.Scan(context.Background())
	miss := byKind(svc.Report())["irr_missing"]
	if len(miss) != 1 || !miss[0].Pushable || miss[0].Change.Registry != "ripe" || !strings.Contains(miss[0].Change.Object, "source:         TEST") {
		t.Fatalf("irr_missing = %+v", miss)
	}
}

// #289: a push is remembered for the change that was pushed. When the
// next scan needs a different value for the same drift, the finding is open
// again instead of showing the old push.
func TestPushedMarkFollowsTheChange(t *testing.T) {
	svc, chk, id := pushService(t, true)
	f := svc.Report().Findings[0]
	if _, err := svc.Push(context.Background(), id, f.Digest); err != nil {
		t.Fatal(err)
	}
	chk.findings[0].Change = &plugin.RegistryChange{Registry: "peeringdb", Op: "update_field", Class: "net", Key: "42", Field: "info_prefixes4", Old: "3", New: "9"}
	svc.Scan(context.Background())
	g := svc.Report().Findings[0]
	if g.ID != id || g.Pushed != nil || g.Digest == f.Digest {
		t.Fatalf("finding after the value moved = %+v", g)
	}
	if _, err := svc.Push(context.Background(), id, g.Digest); err != nil || len(chk.pushed) != 2 {
		t.Fatalf("second change: %v, pushed %v", err, chk.pushed)
	}
}

// #289: a route object for another of our own origins is live when any
// learned path of the prefix has that origin, even if the selected path has
// not. Without the Origins set it would be offered for deletion.
func TestStaleIgnoresOtherOwnOrigin(t *testing.T) {
	p := pfx("198.51.100.0/24")
	src := &fakeIRR{
		byOrigin: map[uint32][]netip.Prefix{64496: {p}, 64497: {p}},
		routes:   map[netip.Prefix][]plugin.IRRRoute{p: {{Prefix: p, Origin: 64496, Database: "RIPE"}, {Prefix: p, Origin: 64497, Database: "RIPE"}}},
	}
	obs := func() Observed {
		return Observed{Ready: true, Announced: map[netip.Prefix]uint32{p: 64496}, Origins: map[netip.Prefix]map[uint32]bool{p: {64496: true}}}
	}
	svc := newService(Config{ASNs: []uint32{64496, 64497}, IRRSource: "RIPE"}, Deps{Observe: obs, IRR: []IRRSource{{Name: "x", Plugin: src}}})
	svc.Scan(context.Background())
	if st := byKind(svc.Report())["irr_stale"]; len(st) != 1 || st[0].Subject != "198.51.100.0/24 AS64497 RIPE" {
		t.Fatalf("with only the selected origin seen, AS64497 is stale: %+v", st)
	}
	svc = newService(Config{ASNs: []uint32{64496, 64497}, IRRSource: "RIPE"}, Deps{
		Observe: func() Observed {
			o := obs()
			o.Origins[p][64497] = true
			return o
		}, IRR: []IRRSource{{Name: "x", Plugin: src}}})
	svc.Scan(context.Background())
	if st := byKind(svc.Report())["irr_stale"]; len(st) != 0 {
		t.Fatalf("an origin seen on another learned path is live: %+v", st)
	}
}

// #289: a leftover copy is text to submit by hand even when it sits in the
// database the ripe source writes to; only the object the scan shows as
// stale or missing is pushed.
func TestDuplicateIsTextOnly(t *testing.T) {
	p := pfx("198.51.100.0/24")
	src := &fakeIRR{
		byOrigin: map[uint32][]netip.Prefix{64496: {p, pfx("203.0.113.0/24"), pfx("2001:db8::/32")}},
		routes: map[netip.Prefix][]plugin.IRRRoute{p: {
			{Prefix: p, Origin: 64496, Database: "RADB"}, {Prefix: p, Origin: 64496, Database: "RIPE"},
		}},
	}
	svc := newService(Config{IRRSource: "RADB", PushDB: "RIPE", MntBy: "EXAMPLE-MNT", PushEnabled: true}, Deps{
		IRR: []IRRSource{{Name: "x", Plugin: src}}, Checkers: []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}},
	})
	for range 2 {
		svc.Scan(context.Background())
	}
	dup := byKind(svc.Report())["irr_duplicate"]
	if len(dup) != 1 || dup[0].Subject != "198.51.100.0/24 AS64496 RIPE" || dup[0].Change != nil || dup[0].Pushable || dup[0].Diff == "" {
		t.Fatalf("irr_duplicate = %+v", dup)
	}
}

// #289: a stale or duplicate object is shown, deleted, and returned for the
// audit as the database stores it, not as our template would write it.
func TestDeleteUsesStoredObject(t *testing.T) {
	stale, live := pfx("192.0.2.0/24"), pfx("198.51.100.0/24")
	ripeText := "route:          192.0.2.0/24\n" +
		"descr:          Customer link, moved in 2025\n" +
		"origin:         AS64496\n" +
		"mnt-by:         OTHER-MNT\n" +
		"mnt-routes:     ROUTES-MNT\n" +
		"remarks:        keep until the contract ends\n" +
		"source:         RIPE\n"
	radbText := "route:      198.51.100.0/24\ndescr:      Old upstream registration\norigin:     AS64496\nmnt-by:     RADB-MNT\nremarks:    added by the previous operator\nsource:     RADB\n"
	src := &fakeIRR{
		byOrigin: map[uint32][]netip.Prefix{64496: {stale, live, pfx("203.0.113.0/24"), pfx("2001:db8::/32")}},
		routes: map[netip.Prefix][]plugin.IRRRoute{
			stale: {{Prefix: stale, Origin: 64496, Database: "RIPE"}},
			live:  {{Prefix: live, Origin: 64496, Database: "RIPE"}, {Prefix: live, Origin: 64496, Database: "RADB"}},
		},
		texts: map[string]string{"RIPE": ripeText, "RADB": radbText},
	}
	chk := &fakeChecker{}
	svc := newService(Config{IRRSource: "RIPE", PushDB: "RIPE", MntBy: "EXAMPLE-MNT", PushEnabled: true}, Deps{
		IRR: []IRRSource{{Name: "x", Plugin: src}}, Checkers: []Checker{{Name: "ripe", Type: "ripe", Plugin: chk}},
	})
	for range 2 {
		svc.Scan(context.Background())
	}
	got := byKind(svc.Report())
	st := got["irr_stale"]
	if len(st) != 1 || !st[0].Pushable || st[0].Change.Object != ripeText || st[0].Change.Key != "192.0.2.0/24AS64496" {
		t.Fatalf("irr_stale = %+v", st)
	}
	wantDiff := "- route:          192.0.2.0/24\n- descr:          Customer link, moved in 2025\n- origin:         AS64496\n- mnt-by:         OTHER-MNT\n- mnt-routes:     ROUTES-MNT\n- remarks:        keep until the contract ends\n- source:         RIPE"
	if st[0].Diff != wantDiff {
		t.Fatalf("stale diff = %q, want %q", st[0].Diff, wantDiff)
	}
	dup := got["irr_duplicate"]
	if len(dup) != 1 || dup[0].Diff != "- "+strings.ReplaceAll(strings.TrimSpace(radbText), "\n", "\n- ") || strings.Contains(dup[0].Diff, "EXAMPLE-MNT") {
		t.Fatalf("irr_duplicate = %+v", dup)
	}
	ch, err := svc.Push(context.Background(), st[0].ID, st[0].Digest)
	if err != nil || ch.Object != ripeText || len(chk.pushed) != 1 || chk.pushed[0].Object != ripeText {
		t.Fatalf("push = %+v %v, plugin got %+v", ch, err, chk.pushed)
	}
}

// #289: when the stored object cannot be read, the finding says so and
// offers no diff and no delete, in any scan.
func TestStaleWithoutStoredObject(t *testing.T) {
	stale := pfx("192.0.2.0/24")
	cases := map[string]struct {
		src  *fakeIRR
		want string
	}{
		"no text": {&fakeIRR{noText: true}, "source x keeps no object text, so no diff or delete is offered"},
		"error":   {&fakeIRR{routesErr: errors.New("connection reset")}, "the object could not be read (x: connection reset), so no delete is offered"},
	}
	for name, tc := range cases {
		tc.src.byOrigin = map[uint32][]netip.Prefix{64496: {stale, pfx("198.51.100.0/24"), pfx("203.0.113.0/24"), pfx("2001:db8::/32")}}
		tc.src.routes = map[netip.Prefix][]plugin.IRRRoute{stale: {{Prefix: stale, Origin: 64496, Database: "RIPE"}}}
		svc := newService(Config{IRRSource: "RIPE", PushDB: "RIPE", PushEnabled: true}, Deps{
			IRR: []IRRSource{{Name: "x", Plugin: tc.src}}, Checkers: []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}},
		})
		for range 2 {
			svc.Scan(context.Background())
		}
		st := byKind(svc.Report())["irr_stale"]
		if len(st) != 1 || st[0].Diff != "" || st[0].Change != nil || st[0].Pushable || !strings.HasSuffix(st[0].Message, tc.want) {
			t.Errorf("%s: irr_stale = %+v", name, st)
		}
	}
}

// #289: before the first scan the report has no scan time at all. A zero
// time.Time would marshal as 0001-01-01 and the page would read as clean, so
// the field is left out of the JSON until a scan has finished.
func TestReportBeforeFirstScanOmitsScanned(t *testing.T) {
	svc := newService(Config{}, Deps{})
	r := svc.Report()
	if !r.Scanned.IsZero() {
		t.Fatalf("Scanned = %v before any scan", r.Scanned)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "scanned") || strings.Contains(string(b), "0001-01-01") {
		t.Fatalf("report before the first scan carries a scan time: %s", b)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("findings before the first scan: %v", r.Findings)
	}
}
