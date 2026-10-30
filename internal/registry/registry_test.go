package registry

import (
	"context"
	"errors"
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
	err      error
	noOrigin bool
}

func (f *fakeIRR) Routes(_ context.Context, p netip.Prefix) ([]plugin.IRRRoute, time.Time, error) {
	return f.routes[p], time.Time{}, f.err
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
	svc := newService(Config{IRRSource: "ripe", MntBy: "EXAMPLE-MNT", PushEnabled: true}, Deps{
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
	if len(stale) != 1 || stale[0].Subject != "192.0.2.0/24 AS64496 RIPE" || stale[0].Change == nil || stale[0].Change.Op != "delete_object" {
		t.Fatalf("irr_stale = %+v", stale)
	}
	conf := got["irr_conflict"]
	if len(conf) != 1 || conf[0].Subject != "198.51.100.0/24 AS64499 RADB" || conf[0].Change != nil {
		t.Fatalf("irr_conflict = %+v", conf)
	}
	dup := got["irr_duplicate"]
	if len(dup) != 1 || dup[0].Subject != "198.51.100.0/24 AS64496 RADB" || dup[0].Change != nil || dup[0].Pushable {
		t.Fatalf("irr_duplicate = %+v (a RADB copy is text to submit, not a push)", dup)
	}
	if !strings.HasPrefix(dup[0].Diff, "- route:") || !strings.Contains(dup[0].Diff, "source:         RADB") {
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
		"no plugin": {Config{IRRSource: "RIPE", PushEnabled: true}, nil},
		"radb":      {Config{IRRSource: "RADB", PushEnabled: true}, []Checker{{Name: "ripe", Type: "ripe", Plugin: &fakeChecker{}}}},
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
