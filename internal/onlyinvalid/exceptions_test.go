package onlyinvalid

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	rtrplugin "github.com/GrandArcher/Packeteer/internal/plugins/rpki/rtr"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeAudit struct {
	mu   sync.Mutex
	n    int
	recs []plugin.AuditRecord
}

func (a *fakeAudit) Record(_ context.Context, r plugin.AuditRecord) plugin.AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	r.ID = fmt.Sprintf("a%02d", a.n)
	a.recs = append(a.recs, r)
	return r
}

func (a *fakeAudit) actions() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.recs {
		out = append(out, r.Action+":"+r.Result)
	}
	return out
}

var admin = Actor{User: "admin-user", Role: plugin.RoleAdmin, Method: "password", Remote: "192.0.2.9"}

func newExceptions(t *testing.T, d *Detector, review time.Duration) (*Exceptions, *fakeAudit, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "slurm.json")
	au := &fakeAudit{}
	e := NewExceptions(SLURMConfig{Path: path, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/22")}, ReviewAfter: review}, d, au)
	return e, au, path
}

func staleDetector(t *testing.T) (*Detector, *fakeRPKI, *events) {
	r, v, irr := staleFixture()
	ev := &events{}
	d := newDetector(r, v, irr, ev)
	d.Scan(t.Context())
	return d, v, ev
}

// #401 acceptance: the proposal is valid RFC 8416 SLURM, nothing is
// written until an admin approves the digest shown, and the proposal,
// approval, write, and removal are each audited with the evidence.
func TestProposeApproveRemove(t *testing.T) {
	d, _, _ := staleDetector(t)
	e, au, path := newExceptions(t, d, 0)
	p, err := e.Propose(t.Context(), Actor{User: "ops", Role: plugin.RoleOperator}, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a proposal wrote the file: %v", err)
	}
	doc, err := ParseSLURM(p.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("proposal is not valid SLURM: %v\n%s", err, p.Entries)
	}
	if p.Kind != KindAssertion || len(doc.Assertions.Prefix) != 1 || p.Before != plugin.RPKIInvalid || p.After != plugin.RPKIValid {
		t.Fatalf("proposal = %+v", p)
	}
	a := doc.Assertions.Prefix[0]
	if a.ASN != 64500 || a.Prefix != fixture || *a.MaxLength != 24 || !strings.HasPrefix(a.Comment, "packeteer audit="+p.ID+" date=2026-11-09T12:00:00Z: ") {
		t.Fatalf("assertion = %+v", a)
	}
	for _, s := range []string{`"slurmVersion": 1`, `"prefixFilters": []`, `"bgpsecFilters": []`, `"bgpsecAssertions": []`, `"maxPrefixLength": 24`} {
		if !strings.Contains(string(p.Entries), s) {
			t.Errorf("entries miss %s:\n%s", s, p.Entries)
		}
	}

	if _, err := e.Approve(t.Context(), admin, p.ID, "0000"); !errors.Is(err, ErrDigest) {
		t.Fatalf("wrong digest: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused approval wrote the file")
	}
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != string(p.Entries) {
		t.Fatalf("written file differs from the proposal shown:\n%s\nvs\n%s", b, p.Entries)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); !errors.Is(err, ErrNoProposal) {
		t.Fatalf("approved twice: %v", err)
	}
	if _, err := e.Propose(t.Context(), admin, fixture); !errors.Is(err, ErrExists) {
		t.Fatalf("proposed an exception already in the file: %v", err)
	}
	list, err := e.List()
	if err != nil || len(list) != 1 || list[0].AuditID != p.ID || !list[0].Date.Equal(t0) || list[0].Kind != KindAssertion {
		t.Fatalf("list = %+v %v", list, err)
	}
	if _, err := e.Remove(t.Context(), admin, "nope"); !errors.Is(err, ErrNoException) {
		t.Fatalf("remove unknown: %v", err)
	}
	if _, err := e.Remove(t.Context(), admin, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.List(); len(list) != 0 {
		t.Fatalf("after remove: %+v", list)
	}
	if got := strings.Join(au.actions(), " "); got != "rpki.slurm.propose:ok rpki.slurm.approve:ok rpki.slurm.write:ok rpki.slurm.remove:ok" {
		t.Fatalf("audit = %s", got)
	}
	for _, r := range au.recs {
		if !strings.Contains(r.Detail, "198.51.100.0/24 AS64500 class=stale_roa") {
			t.Errorf("%s has no evidence: %s", r.Action, r.Detail)
		}
	}
	if r := au.recs[1]; r.Actor != "admin-user" || r.Role != plugin.RoleAdmin || !strings.Contains(r.Detail, "digest "+p.Digest) {
		t.Errorf("approval record = %+v", r)
	}
	if r := au.recs[0]; r.Actor != "ops" || !strings.Contains(r.Detail, "written only after an admin approves") {
		t.Errorf("proposal record = %+v", r)
	}
}

// Only a likely stale ROA inside slurm.prefixes may get an exception, and
// a file Packeteer cannot read is never overwritten.
func TestProposeRefusals(t *testing.T) {
	d, _, _ := staleDetector(t)
	e, au, path := newExceptions(t, d, 0)
	if _, err := e.Propose(t.Context(), admin, netip.MustParsePrefix("192.0.2.0/24")); !errors.Is(err, ErrNoCase) {
		t.Fatalf("no case: %v", err)
	}
	e.cfg.Prefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	if _, err := e.Propose(t.Context(), admin, fixture); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("outside prefixes: %v", err)
	}
	e.cfg.Prefixes = []netip.Prefix{fixture}
	if err := os.WriteFile(path, []byte(`{"slurmVersion": 2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Propose(t.Context(), admin, fixture); !errors.Is(err, ErrFile) {
		t.Fatalf("broken file: %v", err)
	}
	if _, err := e.List(); !errors.Is(err, ErrFile) {
		t.Fatalf("list read a broken file: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"slurmVersion": 2}` {
		t.Fatalf("broken file changed: %s", b)
	}
	if len(au.recs) != 0 {
		t.Fatalf("refusals audited as proposals: %v", au.actions())
	}

	r, v, irr := staleFixture()
	r.paths[fixture] = nil
	r.add("198.51.100.0/24", "transit-a", t0, 64496, 64511)
	hd := newDetector(r, v, irr, &events{}, Feed{Name: "f", Plugin: fakeFeed{list: []plugin.HijackIncident{{Prefix: fixture}}}})
	hd.Scan(t.Context())
	he, _, _ := newExceptions(t, hd, 0)
	if _, err := he.Propose(t.Context(), admin, fixture); !errors.Is(err, ErrNotStale) {
		t.Fatalf("hijack case: %v", err)
	}
}

// An entry written by hand is kept across an approval, and the approval
// is refused once the case is no longer a likely stale ROA.
func TestApproveKeepsHandEntries(t *testing.T) {
	d, v, _ := staleDetector(t)
	e, _, path := newExceptions(t, d, 0)
	hand := `{"slurmVersion":1,"validationOutputFilters":{"prefixFilters":[{"asn":64510,"comment":"by hand"}],"bgpsecFilters":[]},` +
		`"locallyAddedAssertions":{"prefixAssertions":[],"bgpsecAssertions":[{"asn":64510,"SKI":"c2tp","routerPublicKey":"a2V5"}]}}`
	if err := os.WriteFile(path, []byte(hand), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := e.Propose(t.Context(), admin, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	doc, err := ParseSLURM(b)
	if err != nil || doc.Validate() != nil || len(doc.Filters.Prefix) != 1 || len(doc.Assertions.Prefix) != 1 || len(doc.Assertions.BGPsec) != 1 {
		t.Fatalf("merged file:\n%s\n%v", b, err)
	}
	list, _ := e.List()
	for _, x := range list {
		if x.Kind == KindFilter && (x.AuditID != "" || *x.ASN != 64510) {
			t.Fatalf("hand entry = %+v", x)
		}
	}

	// The ROA gets fixed before a second proposal is approved.
	e2, _, _ := newExceptions(t, d, 0)
	d.deps.RIB.(*fakeRIB).add("203.0.113.0/24", "transit-a", t0.Add(-90*24*time.Hour), 64496, 64500)
	v.vrps.Apply([]rpki.Change{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), MaxLen: 24, ASN: 64499}})
	e2.cfg.Prefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	d.deps.IRR = irrAnswers(map[netip.Prefix][]uint32{netip.MustParsePrefix("203.0.113.0/24"): {64500}}, 64500)
	d.Scan(t.Context())
	p2, err := e2.Propose(t.Context(), admin, netip.MustParsePrefix("203.0.113.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	v.vrps.Apply([]rpki.Change{{Prefix: netip.MustParsePrefix("203.0.113.0/24"), MaxLen: 24, ASN: 64500}})
	d.Scan(t.Context())
	if _, err := e2.Approve(t.Context(), admin, p2.ID, p2.Digest); !errors.Is(err, ErrNoCase) {
		t.Fatalf("approved after the case cleared: %v", err)
	}
}

// When every covering ROA is AS0 the stale payloads are filtered instead.
func TestAS0Filter(t *testing.T) {
	r := newRIB()
	r.add("198.51.100.0/24", "transit-a", t0.Add(-90*24*time.Hour), 64496, 64500)
	r.add("198.51.100.0/24", "transit-b", t0.Add(-90*24*time.Hour), 64497, 64500)
	v := newRPKI(plugin.RPKIVRP{Prefix: netip.MustParsePrefix("198.51.100.0/22"), MaxLen: 24, ASN: 0})
	d := newDetector(r, v, irrAnswers(map[netip.Prefix][]uint32{fixture: {64500}}, 64500), &events{})
	d.Scan(t.Context())
	e, _, _ := newExceptions(t, d, 0)
	p, err := e.Propose(t.Context(), admin, fixture)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := ParseSLURM(p.Entries)
	if p.Kind != KindFilter || len(doc.Filters.Prefix) != 1 || *doc.Filters.Prefix[0].ASN != 0 || *doc.Filters.Prefix[0].Prefix != netip.MustParsePrefix("198.51.100.0/22") {
		t.Fatalf("proposal = %+v\n%s", p, p.Entries)
	}
	if p.Before != plugin.RPKIInvalid || p.After != plugin.RPKINotFound {
		t.Fatalf("states %s -> %s", p.Before, p.After)
	}
}

func as0Detector(t *testing.T, roa string) (*Detector, *fakeRPKI) {
	t.Helper()
	r := newRIB()
	r.add("198.51.100.0/24", "transit-a", t0.Add(-90*24*time.Hour), 64496, 64500)
	r.add("198.51.100.0/24", "transit-b", t0.Add(-90*24*time.Hour), 64497, 64500)
	v := newRPKI(plugin.RPKIVRP{Prefix: netip.MustParsePrefix(roa), MaxLen: 24, ASN: 0})
	d := newDetector(r, v, irrAnswers(map[netip.Prefix][]uint32{fixture: {64500}}, 64500), &events{})
	d.Scan(t.Context())
	return d, v
}

// An AS0 filter drops every payload under the ROA's prefix, so a ROA wider
// than slurm.prefixes is refused and nothing is audited as a proposal.
func TestAS0FilterStaysInsideAllowlist(t *testing.T) {
	d, _ := as0Detector(t, "198.51.0.0/16")
	e, au, _ := newExceptions(t, d, 0)
	if _, err := e.Propose(t.Context(), admin, fixture); !errors.Is(err, ErrNotAllowed) || !strings.Contains(err.Error(), "198.51.0.0/16") {
		t.Fatalf("wide AS0 ROA: %v", err)
	}
	if len(au.recs) != 0 {
		t.Fatalf("audited: %v", au.actions())
	}
}

// What is written is what the admin reviewed: an AS0 ROA that appears
// after the proposal changes the filters, so the approval is refused.
func TestApproveRefusedWhenROAsChange(t *testing.T) {
	d, v := as0Detector(t, "198.51.100.0/22")
	e, au, path := newExceptions(t, d, 0)
	p, err := e.Propose(t.Context(), admin, fixture)
	if err != nil {
		t.Fatal(err)
	}
	v.vrps.Apply([]rpki.Change{{Prefix: fixture, MaxLen: 24, ASN: 0}})
	d.Scan(t.Context())
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); !errors.Is(err, ErrDigest) {
		t.Fatalf("approve after the ROAs changed: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file written: %v", err)
	}
	if got := strings.Join(au.actions(), " "); got != "rpki.slurm.propose:ok" {
		t.Fatalf("audit = %s", got)
	}
}

// A failed write is audited as a failed approval, not an approval that
// worked.
func TestApproveWriteFailureAudit(t *testing.T) {
	d, _, _ := staleDetector(t)
	e, au, _ := newExceptions(t, d, 0)
	p, err := e.Propose(t.Context(), admin, fixture)
	if err != nil {
		t.Fatal(err)
	}
	e.cfg.Path = filepath.Join(t.TempDir(), "missing", "slurm.json")
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); !errors.Is(err, ErrFile) {
		t.Fatalf("approve: %v", err)
	}
	if got := strings.Join(au.actions(), " "); got != "rpki.slurm.propose:ok rpki.slurm.approve:failed rpki.slurm.write:failed" {
		t.Fatalf("audit = %s", got)
	}
}

// Held names the cases whose exception is in the file, also when an AS0
// filter sits on a wider ROA prefix.
func TestHeld(t *testing.T) {
	d, _ := as0Detector(t, "198.51.100.0/22")
	e, _, _ := newExceptions(t, d, 0)
	cases := d.Status().Cases
	if held, err := e.Held(cases); err != nil || len(held) != 0 {
		t.Fatalf("before approval: %v %v", held, err)
	}
	p, err := e.Propose(t.Context(), admin, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); err != nil {
		t.Fatal(err)
	}
	if held, err := e.Held(cases); err != nil || len(held) != 1 || held[0] != fixture {
		t.Fatalf("after approval: %v %v", held, err)
	}
}

// #401 acceptance: the review reminder fires once for an exception past
// review_after, and without review_after there is none.
func TestReviewReminder(t *testing.T) {
	for _, review := range []time.Duration{0, 30 * 24 * time.Hour} {
		d, _, ev := staleDetector(t)
		e, _, _ := newExceptions(t, d, review)
		p, err := e.Propose(t.Context(), admin, fixture)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); err != nil {
			t.Fatal(err)
		}
		e.Remind()
		d.deps.Now = func() time.Time { return t0.Add(31 * 24 * time.Hour) }
		e.Remind()
		e.Remind()
		var got []plugin.Event
		for _, x := range ev.list {
			if x.Kind == plugin.EventRPKISLURMReview {
				got = append(got, x)
			}
		}
		list, _ := e.List()
		if review == 0 {
			if len(got) != 0 || list[0].ReviewDue {
				t.Fatalf("reminder without review_after: %v %+v", got, list)
			}
			continue
		}
		if len(got) != 1 || got[0].Fields["audit_id"] != p.ID || got[0].Fields["prefix"] != "198.51.100.0/24" || !list[0].ReviewDue {
			t.Fatalf("reminders = %+v, list %+v", got, list)
		}
	}
}

// #401 acceptance: a stub RTR cache that serves its ROAs with the approved
// SLURM file applied, read by the real rtr plugin, turns the fixture route
// from invalid to valid.
func TestStubRTRCacheReadsSLURM(t *testing.T) {
	d, _, _ := staleDetector(t)
	e, _, path := newExceptions(t, d, 0)
	roas := []plugin.RPKIVRP{{Prefix: netip.MustParsePrefix("198.51.100.0/22"), MaxLen: 22, ASN: 64500}}
	check := func() plugin.RPKIValidity {
		set := rpki.NewSet([]plugin.RPKI{startRTR(t, stubCache(t, roas, path))})
		return set.Validate(fixture, 64500)
	}
	if got := check(); got != plugin.RPKIInvalid {
		t.Fatalf("before approval = %s", got)
	}
	p, err := e.Propose(t.Context(), admin, fixture)
	if err != nil {
		t.Fatal(err)
	}
	if got := check(); got != plugin.RPKIInvalid {
		t.Fatalf("a proposal changed the cache: %s", got)
	}
	if _, err := e.Approve(t.Context(), admin, p.ID, p.Digest); err != nil {
		t.Fatal(err)
	}
	if got := check(); got != plugin.RPKIValid {
		t.Fatalf("after approval = %s", got)
	}
}

// stubCache is an RTR (RFC 8210) cache that answers one Reset Query with
// roas after the SLURM file at path, read at that moment, is applied.
func stubCache(t *testing.T, roas []plugin.RPKIVRP, path string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	vrps := roas
	if b, err := os.ReadFile(path); err == nil {
		doc, err := ParseSLURM(b)
		if err != nil || doc.Validate() != nil {
			t.Fatalf("stub cache: %v", err)
		}
		vrps = doc.Apply(roas)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		head := make([]byte, 8)
		if _, err := io.ReadFull(conn, head); err != nil || head[1] != 2 {
			return
		}
		pdu := func(typ byte, session uint16, body []byte) []byte {
			b := make([]byte, 8, 8+len(body))
			b[0], b[1] = 1, typ
			binary.BigEndian.PutUint16(b[2:4], session)
			binary.BigEndian.PutUint32(b[4:8], uint32(8+len(body)))
			return append(b, body...)
		}
		_, _ = conn.Write(pdu(3, 7, nil))
		for _, v := range vrps {
			body := make([]byte, 12)
			body[0], body[1], body[2] = 1, uint8(v.Prefix.Bits()), v.MaxLen
			a := v.Prefix.Addr().As4()
			copy(body[4:8], a[:])
			binary.BigEndian.PutUint32(body[8:12], v.ASN)
			_, _ = conn.Write(pdu(4, 0, body))
		}
		eod := make([]byte, 16)
		binary.BigEndian.PutUint32(eod[0:4], 1)
		binary.BigEndian.PutUint32(eod[4:8], 300)
		binary.BigEndian.PutUint32(eod[8:12], 600)
		binary.BigEndian.PutUint32(eod[12:16], 3600)
		_, _ = conn.Write(pdu(7, 7, eod))
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String()
}

func startRTR(t *testing.T, addr string) plugin.RPKI {
	t.Helper()
	cfg, err := plugin.ConfigFromYAML("address: " + addr + "\nrefresh: 10s\nstaleness: 1h\n")
	if err != nil {
		t.Fatal(err)
	}
	c, err := rtrplugin.New(cfg, plugin.Env{Name: "stub-cache"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := c.Status(); st.Up && !st.Stale && st.VRPs > 0 {
			return c
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("rtr client never loaded the stub cache")
	return nil
}
