package onlyinvalid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds.
const (
	// DefaultReviewAfter is slurm.review_after when it is not set. An
	// exception is never re-checked once its case clears, and it stays in
	// the file after Packeteer stops, so the reminder is on unless turned
	// off.
	DefaultReviewAfter = 30 * 24 * time.Hour
	// MinReviewAfter and MaxReviewAfter bound slurm.review_after.
	MinReviewAfter = 24 * time.Hour
	MaxReviewAfter = 365 * 24 * time.Hour
	// proposalTTL is how long a proposal can be approved.
	proposalTTL = time.Hour
	// maxProposals bounds the proposals kept; the oldest goes first.
	maxProposals = 64
)

// Exception kinds.
const (
	KindAssertion = "prefix_assertion"
	KindFilter    = "prefix_filter"
)

// Audit actions.
const (
	ActionPropose = "rpki.slurm.propose"
	ActionApprove = "rpki.slurm.approve"
	ActionWrite   = "rpki.slurm.write"
	ActionRemove  = "rpki.slurm.remove"
)

// Errors returned by Propose, Approve, and Remove.
var (
	ErrNoCase      = errors.New("no open RPKI-invalid only path for this prefix")
	ErrNotStale    = errors.New("only a case classed stale_roa can get an exception")
	ErrNotAllowed  = errors.New("the prefix is outside rpki.only_invalid.slurm.prefixes")
	ErrExists      = errors.New("the SLURM file already has this exception")
	ErrNoProposal  = errors.New("no such proposal, or it expired; propose again")
	ErrDigest      = errors.New("the SLURM entries differ from the ones shown; propose again")
	ErrNoException = errors.New("no such exception in the SLURM file")
	ErrFile        = errors.New("the SLURM file cannot be used")
)

// SLURMConfig is the slurm block.
type SLURMConfig struct {
	// Path is the file Packeteer writes and the RTR cache reads.
	Path string
	// Prefixes are the only prefixes an exception may cover.
	Prefixes []netip.Prefix
	// ReviewAfter, when set, raises rpki.slurm_review for an exception
	// older than it.
	ReviewAfter time.Duration
}

// Actor is who asked, for the audit log.
type Actor struct {
	User   string
	Role   plugin.Role
	Method string
	Remote string
}

// Auditor writes the audit log: *auth.Auditor. Record returns the record
// with its ID.
type Auditor interface {
	Record(ctx context.Context, r plugin.AuditRecord) plugin.AuditRecord
}

// Proposal is a SLURM change waiting for an admin. Entries is exactly what
// approval adds to the file.
type Proposal struct {
	// ID is the audit record of the proposal, which the entry comments
	// reference.
	ID      string              `json:"id"`
	Digest  string              `json:"digest"`
	Prefix  netip.Prefix        `json:"prefix"`
	Origin  uint32              `json:"origin"`
	Kind    string              `json:"kind"`
	Entries json.RawMessage     `json:"entries"`
	Before  plugin.RPKIValidity `json:"state_before"`
	After   plugin.RPKIValidity `json:"state_after"`
	Path    string              `json:"path"`
	Expires time.Time           `json:"expires"`
	// Evidence is the case as it was proposed.
	Evidence Case `json:"evidence"`

	doc     SLURM
	comment string
}

// Exception is one entry of the SLURM file.
type Exception struct {
	ID        string        `json:"id"`
	Kind      string        `json:"kind"`
	Prefix    *netip.Prefix `json:"prefix,omitempty"`
	ASN       *uint32       `json:"asn,omitempty"`
	MaxLength *uint8        `json:"max_length,omitempty"`
	Comment   string        `json:"comment,omitempty"`
	// AuditID and Date are read from a comment Packeteer wrote; empty
	// for an entry added by hand.
	AuditID   string    `json:"audit_id,omitempty"`
	Date      time.Time `json:"date,omitzero"`
	ReviewDue bool      `json:"review_due,omitempty"`
}

// Exceptions proposes, writes, and removes SLURM entries. The file is read
// before every change, so an entry added by hand is kept.
type Exceptions struct {
	cfg   SLURMConfig
	det   *Detector
	audit Auditor

	mu        sync.Mutex
	proposals map[string]Proposal
	reminded  map[string]bool
}

// NewExceptions returns the exceptions of the file in cfg. The file is
// read and validated before every change, and one that is not valid SLURM
// is never overwritten.
func NewExceptions(cfg SLURMConfig, det *Detector, audit Auditor) *Exceptions {
	return &Exceptions{cfg: cfg, det: det, audit: audit, proposals: map[string]Proposal{}, reminded: map[string]bool{}}
}

// Path is the SLURM file.
func (e *Exceptions) Path() string { return e.cfg.Path }

// Prefixes are the prefixes an exception may cover.
func (e *Exceptions) Prefixes() []netip.Prefix { return e.cfg.Prefixes }

var commentRE = regexp.MustCompile(`^packeteer audit=([0-9a-f]+) date=([^ ]+):`)

func (e *Exceptions) read() (SLURM, error) {
	b, err := os.ReadFile(e.cfg.Path)
	if errors.Is(err, os.ErrNotExist) {
		return emptySLURM(), nil
	}
	if err != nil {
		return SLURM{}, fmt.Errorf("%w: %v", ErrFile, err)
	}
	doc, err := ParseSLURM(b)
	if err == nil {
		err = doc.Validate()
	}
	if err != nil {
		return SLURM{}, fmt.Errorf("%w: %s: %v", ErrFile, e.cfg.Path, err)
	}
	return doc, nil
}

// write replaces the file atomically. It is world-readable: the RTR cache
// runs as another user and the file holds no secret.
func (e *Exceptions) write(doc SLURM) error {
	if err := doc.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrFile, err)
	}
	dir := filepath.Dir(e.cfg.Path)
	tmp, err := os.CreateTemp(dir, ".slurm-*")
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFile, err)
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(doc.Marshal())
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), e.cfg.Path)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFile, err)
	}
	return nil
}

func assertionID(a PrefixAssertion) string {
	v := a.VRP()
	return entryID(KindAssertion, v.Prefix.String(), fmt.Sprint(v.ASN), fmt.Sprint(v.MaxLen))
}

func filterID(f PrefixFilter) string {
	p, asn := "", ""
	if f.Prefix != nil {
		p = f.Prefix.String()
	}
	if f.ASN != nil {
		asn = fmt.Sprint(*f.ASN)
	}
	return entryID(KindFilter, p, asn)
}

func entryID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:6])
}

func (e *Exceptions) exceptions(doc SLURM, now time.Time) []Exception {
	out := []Exception{}
	add := func(x Exception) {
		if m := commentRE.FindStringSubmatch(x.Comment); m != nil {
			x.AuditID = m[1]
			if t, err := time.Parse(time.RFC3339, m[2]); err == nil {
				x.Date = t
				x.ReviewDue = e.cfg.ReviewAfter > 0 && now.Sub(t) >= e.cfg.ReviewAfter
			}
		}
		out = append(out, x)
	}
	for _, a := range doc.Assertions.Prefix {
		p, asn, ml := a.Prefix, a.ASN, a.VRP().MaxLen
		add(Exception{ID: assertionID(a), Kind: KindAssertion, Prefix: &p, ASN: &asn, MaxLength: &ml, Comment: a.Comment})
	}
	for _, f := range doc.Filters.Prefix {
		add(Exception{ID: filterID(f), Kind: KindFilter, Prefix: f.Prefix, ASN: f.ASN, Comment: f.Comment})
	}
	return out
}

// List is every entry of the file now.
func (e *Exceptions) List() ([]Exception, error) {
	doc, err := e.read()
	if err != nil {
		return nil, err
	}
	return e.exceptions(doc, e.det.deps.Now()), nil
}

// Held is the prefixes of cases whose exception is already in the file.
func (e *Exceptions) Held(cases []Case) ([]netip.Prefix, error) {
	doc, err := e.read()
	if err != nil {
		return nil, err
	}
	held := []netip.Prefix{}
	for _, c := range cases {
		if add, _ := entries(c, ""); has(doc, add) {
			held = append(held, c.Prefix)
		}
	}
	return held, nil
}

// File is the file as an RTR cache would read it, or an empty SLURM
// document before the first approval.
func (e *Exceptions) File() ([]byte, error) {
	doc, err := e.read()
	if err != nil {
		return nil, err
	}
	return doc.Marshal(), nil
}

// entries is the change that fits the case. When every ROA covering the
// prefix is AS0 (RFC 7607), the stale data is the AS0 payloads and they are
// filtered. Otherwise the observed origin is asserted for exactly the
// prefix, which keeps every other origin invalid.
func entries(c Case, comment string) (SLURM, string) {
	doc := emptySLURM()
	if allAS0(c) {
		seen := map[netip.Prefix]bool{}
		for _, v := range c.VRPs {
			if seen[v.Prefix] {
				continue
			}
			seen[v.Prefix] = true
			p, zero := v.Prefix, uint32(0)
			doc.Filters.Prefix = append(doc.Filters.Prefix, PrefixFilter{Prefix: &p, ASN: &zero, Comment: comment})
		}
		return doc, KindFilter
	}
	ml := uint8(c.Prefix.Bits())
	doc.Assertions.Prefix = append(doc.Assertions.Prefix, PrefixAssertion{ASN: c.Origin, Prefix: c.Prefix, MaxLength: &ml, Comment: comment})
	return doc, KindAssertion
}

func allAS0(c Case) bool {
	for _, v := range c.VRPs {
		if v.ASN != 0 {
			return false
		}
	}
	return len(c.VRPs) > 0
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func (e *Exceptions) record(ctx context.Context, who Actor, action, target, result, detail string) plugin.AuditRecord {
	return e.audit.Record(ctx, plugin.AuditRecord{Actor: who.User, Role: who.Role, Method: who.Method, Remote: who.Remote,
		Action: action, Target: target, Result: result, Detail: detail})
}

// openCase is the case for prefix that may get an exception.
func (e *Exceptions) openCase(prefix netip.Prefix) (Case, error) {
	c, ok := e.det.Case(prefix)
	switch {
	case !ok:
		return Case{}, ErrNoCase
	case c.Class != ClassStaleROA:
		return Case{}, ErrNotStale
	case !netpfx.CoveredBy(e.cfg.Prefixes, c.Prefix):
		return Case{}, ErrNotAllowed
	}
	// A prefixFilter drops every payload under the ROA's own prefix, so a
	// ROA wider than the allowlist would reach past it.
	if allAS0(c) {
		for _, v := range c.VRPs {
			if !netpfx.CoveredBy(e.cfg.Prefixes, v.Prefix) {
				return Case{}, fmt.Errorf("%w: the AS0 ROA %s is wider than it", ErrNotAllowed, v.Prefix)
			}
		}
	}
	return c, nil
}

// has reports whether doc already holds every entry of add.
func has(doc, add SLURM) bool {
	ids := map[string]bool{}
	for _, x := range doc.Assertions.Prefix {
		ids[assertionID(x)] = true
	}
	for _, x := range doc.Filters.Prefix {
		ids[filterID(x)] = true
	}
	for _, x := range add.Assertions.Prefix {
		if !ids[assertionID(x)] {
			return false
		}
	}
	for _, x := range add.Filters.Prefix {
		if !ids[filterID(x)] {
			return false
		}
	}
	return true
}

// Propose builds the SLURM entries for the open case of prefix and audits
// the proposal with its evidence. It writes nothing.
func (e *Exceptions) Propose(ctx context.Context, who Actor, prefix netip.Prefix) (Proposal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c, err := e.openCase(prefix)
	if err != nil {
		return Proposal{}, err
	}
	cur, err := e.read()
	if err != nil {
		return Proposal{}, err
	}
	probe, kind := entries(c, "")
	if has(cur, probe) {
		return Proposal{}, ErrExists
	}
	now := e.det.deps.Now().UTC()
	rec := e.record(ctx, who, ActionPropose, c.Prefix.String(), "ok",
		fmt.Sprintf("proposed %s for %s AS%d, written only after an admin approves; evidence: %s", kind, c.Prefix, c.Origin, c.Evidence()))
	comment := fmt.Sprintf("packeteer audit=%s date=%s: %s AS%d, %s", rec.ID, now.Format(time.RFC3339), c.Prefix, c.Origin, classText(c.Class))
	doc, _ := entries(c, comment)
	text := doc.Marshal()
	before, after := states(c, doc)
	p := Proposal{ID: rec.ID, Digest: digest(text), Prefix: c.Prefix, Origin: c.Origin, Kind: kind, Entries: json.RawMessage(text),
		Before: before, After: after,
		Path: e.cfg.Path, Expires: now.Add(proposalTTL), Evidence: c, doc: doc, comment: comment}
	e.pruneLocked(now)
	e.proposals[p.ID] = p
	return p, nil
}

// states is the validity of the case's route before and after doc, from
// the ROAs covering it.
func states(c Case, doc SLURM) (before, after plugin.RPKIValidity) {
	vrps := make([]plugin.RPKIVRP, 0, len(c.VRPs))
	for _, v := range c.VRPs {
		vrps = append(vrps, plugin.RPKIVRP{Prefix: v.Prefix, MaxLen: v.MaxLength, ASN: v.ASN})
	}
	return validity(vrps, c.Prefix, c.Origin), validity(doc.Apply(vrps), c.Prefix, c.Origin)
}

func (e *Exceptions) pruneLocked(now time.Time) {
	var oldest string
	for id, p := range e.proposals {
		if !now.Before(p.Expires) {
			delete(e.proposals, id)
			continue
		}
		if oldest == "" || p.Expires.Before(e.proposals[oldest].Expires) {
			oldest = id
		}
	}
	if len(e.proposals) >= maxProposals {
		delete(e.proposals, oldest)
	}
}

// Approve adds the entries of proposal id to the file. digest must be the
// one shown with the proposal, and the case must still be a likely stale
// ROA. The approval and the write are audited with the evidence.
func (e *Exceptions) Approve(ctx context.Context, who Actor, id, dig string) (Proposal, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.det.deps.Now().UTC()
	p, ok := e.proposals[id]
	switch {
	case !ok || !now.Before(p.Expires):
		return Proposal{}, ErrNoProposal
	case p.Digest != dig:
		return Proposal{}, ErrDigest
	}
	c, err := e.openCase(p.Prefix)
	if err != nil {
		return p, err
	}
	if c.Origin != p.Origin {
		return p, ErrNoCase
	}
	// The covering ROAs may have changed since the proposal; what is
	// written must be what the admin reviewed.
	fresh, _ := entries(c, p.comment)
	if before, after := states(c, fresh); digest(fresh.Marshal()) != p.Digest || before != p.Before || after != p.After {
		return p, ErrDigest
	}
	cur, err := e.read()
	if err != nil {
		return p, err
	}
	if has(cur, p.doc) {
		delete(e.proposals, id)
		return p, ErrExists
	}
	compact := strings.Join(strings.Fields(string(p.Entries)), " ")
	cur.Assertions.Prefix = append(cur.Assertions.Prefix, p.doc.Assertions.Prefix...)
	cur.Filters.Prefix = append(cur.Filters.Prefix, p.doc.Filters.Prefix...)
	werr := e.write(cur)
	result := "ok"
	if werr != nil {
		result = "failed"
	}
	e.record(ctx, who, ActionApprove, p.Prefix.String(), result,
		fmt.Sprintf("approved proposal %s digest %s: %s; evidence: %s", p.ID, p.Digest, compact, c.Evidence()))
	if werr != nil {
		e.record(ctx, who, ActionWrite, e.cfg.Path, "failed", fmt.Sprintf("proposal %s not written: %v; evidence: %s", p.ID, werr, c.Evidence()))
		return p, werr
	}
	e.record(ctx, who, ActionWrite, e.cfg.Path, "ok",
		fmt.Sprintf("wrote proposal %s for %s AS%d: %d prefix assertions and %d prefix filters in the file now; added %s; evidence: %s",
			p.ID, p.Prefix, p.Origin, len(cur.Assertions.Prefix), len(cur.Filters.Prefix), compact, c.Evidence()))
	delete(e.proposals, id)
	return p, nil
}

// Remove deletes one entry from the file and audits it with the entry and
// the current evidence for its prefix.
func (e *Exceptions) Remove(ctx context.Context, who Actor, id string) (Exception, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cur, err := e.read()
	if err != nil {
		return Exception{}, err
	}
	now := e.det.deps.Now().UTC()
	var gone *Exception
	for _, x := range e.exceptions(cur, now) {
		if x.ID == id {
			gone = &x
			break
		}
	}
	if gone == nil {
		return Exception{}, ErrNoException
	}
	cur.Assertions.Prefix = slices.DeleteFunc(cur.Assertions.Prefix, func(a PrefixAssertion) bool { return assertionID(a) == id })
	cur.Filters.Prefix = slices.DeleteFunc(cur.Filters.Prefix, func(f PrefixFilter) bool { return filterID(f) == id })
	entry, _ := json.Marshal(gone)
	if err := e.write(cur); err != nil {
		e.record(ctx, who, ActionRemove, e.cfg.Path, "failed", fmt.Sprintf("exception %s not removed: %v; evidence: %s", id, err, e.evidenceFor(*gone)))
		return *gone, err
	}
	e.record(ctx, who, ActionRemove, e.cfg.Path, "ok", fmt.Sprintf("removed %s; evidence: %s", entry, e.evidenceFor(*gone)))
	delete(e.reminded, id)
	return *gone, nil
}

func (e *Exceptions) evidenceFor(x Exception) string {
	if x.Prefix == nil {
		return "the entry names no prefix"
	}
	if c, ok := e.det.Case(*x.Prefix); ok {
		return c.Evidence()
	}
	if x.ASN == nil {
		return fmt.Sprintf("no open case for %s", x.Prefix)
	}
	a := e.det.deps.RPKI.Lookup(*x.Prefix, *x.ASN)
	return fmt.Sprintf("no open case for %s; AS%d is %s now (source %s, with the exception installed)", x.Prefix, *x.ASN, a.State, a.Source)
}

// Remind raises rpki.slurm_review once per run for each exception past
// review_after. Without review_after it does nothing.
func (e *Exceptions) Remind() {
	if e.cfg.ReviewAfter == 0 {
		return
	}
	list, err := e.List()
	if err != nil {
		e.det.deps.Log.Warn("slurm review check", "err", err)
		return
	}
	now := e.det.deps.Now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, x := range list {
		if !x.ReviewDue || e.reminded[x.ID] {
			continue
		}
		e.reminded[x.ID] = true
		target := ""
		if x.Prefix != nil {
			target = x.Prefix.String()
		}
		e.det.deps.Emit(plugin.NewEvent(plugin.EventRPKISLURMReview, now,
			fmt.Sprintf("SLURM exception %s %s from %s is older than review_after %s: check whether the ROA is fixed and remove it", x.Kind, target, x.Date.Format(time.DateOnly), e.cfg.ReviewAfter),
			map[string]string{"id": x.ID, "prefix": target, "audit_id": x.AuditID, "path": e.cfg.Path}))
	}
}
