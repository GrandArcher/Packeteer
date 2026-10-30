// Package registry is registry hygiene (#289): a scheduled, read-only scan
// that compares what the network announces with IRR route objects, RPKI
// ROAs, the operator's as-set, and PeeringDB, and lists each difference
// with the exact change that would fix it. A change is applied only by an
// explicit, confirmed push, and pushing is off by default. The package
// never announces and never changes the learned RIB.
package registry

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Defaults and bounds.
const (
	DefaultInterval = 24 * time.Hour
	MinInterval     = time.Hour
	MaxInterval     = 7 * 24 * time.Hour
	DefaultHeadroom = 20
	MaxHeadroom     = 1000
	// firstScanDelay lets the RIB learn before the first scan; an empty
	// view would read as every prefix unregistered.
	firstScanDelay = time.Minute
	// maxInspect bounds the per-prefix IRR lookups of one scan, which are
	// rate-limited by the IRR sources.
	maxInspect = 500
	// maxFindings bounds the report.
	maxFindings = 1000
	// maxPerKind bounds the findings of one kind from one section.
	maxPerKind = 200
	// scanTimeout bounds one scan.
	scanTimeout = time.Hour
)

// Errors returned by Push.
var (
	ErrPushOff       = errors.New("registry.push_enabled is off")
	ErrNotFound      = errors.New("no such finding in the last scan")
	ErrNotPushable   = errors.New("this finding has no change a registry plugin can apply")
	ErrDigestChanged = errors.New("the change differs from the one shown; reload the diff")
	ErrAlreadyPushed = errors.New("this change was already pushed; the next scan shows the result")
)

// Config is the scan setup (registry block).
type Config struct {
	ASNs        []uint32
	ASSet       string
	Interval    time.Duration
	Headroom    int
	IRRSource   string
	MntBy       string
	PushEnabled bool
}

// IRRSource is one irr.sources entry.
type IRRSource struct {
	Name   string
	Plugin plugin.IRR
}

// Checker is one registry.sources entry.
type Checker struct {
	Name   string
	Type   string
	Plugin plugin.RegistryChecker
}

// RPKI is the validation view the scan reads: *rpki.Set.
type RPKI interface {
	Enabled() bool
	Lookup(prefix netip.Prefix, origin uint32) plugin.RPKIAnswer
	Covering(prefix netip.Prefix) []plugin.RPKIVRP
}

// Observed is what the network does now.
type Observed struct {
	// Ready is false until the learned RIB is complete enough to compare.
	Ready bool
	// Announced maps each learned prefix whose origin is one of the
	// configured ASNs to that origin.
	Announced map[netip.Prefix]uint32
	// Downstream are the ASNs that follow a configured ASN on a learned
	// AS path: the customer cone seen as transit.
	Downstream map[uint32]bool
	Sessions   []plugin.RegistrySession
}

// Deps are what the service reads and writes.
type Deps struct {
	Observe  func() Observed
	IRR      []IRRSource
	RPKI     RPKI
	Checkers []Checker
	Log      *slog.Logger
	Now      func() time.Time
}

// Finding is a plugin finding plus what the API needs to confirm a push.
type Finding struct {
	plugin.RegistryFinding
	// Pushable is true when a push is on and a plugin applies the change.
	Pushable bool `json:"pushable"`
	// Digest identifies the exact change shown. A push must quote it.
	Digest string `json:"digest,omitempty"`
	// Pushed is when a confirmed push of this exact change succeeded.
	Pushed *time.Time `json:"pushed,omitempty"`
	// Note says why a change is not offered yet.
	Note string `json:"note,omitempty"`
}

// pushRecord remembers what was pushed. A later scan that needs a
// different change for the same drift is not "already pushed".
type pushRecord struct {
	at     time.Time
	digest string
}

// Section is the outcome of one part of a scan.
type Section struct {
	Name string `json:"name"`
	// Status is ok, skipped, or error.
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Report is the last scan.
type Report struct {
	Scanned     time.Time `json:"scanned,omitempty"`
	PushEnabled bool      `json:"push_enabled"`
	Sections    []Section `json:"sections"`
	Findings    []Finding `json:"findings"`
}

// Service runs the scan and applies confirmed pushes.
type Service struct {
	cfg  Config
	deps Deps
	asns map[uint32]bool

	mu     sync.Mutex
	report Report
	pushed map[string]pushRecord

	// pushMu serializes pushes: one registry write at a time.
	pushMu sync.Mutex
}

// New returns a service. Call Run to start the schedule.
func New(cfg Config, deps Deps) *Service {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Log == nil {
		deps.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Interval == 0 {
		cfg.Interval = DefaultInterval
	}
	cfg.IRRSource = strings.ToUpper(cfg.IRRSource)
	s := &Service{cfg: cfg, deps: deps, asns: map[uint32]bool{}, pushed: map[string]pushRecord{}}
	for _, a := range cfg.ASNs {
		s.asns[a] = true
	}
	s.report = Report{PushEnabled: cfg.PushEnabled, Sections: []Section{}, Findings: []Finding{}}
	return s
}

// Run scans after a short delay and then every interval until ctx ends.
func (s *Service) Run(ctx context.Context) {
	wait := firstScanDelay
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		sctx, cancel := context.WithTimeout(ctx, scanTimeout)
		s.Scan(sctx)
		cancel()
		wait = s.cfg.Interval
	}
}

// Report returns a copy of the last scan.
func (s *Service) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.report
	r.Sections = slices.Clone(r.Sections)
	r.Findings = slices.Clone(r.Findings)
	for i := range r.Findings {
		if rec, ok := s.pushed[r.Findings[i].ID]; ok && rec.digest == r.Findings[i].Digest {
			t := rec.at
			r.Findings[i].Pushed = &t
		}
	}
	return r
}

// Scan reads the registries once and replaces the report. A part that
// cannot answer is reported as such and produces no findings, so an
// unreachable registry is never read as a clean one.
func (s *Service) Scan(ctx context.Context) {
	obs := s.deps.Observe()
	var found []plugin.RegistryFinding
	var secs []Section
	add := func(fs []plugin.RegistryFinding, sec Section) {
		found = append(found, fs...)
		secs = append(secs, sec)
	}
	if !obs.Ready || len(obs.Announced) == 0 {
		detail := "the learned RIB has no prefix originated by registry.asns yet"
		if !obs.Ready {
			detail = "the learned RIB is not ready"
		}
		secs = append(secs, Section{Name: "network", Status: "skipped", Detail: detail})
	} else {
		add(s.scanIRR(ctx, obs))
		add(s.scanRPKI(obs))
		add(s.scanASSet(ctx, obs))
	}
	facts := s.facts(obs)
	for _, c := range s.deps.Checkers {
		fs, err := c.Plugin.Check(ctx, facts)
		if err != nil {
			s.deps.Log.Warn("registry check failed", "registry", c.Name, "err", err)
			secs = append(secs, Section{Name: c.Name, Status: "error", Detail: err.Error()})
			continue
		}
		add(fs, Section{Name: c.Name, Status: "ok"})
	}
	slices.SortStableFunc(found, func(a, b plugin.RegistryFinding) int {
		return cmp.Or(severityRank(a.Severity)-severityRank(b.Severity), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Subject, b.Subject))
	})
	if len(found) > maxFindings {
		secs = append(secs, Section{Name: "report", Status: "ok", Detail: fmt.Sprintf("the %d most severe of %d findings are listed", maxFindings, len(found))})
		found = found[:maxFindings]
	}
	r := Report{Scanned: s.deps.Now().UTC(), PushEnabled: s.cfg.PushEnabled, Sections: secs, Findings: make([]Finding, 0, len(found))}
	s.mu.Lock()
	seen := map[string]bool{}
	for _, f := range s.report.Findings {
		seen[f.ID] = true
	}
	s.mu.Unlock()
	for _, f := range found {
		r.Findings = append(r.Findings, s.finish(f, seen))
	}
	s.mu.Lock()
	s.report = r
	keep := map[string]pushRecord{}
	for _, f := range r.Findings {
		if rec, ok := s.pushed[f.ID]; ok {
			keep[f.ID] = rec
		}
	}
	s.pushed = keep
	s.mu.Unlock()
}

func severityRank(s string) int {
	switch s {
	case plugin.RegistryError:
		return 0
	case plugin.RegistryWarning:
		return 1
	}
	return 2
}

// facts is what the checkers compare against.
func (s *Service) facts(obs Observed) plugin.RegistryFacts {
	f := plugin.RegistryFacts{
		ASNs: slices.Clone(s.cfg.ASNs), Sessions: obs.Sessions, Headroom: s.cfg.Headroom,
		Announced4: map[uint32]int{}, Announced6: map[uint32]int{},
	}
	for p, origin := range obs.Announced {
		if p.Addr().Is4() {
			f.Announced4[origin]++
		} else {
			f.Announced6[origin]++
		}
	}
	return f
}

// finish gives a finding its ID and, when a push could apply it, the digest
// that confirms it. A change nothing can apply is dropped: the diff stays.
// A delete is offered only when the previous scan showed the same finding:
// the learned RIB is ready once one session is up, so a scan right after a
// session flap sees a partial table and would call live objects stale.
func (s *Service) finish(f plugin.RegistryFinding, seen map[string]bool) Finding {
	f.ID = findingID(f)
	out := Finding{RegistryFinding: f}
	if f.Change == nil {
		return out
	}
	switch {
	case !s.cfg.PushEnabled || s.checker(f.Change.Registry) == nil:
		out.Change = nil
	case f.Change.Op == "delete_object" && !seen[f.ID]:
		out.Change = nil
		out.Note = "A delete is offered once the next scan shows it again."
	default:
		out.Pushable, out.Digest = true, changeDigest(*f.Change)
	}
	return out
}

func (s *Service) checker(typ string) *Checker {
	for i := range s.deps.Checkers {
		if s.deps.Checkers[i].Type == typ {
			return &s.deps.Checkers[i]
		}
	}
	return nil
}

func findingID(f plugin.RegistryFinding) string {
	sum := sha256.Sum256([]byte(f.Kind + "\x00" + f.Subject))
	return hex.EncodeToString(sum[:6])
}

func changeDigest(c plugin.RegistryChange) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{c.Registry, c.Op, c.Class, c.Key, c.Object, c.Field, c.Old, c.New}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// Push applies the change of finding id, when push_enabled is on and digest
// is the one the report showed. It returns the change applied. The caller
// audit-logs it.
func (s *Service) Push(ctx context.Context, id, digest string) (plugin.RegistryChange, error) {
	if !s.cfg.PushEnabled {
		return plugin.RegistryChange{}, ErrPushOff
	}
	s.pushMu.Lock()
	defer s.pushMu.Unlock()
	var f *Finding
	r := s.Report()
	for i := range r.Findings {
		if r.Findings[i].ID == id {
			f = &r.Findings[i]
		}
	}
	switch {
	case f == nil:
		return plugin.RegistryChange{}, ErrNotFound
	case f.Pushed != nil:
		return plugin.RegistryChange{}, ErrAlreadyPushed
	case !f.Pushable || f.Change == nil:
		return plugin.RegistryChange{}, ErrNotPushable
	case f.Digest != digest:
		return plugin.RegistryChange{}, ErrDigestChanged
	}
	c := s.checker(f.Change.Registry)
	if c == nil {
		return plugin.RegistryChange{}, ErrNotPushable
	}
	if err := c.Plugin.Push(ctx, *f.Change); err != nil {
		return *f.Change, fmt.Errorf("%s: %w", c.Name, err)
	}
	s.mu.Lock()
	s.pushed[id] = pushRecord{at: s.deps.Now().UTC(), digest: f.Digest}
	s.mu.Unlock()
	s.deps.Log.Info("registry change pushed", "registry", c.Name, "finding", f.Kind, "subject", f.Subject)
	return *f.Change, nil
}
