package plugin

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventSpec describes one event kind in the catalog. docs/EVENTS.md is the
// operator-facing copy of this table.
type EventSpec struct {
	// Kind is the dotted name carried in Event.Kind.
	Kind string `json:"kind"`
	// Severity is the default severity.
	Severity Severity `json:"severity"`
	// Summary says when the event fires.
	Summary string `json:"summary"`
	// Group ties a problem to the event that clears it (provider.down and
	// provider.up share "provider"). Keys are the fields that identify one
	// incident inside the group. Together they form Event.DedupKey.
	Group string   `json:"group"`
	Keys  []string `json:"keys,omitempty"`
	// Resolves is true when this kind clears an open problem of its group.
	Resolves bool `json:"resolves,omitempty"`
	// TrapID is the last arc of the SNMP notification OID. It is stable:
	// new kinds get new numbers and numbers are never reused.
	TrapID int `json:"trap_id"`
}

// Event kinds. Every kind the controller emits is in EventCatalog.
const (
	EventControllerStarted  = "controller.started"
	EventControllerStopping = "controller.stopping"
	EventImprovementAdded   = "improvement.added"
	EventImprovementSwitch  = "improvement.switched"
	EventImprovementRemoved = "improvement.removed"
	EventProviderDown       = "provider.down"
	EventProviderUp         = "provider.up"
	EventBGPSessionDown     = "bgp.session_down"
	EventBGPSessionUp       = "bgp.session_up"
	EventCommitExceeded     = "commit.exceeded"
	EventCommitCleared      = "commit.cleared"
	EventAnnounceFailed     = "announce.failed"
	EventAnnounceRecovered  = "announce.recovered"
	EventOutageAS           = "outage.as"
	EventOutageCircuit      = "outage.circuit"
	EventOutageCleared      = "outage.cleared"
	// EventTest is sent by hand to check a notifier's delivery path.
	EventTest = "notifier.test"
)

var eventCatalog = []EventSpec{
	{Kind: EventControllerStarted, Severity: SeverityInfo, Group: "controller", TrapID: 1,
		Summary: "The controller started and its plugins are running.", Resolves: true},
	{Kind: EventControllerStopping, Severity: SeverityWarning, Group: "controller", TrapID: 2,
		Summary: "The controller is shutting down and has withdrawn its routes."},
	{Kind: EventImprovementAdded, Severity: SeverityInfo, Group: "improvement", Keys: []string{"prefix"}, TrapID: 3,
		Summary: "A prefix was steered to a better provider (announced in inject, logged only in observe and suggest)."},
	{Kind: EventImprovementSwitch, Severity: SeverityInfo, Group: "improvement", Keys: []string{"prefix"}, TrapID: 4,
		Summary: "An existing improvement moved to another provider."},
	{Kind: EventImprovementRemoved, Severity: SeverityInfo, Group: "improvement", Keys: []string{"prefix"}, TrapID: 5, Resolves: true,
		Summary: "An improvement was retired: native path recovered, stale data, RIB loss, policy, maintenance, or TTL."},
	{Kind: EventProviderDown, Severity: SeverityCritical, Group: "provider", Keys: []string{"provider"}, TrapID: 6,
		Summary: "A provider's probe source failed. Improvements onto it are withdrawn (fail closed)."},
	{Kind: EventProviderUp, Severity: SeverityInfo, Group: "provider", Keys: []string{"provider"}, TrapID: 7, Resolves: true,
		Summary: "A provider's probe source recovered."},
	{Kind: EventBGPSessionDown, Severity: SeverityCritical, Group: "bgp", Keys: []string{"neighbor"}, TrapID: 8,
		Summary: "An established iBGP session to an edge router went down."},
	{Kind: EventBGPSessionUp, Severity: SeverityInfo, Group: "bgp", Keys: []string{"neighbor"}, TrapID: 9, Resolves: true,
		Summary: "An iBGP session to an edge router reached Established."},
	{Kind: EventCommitExceeded, Severity: SeverityWarning, Group: "commit", Keys: []string{"provider"}, TrapID: 10,
		Summary: "A provider's billable 95th percentile for the open period is above its commit."},
	{Kind: EventCommitCleared, Severity: SeverityInfo, Group: "commit", Keys: []string{"provider"}, TrapID: 11, Resolves: true,
		Summary: "A provider's billable 95th percentile is back at or below its commit."},
	{Kind: EventAnnounceFailed, Severity: SeverityCritical, Group: "announce", TrapID: 12,
		Summary: "Syncing improvements to the announcer failed."},
	{Kind: EventAnnounceRecovered, Severity: SeverityInfo, Group: "announce", TrapID: 13, Resolves: true,
		Summary: "Syncing improvements to the announcer succeeded after a failure."},
	{Kind: EventOutageAS, Severity: SeverityCritical, Group: "outage", Keys: []string{"asn", "provider"}, TrapID: 14,
		Summary: "The outage source found several prefixes degraded behind one ASN on every provider."},
	{Kind: EventOutageCircuit, Severity: SeverityCritical, Group: "outage", Keys: []string{"asn", "provider"}, TrapID: 15,
		Summary: "The outage source found several prefixes degraded on one provider only."},
	{Kind: EventOutageCleared, Severity: SeverityWarning, Group: "outage", Keys: []string{"asn", "provider"}, TrapID: 16, Resolves: true,
		Summary: "An AS or circuit incident recovered."},
	{Kind: EventTest, Severity: SeverityInfo, Group: "notifier", TrapID: 17,
		Summary: "A test event, sent only by -notify-test."},
}

// EventCatalog returns a copy of every event kind the controller emits.
func EventCatalog() []EventSpec {
	out := make([]EventSpec, len(eventCatalog))
	for i, s := range eventCatalog {
		s.Keys = append([]string(nil), s.Keys...)
		out[i] = s
	}
	return out
}

// LookupEvent returns the catalog entry for kind.
func LookupEvent(kind string) (EventSpec, bool) {
	for _, s := range eventCatalog {
		if s.Kind == kind {
			return s, true
		}
	}
	return EventSpec{}, false
}

// NewEvent builds an event with the catalog severity for kind. An unknown
// kind is info.
func NewEvent(kind string, now time.Time, msg string, fields map[string]string) Event {
	sev := SeverityInfo
	if s, ok := LookupEvent(kind); ok {
		sev = s.Severity
	}
	return Event{Time: now, Kind: kind, Severity: sev, Message: msg, Fields: fields}
}

// DedupKey identifies one incident: the catalog group plus the key fields
// that are set. A problem and the event that resolves it share the key,
// so a pager can open and close the same alert. Unknown kinds use the kind.
func (e Event) DedupKey() string {
	s, ok := LookupEvent(e.Kind)
	if !ok {
		return "packeteer/" + e.Kind
	}
	parts := []string{"packeteer", s.Group}
	for _, k := range s.Keys {
		if v := e.Fields[k]; v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "/")
}

// Resolves reports whether e clears an open problem (catalog Resolves).
func (e Event) Resolves() bool {
	s, ok := LookupEvent(e.Kind)
	return ok && s.Resolves
}

var severityRank = map[Severity]int{SeverityInfo: 0, SeverityWarning: 1, SeverityCritical: 2}

// groupRank is the highest severity of the problem kinds in each group. A
// resolving event is filtered at that rank, so whoever was told about
// provider.down (critical) is also told about provider.up (info).
var groupRank = func() map[string]int {
	m := map[string]int{}
	for _, s := range eventCatalog {
		if s.Resolves {
			continue
		}
		if r := severityRank[s.Severity]; r > m[s.Group] {
			m[s.Group] = r
		}
	}
	return m
}()

// SeverityRank orders severities: info < warning < critical.
func SeverityRank(s Severity) (int, bool) {
	r, ok := severityRank[s]
	return r, ok
}

// EventFilter is the per-notifier filter and rate limit. Notifiers embed it
// inline in their config block, so the keys sit next to the plugin's own.
type EventFilter struct {
	// Events lists kinds to deliver. An entry is a kind ("provider.down"),
	// a group wildcard ("improvement.*"), or "*". Empty means every kind.
	Events []string `yaml:"events"`
	// MinSeverity drops events below this level (info, warning, critical).
	MinSeverity Severity `yaml:"min_severity"`
	// RateLimit caps deliveries per RateWindow. Zero is unlimited.
	RateLimit int `yaml:"rate_limit"`
	// RateWindow is the rate-limit window (default 1m).
	RateWindow time.Duration `yaml:"rate_window"`
}

// Rate-limit bounds.
const (
	DefaultRateWindow = time.Minute
	MaxRateLimit      = 100000
	MaxRateWindow     = 24 * time.Hour
)

// EventGate applies an EventFilter. Match is stateless; Allow also spends
// the rate limit. It is safe for concurrent use.
type EventGate struct {
	patterns []string
	min      int
	limit    int
	window   time.Duration

	mu         sync.Mutex
	start      time.Time
	count      int
	suppressed int
}

// NewEventGate validates f. Every pattern must match at least one catalog
// kind, so a typo is a startup error instead of silence.
func NewEventGate(f EventFilter) (*EventGate, error) {
	g := &EventGate{}
	if f.MinSeverity == "" {
		f.MinSeverity = SeverityInfo
	}
	r, ok := SeverityRank(f.MinSeverity)
	if !ok {
		return nil, fmt.Errorf("min_severity %q is invalid (want info, warning, critical)", f.MinSeverity)
	}
	g.min = r
	for i, p := range f.Events {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("events[%d]: empty", i)
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("events[%d]: bad pattern %q", i, p)
		}
		hit := false
		for _, s := range eventCatalog {
			if ok, _ := path.Match(p, s.Kind); ok {
				hit = true
				break
			}
		}
		if !hit {
			return nil, fmt.Errorf("events[%d]: %q matches no event kind (see docs/EVENTS.md)", i, p)
		}
		g.patterns = append(g.patterns, p)
	}
	if f.RateLimit < 0 || f.RateLimit > MaxRateLimit {
		return nil, fmt.Errorf("rate_limit %d must be between 0 and %d", f.RateLimit, MaxRateLimit)
	}
	if f.RateWindow < 0 || f.RateWindow > MaxRateWindow {
		return nil, fmt.Errorf("rate_window %s must be between 0 and %s", f.RateWindow, MaxRateWindow)
	}
	if f.RateWindow > 0 && f.RateWindow < time.Second {
		return nil, fmt.Errorf("rate_window %s must be at least 1s", f.RateWindow)
	}
	if f.RateWindow == 0 {
		f.RateWindow = DefaultRateWindow
	}
	g.limit, g.window = f.RateLimit, f.RateWindow
	return g, nil
}

// Match reports whether e passes the kind and severity filters. A resolving
// kind passes min_severity when the problem it clears would. A nil gate
// matches everything.
func (g *EventGate) Match(e Event) bool {
	if g == nil {
		return true
	}
	if r, ok := SeverityRank(e.Severity); ok && r < g.min {
		s, known := LookupEvent(e.Kind)
		if !known || !s.Resolves || groupRank[s.Group] < g.min {
			return false
		}
	}
	if len(g.patterns) == 0 {
		return true
	}
	for _, p := range g.patterns {
		if ok, _ := path.Match(p, e.Kind); ok {
			return true
		}
	}
	return false
}

// Allow is Match plus the rate limit, in fixed windows. When it returns
// true, suppressed is how many matching events the limit dropped since the
// last delivery, so the receiver can see that it missed some.
func (g *EventGate) Allow(e Event, now time.Time) (ok bool, suppressed int) {
	if g == nil {
		return true, 0
	}
	if !g.Match(e) {
		return false, 0
	}
	if g.limit == 0 {
		return true, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.start.IsZero() || now.Sub(g.start) >= g.window || now.Before(g.start) {
		g.start, g.count = now, 0
	}
	if g.count >= g.limit {
		g.suppressed++
		return false, 0
	}
	g.count++
	suppressed, g.suppressed = g.suppressed, 0
	return true, suppressed
}

// Gated is implemented by notifiers that carry an EventGate. The
// controller's dispatcher consults it before calling Notify, so filters
// and rate limits apply the same way to every notifier type.
type Gated interface {
	EventGate() *EventGate
}

// WithSuppressed returns a copy of e with the suppressed count in Fields.
func (e Event) WithSuppressed(n int) Event {
	if n <= 0 {
		return e
	}
	f := make(map[string]string, len(e.Fields)+1)
	for k, v := range e.Fields {
		f[k] = v
	}
	f["suppressed"] = strconv.Itoa(n)
	e.Fields = f
	return e
}
