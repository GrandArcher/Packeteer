package policy

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Engine wraps Decide with state and makes the latest output available to
// the API. It is safe for concurrent use.
type Engine struct {
	mu     sync.RWMutex
	cfg    Config
	scorer plugin.Scorer
	state  State
	last   Output
	at     time.Time
}

// NewEngine returns an engine with empty state.
func NewEngine(cfg Config, scorer plugin.Scorer) *Engine {
	return &Engine{cfg: cfg, scorer: scorer, state: NewState()}
}

// Evaluate runs Decide and stores the result. It returns the changes.
func (e *Engine) Evaluate(in Input, now time.Time) []Change {
	e.mu.Lock()
	defer e.mu.Unlock()
	st, out := Decide(e.state, in, e.cfg, e.scorer, now)
	e.state, e.last, e.at = st, out, now
	return out.Changes
}

// Quarantined returns the prefixes parked by the flap quarantine, sorted
// by prefix.
func (e *Engine) Quarantined() []Quarantine {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Quarantine, 0, len(e.state.quarantine))
	for _, q := range e.state.quarantine {
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool { return netpfx.Less(out[i].Prefix, out[j].Prefix) })
	return out
}

// QuarantineChanges are the quarantines the latest evaluation started or
// ended.
func (e *Engine) QuarantineChanges() []QuarantineChange {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]QuarantineChange(nil), e.last.Quarantines...)
}

// Release ends a prefix's quarantine at an operator's request. It reports
// false when the prefix is not quarantined. It announces nothing: the next
// evaluation decides the prefix as usual, and a prefix that flips again is
// parked again with a longer cool-down.
func (e *Engine) Release(p netip.Prefix, now time.Time) (Quarantine, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	q, ok := e.state.quarantine[p.Masked()]
	if ok {
		e.state.releaseQuarantine(q.Prefix, now)
	}
	return q, ok
}

// Decisions returns the latest per-prefix decisions and when they were made.
func (e *Engine) Decisions() ([]Decision, time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Decision(nil), e.last.Decisions...), e.at
}

// Urgent returns prefixes whose performance move is waiting on another
// fresh round. The probe engine marks them urgent. Empty when
// confirm_rounds is 1.
func (e *Engine) Urgent() []netip.Prefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]netip.Prefix(nil), e.last.Urgent...)
}

// Improvements returns the active improvements sorted by prefix.
func (e *Engine) Improvements() []Improvement {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Improvement, 0, len(e.state.Improvements))
	for _, p := range sortedKeys(e.state.Improvements) {
		out = append(out, e.state.Improvements[p])
	}
	return out
}

// Reset drops every improvement, cooldown, and decision, as a new engine
// would have. An HA instance (#31) resets when it becomes standby, so it
// does not carry its old intent into a later takeover.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state, e.last, e.at = NewState(), Output{}, time.Time{}
}

// SetConfig replaces the config the next Evaluate uses. The caller passes
// a fresh config (its maps are not shared with a config Evaluate is
// reading). It does not drop improvements; Decide retires whatever the
// new values make ineligible.
func (e *Engine) SetConfig(cfg Config) {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
}

// Mode returns the configured mode.
func (e *Engine) Mode() string {
	if e == nil {
		return ""
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Mode
}
