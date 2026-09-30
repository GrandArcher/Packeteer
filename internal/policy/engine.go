package policy

import (
	"sync"
	"time"

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

// Decisions returns the latest per-prefix decisions and when they were made.
func (e *Engine) Decisions() ([]Decision, time.Time) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Decision(nil), e.last.Decisions...), e.at
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

// Mode returns the configured mode.
func (e *Engine) Mode() string { return e.cfg.Mode }
