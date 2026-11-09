// Package syshealth remembers the last result of the operations a
// component performs (a notifier delivery, a storage write, a router's
// monitoring session) so the System page can show state, since, and the
// last error. It only records; nothing here changes routing.
package syshealth

import (
	"strings"
	"sync"
	"time"
)

// Outcome is the latest result for one key. Since is when OK last
// changed; At is the time of the latest result.
type Outcome struct {
	OK    bool
	Since time.Time
	At    time.Time
	Err   string
}

// Tracker is safe for concurrent use. A nil Tracker records nothing.
type Tracker struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]Outcome
}

// New returns an empty tracker. now may be nil for time.Now.
func New(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{now: now, m: map[string]Outcome{}}
}

// Record stores the result of one operation under key. A nil err is a
// success.
func (t *Tracker) Record(key string, err error) {
	if t == nil {
		return
	}
	at := t.now().UTC()
	t.mu.Lock()
	defer t.mu.Unlock()
	o, seen := t.m[key]
	ok := err == nil
	if !seen || o.OK != ok {
		o.Since = at
	}
	o.OK, o.At, o.Err = ok, at, ""
	if err != nil {
		o.Err = err.Error()
	}
	t.m[key] = o
}

// Get returns the latest outcome for key.
func (t *Tracker) Get(key string) (Outcome, bool) {
	if t == nil {
		return Outcome{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	o, ok := t.m[key]
	return o, ok
}

// Under returns the outcomes whose key starts with prefix, keyed by the
// rest of the key.
func (t *Tracker) Under(prefix string) map[string]Outcome {
	out := map[string]Outcome{}
	if t == nil {
		return out
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, o := range t.m {
		if rest, ok := strings.CutPrefix(k, prefix); ok {
			out[rest] = o
		}
	}
	return out
}
