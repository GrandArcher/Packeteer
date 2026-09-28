package plugin

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Factory constructs and validates a plugin instance from its config. It is
// the plugin's Init step and must not perform network I/O.
type Factory[T any] func(cfg Config, env Env) (T, error)

// Registry maps type names to factories for one extension point.
type Registry[T any] struct {
	kind Kind
	mu   sync.RWMutex
	m    map[string]Factory[T]
}

// NewRegistry returns an empty registry for kind.
func NewRegistry[T any](kind Kind) *Registry[T] {
	return &Registry[T]{kind: kind, m: map[string]Factory[T]{}}
}

// Kind returns the extension point this registry serves.
func (r *Registry[T]) Kind() Kind { return r.kind }

// Register adds a factory. It panics on an empty or duplicate name, which is
// a programming error caught at init time.
func (r *Registry[T]) Register(name string, f Factory[T]) {
	if name == "" || f == nil {
		panic(fmt.Sprintf("plugin: invalid %s registration %q", r.kind, name))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.m[name]; dup {
		panic(fmt.Sprintf("plugin: duplicate %s type %q", r.kind, name))
	}
	r.m[name] = f
}

// Has reports whether a type is registered.
func (r *Registry[T]) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.m[name]
	return ok
}

// Types lists registered type names, sorted.
func (r *Registry[T]) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// New constructs a plugin of the named type.
func (r *Registry[T]) New(name string, cfg Config, env Env) (T, error) {
	r.mu.RLock()
	f, ok := r.m[name]
	r.mu.RUnlock()
	if !ok {
		var zero T
		avail := strings.Join(r.Types(), ", ")
		if avail == "" {
			avail = "none"
		}
		return zero, fmt.Errorf("unknown %s type %q (available: %s)", r.kind, name, avail)
	}
	return f(cfg, env)
}

// Global registries. Built-in plugins register themselves from init().
var (
	Probers     = NewRegistry[Prober](KindProber)
	Sources     = NewRegistry[TargetSource](KindSource)
	Scorers     = NewRegistry[Scorer](KindScorer)
	Announcers  = NewRegistry[Announcer](KindAnnouncer)
	Notifiers   = NewRegistry[Notifier](KindNotifier)
	Telemetries = NewRegistry[Telemetry](KindTelemetry)
	Policies    = NewRegistry[Policy](KindPolicy)
)
