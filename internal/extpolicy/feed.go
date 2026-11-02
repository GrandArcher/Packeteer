// Package extpolicy is the external policy feed (#232): the outbound
// routes the announce controller puts on the wire, published read-only
// for the operator's own BGP daemon to apply, so Packeteer can stay out of
// the announcing session.
//
// The feed never decides anything. Mirror is the announcer the outbound
// announce controller drives, so every route in the feed went through the
// same Decide output and the same rails as an injected route (allowlist,
// cap, learned-RIB check, leak-watch hold, stale-data and session-loss
// withdraw, HA standby, flap quarantine). With an embedded announcer
// configured, Mirror passes each call on first and records the route only
// once the announcer accepted it, so the two paths never disagree.
//
// Fail safe: a document carries an expiry, renewed by each decision round
// (Touch). A consumer must drop every route once the expiry passes, so a
// stopped, frozen, or unreachable controller is withdrawn within the TTL.
// Turning the feed off or stopping the controller publishes an empty set
// that is already expired.
package extpolicy

import (
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// NoExport is the well-known NO_EXPORT community (RFC 1997). The embedded
// announcer adds it to every route; the feed lists it so a consumer
// applies it too.
const NoExport = "65535:65281"

// Route is one recommended route.
type Route struct {
	Prefix   netip.Prefix `json:"prefix"`
	Provider string       `json:"provider"`
	NextHop  netip.Addr   `json:"next_hop"`
	// LocalPref and Communities are what the embedded announcer would
	// send. Communities ends with NoExport.
	LocalPref   uint32   `json:"local_pref"`
	Communities []string `json:"communities"`
	ASPath      []uint32 `json:"as_path,omitempty"`
	// Cause and Reason come from the improvement the route belongs to; a
	// learned more-specific carries its covering improvement's.
	Cause  string `json:"cause"`
	Reason string `json:"reason,omitempty"`
}

// Document is the published route set.
type Document struct {
	// Revision changes whenever Routes changes. It starts again with a
	// restart, so a consumer compares it for equality, not order.
	Revision uint64 `json:"revision"`
	// GeneratedAt is the decision round that last renewed the feed.
	GeneratedAt time.Time `json:"generated_at,omitzero"`
	// ExpiresAt is GeneratedAt plus the TTL. ExpiresInMS is the time left
	// when the document was sent; a consumer adds it to its own clock, so
	// clock skew does not matter. Zero means drop every route now.
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	ExpiresInMS int64     `json:"expires_in_ms"`
	// HeartbeatMS is how often the stream resends the document, and the
	// longest a long poll (DocumentPath?wait=revision) waits.
	HeartbeatMS int64   `json:"heartbeat_ms"`
	Routes      []Route `json:"routes"`
}

// Feed is the route set the announce controller has on the wire, as last
// published by a decision round.
type Feed struct {
	mu      sync.Mutex
	wire    map[netip.Prefix]plugin.Route // what Mirror recorded
	routes  []Route                       // published
	rev     uint64
	fresh   time.Time
	ttl     time.Duration
	enabled bool
	closed  bool
	changed chan struct{}
	now     func() time.Time
}

// New returns a feed. enabled false publishes an empty, expired set.
func New(enabled bool, ttl time.Duration, now func() time.Time) *Feed {
	if now == nil {
		now = time.Now
	}
	return &Feed{wire: map[netip.Prefix]plugin.Route{}, ttl: ttl, enabled: enabled, changed: make(chan struct{}), now: now}
}

// Heartbeat is how often the stream resends the document: a third of the
// TTL, so two lost heartbeats still leave time before the expiry.
func (f *Feed) Heartbeat() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeatLocked()
}

func (f *Feed) heartbeatLocked() time.Duration {
	return max(f.ttl/3, time.Second)
}

func (f *Feed) set(r plugin.Route) {
	f.mu.Lock()
	r.Prefix = r.Prefix.Masked()
	r.Communities = slices.Clone(r.Communities)
	r.ASPath = slices.Clone(r.ASPath)
	f.wire[r.Prefix] = r
	f.mu.Unlock()
}

// del and clear also drop the route from the published set at once, so a
// withdraw outside a decision round (leak watch, HA step-down, a reload
// that leaves inject) reaches consumers without waiting for the next Touch.
func (f *Feed) del(p netip.Prefix) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p = p.Masked()
	delete(f.wire, p)
	f.unpublishLocked(func(r Route) bool { return r.Prefix == p })
}

func (f *Feed) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.wire)
	f.unpublishLocked(func(Route) bool { return true })
}

func (f *Feed) unpublishLocked(drop func(Route) bool) {
	if f.closed {
		return
	}
	next := slices.DeleteFunc(slices.Clone(f.routes), drop)
	if len(next) != len(f.routes) {
		f.routes = next
		f.rev++
		f.notifyLocked()
	}
}

// Touch publishes what is on the wire after a decision round and renews
// the expiry from now. imps are the decision engine's improvements, read
// for each route's cause and reason. It is called after the round's Sync,
// so a consumer never sees half of a round. A nil feed is off.
func (f *Feed) Touch(now time.Time, imps []policy.Improvement) {
	if f == nil {
		return
	}
	byPrefix := make(map[netip.Prefix]policy.Improvement, len(imps))
	for _, im := range imps {
		byPrefix[im.Prefix.Masked()] = im
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	order := slices.Collect(maps.Keys(f.wire))
	netpfx.Sort(order)
	next := make([]Route, 0, len(order))
	for _, p := range order {
		next = append(next, feedRoute(f.wire[p], improvementFor(p, byPrefix, imps)))
	}
	f.fresh = now
	if !slices.EqualFunc(next, f.routes, sameRoute) {
		f.routes = next
		f.rev++
		f.notifyLocked()
	}
}

// improvementFor is the improvement exactly on p, else the one whose
// prefix covers p (p is one of its learned more-specifics).
func improvementFor(p netip.Prefix, byPrefix map[netip.Prefix]policy.Improvement, imps []policy.Improvement) policy.Improvement {
	if im, ok := byPrefix[p]; ok {
		return im
	}
	var best policy.Improvement
	for _, im := range imps {
		q := im.Prefix.Masked()
		if q.Bits() < p.Bits() && q.Contains(p.Addr()) && (!best.Prefix.IsValid() || q.Bits() > best.Prefix.Bits()) {
			best = im
		}
	}
	return best
}

func feedRoute(r plugin.Route, im policy.Improvement) Route {
	cause := im.Cause
	if cause == "" {
		cause = plugin.CausePerformance
	}
	comms := slices.Clone(r.Communities)
	if !slices.Contains(comms, NoExport) {
		comms = append(comms, NoExport)
	}
	return Route{Prefix: r.Prefix, Provider: r.Provider, NextHop: r.NextHop, LocalPref: r.LocalPref,
		Communities: comms, ASPath: slices.Clone(r.ASPath), Cause: cause, Reason: im.Reason}
}

func sameRoute(a, b Route) bool {
	return a.Prefix == b.Prefix && a.Provider == b.Provider && a.NextHop == b.NextHop && a.LocalPref == b.LocalPref &&
		slices.Equal(a.Communities, b.Communities) && slices.Equal(a.ASPath, b.ASPath) && a.Cause == b.Cause && a.Reason == b.Reason
}

// SetRuntime turns the feed on or off and sets the TTL while running
// (#128). Turning it off publishes an empty, expired set at once; turning
// it on publishes the routes on the wire with the last round's expiry.
func (f *Feed) SetRuntime(enabled bool, ttl time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enabled == enabled && f.ttl == ttl {
		return
	}
	// A new revision answers open long polls, so consumers learn the new
	// expiry and heartbeat at once.
	f.rev++
	f.enabled, f.ttl = enabled, ttl
	f.notifyLocked()
}

// Close publishes an empty, expired set for good. The controller calls it
// on shutdown after the withdraw. A nil feed is off.
func (f *Feed) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	f.rev++
	f.notifyLocked()
}

// Routes is the count (not the list) of routes a consumer applies now:
// zero while the feed is off, closed, or expired.
func (f *Feed) Routes() int {
	return len(f.Document().Routes)
}

// Document is the feed as a consumer sees it now. Off, closed, or past
// its expiry, it has no routes and nothing left of its TTL.
func (f *Feed) Document() Document {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	doc := Document{Revision: f.rev, HeartbeatMS: f.heartbeatLocked().Milliseconds(), Routes: []Route{}}
	if f.fresh.IsZero() {
		return doc
	}
	doc.GeneratedAt = f.fresh
	if !f.enabled || f.closed {
		doc.ExpiresAt = f.fresh
		return doc
	}
	doc.ExpiresAt = f.fresh.Add(f.ttl)
	left := doc.ExpiresAt.Sub(now)
	if left <= 0 {
		return doc
	}
	doc.ExpiresInMS = max(left.Milliseconds(), 1)
	doc.Routes = slices.Clone(f.routes)
	return doc
}

// Changed is closed the next time the published document changes. done is
// true once the feed is closed for good.
func (f *Feed) Changed() (ch <-chan struct{}, done bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.changed, f.closed
}

func (f *Feed) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}
