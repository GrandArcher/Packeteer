// Package leakwatch notices Packeteer's own routes outside the AS and takes
// them back (#199). Leak sources report routes seen outside the iBGP
// sessions. A sighting is a leak when it carries packeteer_community, or
// when it shows a prefix Packeteer has injected with the local ASN in its
// path. The route is withdrawn at once, alone, and the prefix is held out
// of announcements until an operator clears it. The watch only withdraws:
// it never announces, and a source that is down or slow cannot delay a
// withdraw, because sources hand sightings over a bounded queue and
// withdraws run from the controller's own state.
package leakwatch

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Detection reasons.
const (
	ReasonCommunity = "community"
	ReasonASPath    = "as_path"
)

// What happened to the route when the leak was seen.
const (
	ActionWithdrawn      = "withdrawn"
	ActionWithdrawFailed = "withdraw_failed"
	ActionHeld           = "held"
)

const (
	queueSize = 4096
	// maxHeld bounds the held set for prefixes that are not injected. A
	// sighting carrying the community names any prefix, so the set must
	// not grow without limit; injected prefixes are bounded by the
	// announcer.
	maxHeld        = 1000
	healthInterval = 5 * time.Second
)

// Source is one configured leak source.
type Source struct {
	Name   string
	Type   string
	Plugin plugin.LeakSource
}

// Config wires the watch to the announcer and the event stream.
type Config struct {
	// ASN is the local AS for the AS path rule, which flags an injected
	// prefix seen with it in the path. Zero turns that rule off: an
	// operator that exports transit to customers sees every injected
	// prefix with its ASN in the path, legitimately.
	ASN uint32
	// Community is packeteer_community as asn<<16|value, or Large as
	// "global:data1:data2". At least one is set.
	Community uint32
	Large     string
	// Injected reports whether p is an outbound route on the wire now.
	Injected func(netip.Prefix) bool
	// Withdraw takes that one route back.
	Withdraw func(context.Context, netip.Prefix) error
	Emit     func(plugin.Event)
	Log      *slog.Logger
}

// Leak is one route held out because it was seen outside the AS.
type Leak struct {
	Prefix    netip.Prefix `json:"prefix"`
	Reason    string       `json:"reason"`
	Action    string       `json:"action"`
	Source    string       `json:"source"`
	Seen      string       `json:"seen"`
	ASPath    []uint32     `json:"as_path"`
	Since     time.Time    `json:"since"`
	LastSeen  time.Time    `json:"last_seen"`
	Sightings int          `json:"sightings"`
}

// SourceStatus is a source's feed state. Unhealthy means unknown: the
// feed is not delivering, so no sighting is not proof of a clean edge.
type SourceStatus struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Healthy bool   `json:"healthy"`
}

// Status is the read-only view for the API.
type Status struct {
	// State is "watching" while at least one source is delivering and
	// "unknown" otherwise.
	State   string         `json:"state"`
	Sources []SourceStatus `json:"sources"`
	Leaks   []Leak         `json:"leaks"`
	// Dropped counts sightings discarded because the queue was full.
	Dropped uint64 `json:"dropped"`
}

type sighting struct {
	source string
	s      plugin.LeakSighting
}

// Watcher evaluates sightings and holds leaked prefixes out.
type Watcher struct {
	cfg     Config
	sources []Source
	queue   chan sighting
	dropped atomic.Uint64

	mu      sync.RWMutex
	held    map[netip.Prefix]*Leak
	healthy map[string]bool
}

// New points every source at the watch. The sources are started by the
// plugin host; Run consumes what they report.
func New(cfg Config, sources []Source) *Watcher {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	w := &Watcher{cfg: cfg, sources: sources, queue: make(chan sighting, queueSize),
		held: map[netip.Prefix]*Leak{}, healthy: map[string]bool{}}
	for _, src := range sources {
		name := src.Name
		src.Plugin.SetLeakSink(func(s plugin.LeakSighting) {
			select {
			case w.queue <- sighting{source: name, s: s}:
			default:
				w.dropped.Add(1)
			}
		})
	}
	return w
}

// Run evaluates sightings until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	tick := time.NewTicker(healthInterval)
	defer tick.Stop()
	w.pollHealth()
	for {
		select {
		case <-ctx.Done():
			return
		case sg := <-w.queue:
			w.handle(ctx, sg)
		case <-tick.C:
			w.pollHealth()
		}
	}
}

func (w *Watcher) pollHealth() {
	for _, src := range w.sources {
		ok := src.Plugin.Healthy()
		w.mu.Lock()
		prev, seen := w.healthy[src.Name]
		w.healthy[src.Name] = ok
		w.mu.Unlock()
		switch {
		case ok && !seen:
			w.cfg.Log.Info("leak source feeding", "source", src.Name)
		case ok && !prev:
			w.cfg.Log.Info("leak source recovered", "source", src.Name)
		case !ok && (!seen || prev):
			w.cfg.Log.Warn("leak source not delivering: leak status is unknown for it; withdraws are unaffected", "source", src.Name)
		}
	}
}

// reason says why s is a leak, or is empty.
func (w *Watcher) reason(s plugin.LeakSighting) string {
	if w.cfg.Community != 0 && slices.Contains(s.Communities, w.cfg.Community) ||
		w.cfg.Large != "" && slices.Contains(s.LargeCommunities, w.cfg.Large) {
		return ReasonCommunity
	}
	if !s.OurExport && w.cfg.ASN != 0 && slices.Contains(s.ASPath, w.cfg.ASN) && w.cfg.Injected(s.Prefix) {
		return ReasonASPath
	}
	return ""
}

func (w *Watcher) handle(ctx context.Context, sg sighting) {
	s := sg.s
	if !s.Prefix.IsValid() {
		return
	}
	s.Prefix = s.Prefix.Masked()
	reason := w.reason(s)
	if reason == "" {
		return
	}
	now := time.Now()
	w.mu.Lock()
	if l, ok := w.held[s.Prefix]; ok {
		l.Sightings++
		l.LastSeen = now
		w.mu.Unlock()
		return
	}
	on := w.cfg.Injected(s.Prefix)
	// A full set drops only prefixes that are not on the wire: anyone
	// downstream can tag routes with the community, but a route that is
	// announced right now must still be withdrawn and held.
	if len(w.held) >= maxHeld && !on {
		w.mu.Unlock()
		w.cfg.Log.Error("leak watch held set is full; sighting ignored", "prefix", s.Prefix, "max", maxHeld)
		return
	}
	l := &Leak{Prefix: s.Prefix, Reason: reason, Action: ActionHeld, Source: sg.source, Seen: s.Seen,
		ASPath: slices.Clone(s.ASPath), Since: now, LastSeen: now, Sightings: 1}
	// Held before the withdraw, so a concurrent Sync cannot announce it again.
	w.held[s.Prefix] = l
	w.mu.Unlock()

	var werr error
	if on {
		werr = w.cfg.Withdraw(ctx, s.Prefix)
	}
	action := ActionHeld
	switch {
	case on && werr == nil:
		action = ActionWithdrawn
	case on:
		action = ActionWithdrawFailed
		w.cfg.Log.Error("leaked route not withdrawn; the next sync retries", "prefix", s.Prefix, "err", werr)
	}
	w.mu.Lock()
	l.Action = action
	snap := *l
	w.mu.Unlock()
	w.cfg.Log.Warn("route seen outside the AS; held out until cleared", "prefix", snap.Prefix, "reason", reason, "action", action, "source", snap.Source, "seen", snap.Seen, "as_path", fmt.Sprint(snap.ASPath))
	w.emit(plugin.EventLeakDetected, now, fmt.Sprintf("%s seen outside the AS (%s); %s and held out until cleared", snap.Prefix, reason, strings.ReplaceAll(action, "_", " ")), map[string]string{
		"prefix": snap.Prefix.String(), "reason": reason, "action": action, "source": snap.Source,
		"seen": snap.Seen, "as_path": joinASNs(snap.ASPath),
	})
}

func (w *Watcher) emit(kind string, now time.Time, msg string, fields map[string]string) {
	if w.cfg.Emit != nil {
		w.cfg.Emit(plugin.NewEvent(kind, now, msg, fields))
	}
}

// Held reports whether p is held out. The announcer asks it on every sync.
func (w *Watcher) Held(p netip.Prefix) bool {
	if w == nil {
		return false
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	_, ok := w.held[p.Masked()]
	return ok
}

// Clear ends the hold on p. It reports whether p was held. If the route is
// still visible outside, the next sighting holds it again.
func (w *Watcher) Clear(p netip.Prefix) bool {
	if w == nil {
		return false
	}
	p = p.Masked()
	w.mu.Lock()
	l, ok := w.held[p]
	delete(w.held, p)
	w.mu.Unlock()
	if ok {
		now := time.Now()
		w.cfg.Log.Info("leak hold cleared", "prefix", p, "since", l.Since)
		w.emit(plugin.EventLeakCleared, now, fmt.Sprintf("%s may be announced again", p), map[string]string{"prefix": p.String()})
	}
	return ok
}

// Status is a copy of the watch state.
func (w *Watcher) Status() Status {
	st := Status{State: "unknown", Sources: []SourceStatus{}, Leaks: []Leak{}}
	if w == nil {
		return st
	}
	st.Dropped = w.dropped.Load()
	w.mu.RLock()
	defer w.mu.RUnlock()
	for _, src := range w.sources {
		ok := w.healthy[src.Name]
		st.Sources = append(st.Sources, SourceStatus{Name: src.Name, Type: src.Type, Healthy: ok})
		if ok {
			st.State = "watching"
		}
	}
	for _, l := range w.held {
		c := *l
		c.ASPath = slices.Clone(l.ASPath)
		st.Leaks = append(st.Leaks, c)
	}
	sort.Slice(st.Leaks, func(i, j int) bool { return st.Leaks[i].Prefix.String() < st.Leaks[j].Prefix.String() })
	return st
}

func joinASNs(path []uint32) string {
	parts := make([]string, len(path))
	for i, a := range path {
		parts[i] = strconv.FormatUint(uint64(a), 10)
	}
	return strings.Join(parts, " ")
}
