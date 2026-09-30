package plugin

import (
	"net/netip"
	"time"
)

// ---- Federation (multi-POP, #30) ----
//
// A federation plugin connects Packeteer instances that run in several
// POPs (routing domains). Each instance publishes a snapshot of what it
// measures and announces; the plugin serves it to its peers and fetches
// theirs. The plugin is transport only: it never announces, and it never
// decides. The controller turns fresh peer snapshots into decision inputs
// (paths through another POP's providers, with the inter-DC RTT added,
// and global commit usage) and serves the central view. Everything an
// instance announces still goes through its own allowlist, learned RIB,
// community tagging, improvement cap, and withdraw rules.

// KindFederation is the federation extension point.
const KindFederation Kind = "federation"

// Federations holds the federation plugin types.
var Federations = NewRegistry[Federation](KindFederation)

// FederatedProvider is one provider as a POP sees it. Domain is the
// provider's routing domain; a POP only reports its own providers' paths.
type FederatedProvider struct {
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
	Up     bool   `json:"up"`
	// Usage is the provider's telemetry row, when the POP has one.
	Usage *Usage `json:"usage,omitempty"`
}

// FederatedPath is one fresh measurement a POP took through one of its
// own providers.
type FederatedPath struct {
	Prefix   netip.Prefix  `json:"prefix"`
	Provider string        `json:"provider"`
	Sent     int           `json:"sent"`
	LossPct  float64       `json:"loss_pct"`
	RTT      time.Duration `json:"rtt"`
	Jitter   time.Duration `json:"jitter"`
	Time     time.Time     `json:"time"`
}

// FederatedRoute is how a POP forwards one probed prefix. Exit is the
// provider its traffic for the prefix leaves through: the provider of an
// announced improvement, else the native provider from its learned RIB.
// A prefix the POP has not learned is not listed.
type FederatedRoute struct {
	Prefix netip.Prefix `json:"prefix"`
	Native string       `json:"native,omitempty"`
	Exit   string       `json:"exit"`
}

// FederatedImprovement is an active improvement on a POP.
type FederatedImprovement struct {
	Prefix   netip.Prefix `json:"prefix"`
	Provider string       `json:"provider"`
	Native   string       `json:"native"`
	Cause    string       `json:"cause,omitempty"`
	Since    time.Time    `json:"since"`
}

// InstanceSnapshot is what one instance publishes to its peers. Times
// are the publishing instance's clock; a plugin converts them to the
// local clock before handing a peer snapshot to the controller.
type InstanceSnapshot struct {
	Instance        string                 `json:"instance"`
	Domain          string                 `json:"domain"`
	Version         string                 `json:"version,omitempty"`
	Mode            string                 `json:"mode"`
	Time            time.Time              `json:"time"`
	RIBReady        bool                   `json:"rib_ready"`
	MaxImprovements int                    `json:"max_improvements"`
	Providers       []FederatedProvider    `json:"providers"`
	Paths           []FederatedPath        `json:"paths"`
	Routes          []FederatedRoute       `json:"routes"`
	Improvements    []FederatedImprovement `json:"improvements"`
}

// PeerState is the latest state of one configured peer. Fresh is false
// when the last good snapshot is older than the plugin's max age, or none
// was ever fetched; the controller then ignores Snapshot for decisions and
// the instance behaves as if it ran standalone.
type PeerState struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	// Fresh reports whether Snapshot may be used for decisions.
	Fresh bool `json:"fresh"`
	// LastSeen is the local time of the last good fetch.
	LastSeen time.Time `json:"last_seen,omitzero"`
	// Error is the last fetch error. Empty when the last fetch succeeded.
	Error string `json:"error,omitempty"`
	// Snapshot is the last good snapshot, with every time converted to
	// the local clock. Zero when none was fetched.
	Snapshot InstanceSnapshot `json:"snapshot"`
}

// Federation is the instance-to-instance transport. Publish must not
// block on I/O; Peers returns a copy. A federation plugin must not
// announce routes or change decisions.
type Federation interface {
	Lifecycle
	// Publish replaces the snapshot served to peers.
	Publish(s InstanceSnapshot)
	// Peers returns the latest state of every configured peer, in config
	// order, with Fresh evaluated at now.
	Peers(now time.Time) []PeerState
}

// ShiftSnapshot converts every time in s from the peer clock to the
// local clock: a time t becomes fetched - (s.Time - t). The ages stay as
// the peer measured them, so clock skew between POPs does not make stale
// data look fresh. Plugins call it on each fetched snapshot.
func ShiftSnapshot(s InstanceSnapshot, fetched time.Time) InstanceSnapshot {
	shift := func(t time.Time) time.Time {
		if t.IsZero() {
			return t
		}
		age := s.Time.Sub(t)
		if age < 0 {
			age = 0
		}
		return fetched.Add(-age)
	}
	out := s
	out.Paths = make([]FederatedPath, len(s.Paths))
	for i, p := range s.Paths {
		p.Time = shift(p.Time)
		out.Paths[i] = p
	}
	out.Providers = make([]FederatedProvider, len(s.Providers))
	for i, p := range s.Providers {
		if p.Usage != nil {
			u := *p.Usage
			u.Updated = shift(u.Updated)
			u.Polled = shift(u.Polled)
			p.Usage = &u
		}
		out.Providers[i] = p
	}
	out.Improvements = make([]FederatedImprovement, len(s.Improvements))
	for i, im := range s.Improvements {
		im.Since = shift(im.Since)
		out.Improvements[i] = im
	}
	out.Routes = append([]FederatedRoute(nil), s.Routes...)
	out.Time = fetched
	return out
}
