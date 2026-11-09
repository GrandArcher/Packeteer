package plugin

import (
	"context"
	"time"
)

// ---- High availability (active/standby, #31) ----
//
// An elector decides which instance of an HA pair is active. Only the
// active instance announces; a standby probes and keeps its RIB view warm
// but runs no decisions and has nothing on the wire. The core gates every
// announcer on Active, withdraws everything when it turns false, and calls
// Resign once it has. An elector never announces and never decides what to
// announce. It is in-process only, because it gates the announce path.

// KindElector is the high-availability extension point.
const KindElector Kind = "elector"

// Electors holds the elector plugin types.
var Electors = NewRegistry[Elector](KindElector)

// Candidacy is what the core reports about this instance on each renewal.
type Candidacy struct {
	// Eligible is false while this instance cannot lead: its RIB view is
	// not ready (no iBGP session is up). An ineligible instance does not
	// take leadership, and an active one steps down.
	Eligible bool
	// RouteHold bounds how long routes this instance announced can stay on
	// the routers after it dies without withdrawing them: the longest
	// negotiated BGP hold time of its sessions (Packeteer never enables
	// graceful restart). A standby must not become active before the
	// last holder's RouteHold has passed since its last renewal, so the
	// routers never carry both instances' routes.
	RouteHold time.Duration
}

// Elector is the leader election behind active/standby.
type Elector interface {
	Lifecycle
	// SetCandidate is called once before Start with the function that
	// reports this instance's candidacy. The elector calls it on each
	// renewal; it may block briefly and must not be called with a lock
	// the core could wait on.
	SetCandidate(func() Candidacy)
	// OnChange is called once before Start. The elector calls fn from its
	// own goroutine after Active changed, one call at a time; fn reads
	// Active. Changes that happen while fn runs are coalesced.
	OnChange(fn func())
	// Active reports whether this instance may announce now. It must turn
	// false before any other instance can turn true, including when the
	// elector's own goroutine is stuck: it is checked under the
	// announcers' locks before every sync. It is false before Start.
	Active() bool
	// Resign gives up leadership immediately, so a standby can take over
	// without waiting for the lease to run out. The core calls it only
	// after this instance stopped being active (or is stopping) and every
	// route it announced was withdrawn. It is a no-op when this instance
	// does not hold leadership.
	Resign(ctx context.Context) error
	// Status is the read-only view for /api/ha.
	Status() ElectorStatus
}

// Elector roles.
const (
	RoleActive  = "active"
	RoleStandby = "standby"
)

// ElectorStatus is an elector's view of the HA pair.
type ElectorStatus struct {
	// Type is the elector plugin type (set by the core).
	Type string `json:"type"`
	// ID names this instance in the pair.
	ID string `json:"id"`
	// Role is RoleActive or RoleStandby.
	Role string `json:"role"`
	// Since is when Role last changed.
	Since time.Time `json:"since"`
	// Holder is the ID of the instance that holds leadership, as far as
	// this instance knows. Empty when nobody holds it.
	Holder string `json:"holder,omitempty"`
	// Eligible is the last reported candidacy.
	Eligible bool `json:"eligible"`
	// Detail says why a standby is waiting, or what failed.
	Detail string `json:"detail,omitempty"`
	// Takeovers counts the times this instance became active.
	Takeovers int `json:"takeovers"`
}
