package plugin

import (
	"context"
	"net/netip"
)

// ---- Inbound announcer ----

// InboundAction is one catalog entry of an inbound announcer: what the
// edge does to the operator's prefix on the session toward Provider when a
// steer route carries Communities.
type InboundAction struct {
	// Provider is the configured provider whose inbound traffic the action
	// reduces.
	Provider string `json:"provider"`
	// Name is an operator label, shown on the API and in logs.
	Name string `json:"name,omitempty"`
	// Prepend is how many times the edge's export policy toward Provider
	// prepends its ASN when it sees Communities. A router cannot accept its
	// own ASN in an iBGP AS path, so the edge does the prepend, not
	// Packeteer. Zero means the action is a TE community only.
	Prepend int `json:"prepend,omitempty"`
	// Communities are standard communities ("asn:value") attached to the
	// steer route: signal communities the edge maps to a prepend, and the
	// provider's own traffic-engineering communities the edge passes on to
	// that provider only.
	Communities []string `json:"communities"`
}

// InboundRoute re-announces one of the operator's own prefixes to the edge
// with the actions that steer inbound traffic away from Away. Prefix must be
// the exact prefix learned from the RIB, and NextHop the learned next hop,
// so forwarding on the edge does not change.
type InboundRoute struct {
	Prefix    netip.Prefix
	NextHop   netip.Addr
	LocalPref uint32
	// Community is the configured packeteer community. It is required.
	Community string
	// Away lists the providers to shed inbound traffic from, sorted. Each
	// must have a catalog action. It is never empty.
	Away []string
}

// InboundAnnouncer publishes inbound steer routes. Like Announcer it runs
// in-process only: an out-of-process plugin must never inject routes. It
// adds its own marker community, the actions of every provider in Away,
// the packeteer community, and NO_EXPORT. It must withdraw everything on
// Stop and must not use graceful restart.
type InboundAnnouncer interface {
	Lifecycle
	// Action returns the catalog entry for provider. ok is false when the
	// provider has none; the core then never steers away from it.
	Action(provider string) (InboundAction, bool)
	Announce(ctx context.Context, r InboundRoute) error
	Withdraw(ctx context.Context, p netip.Prefix) error
	WithdrawAll(ctx context.Context) error
}

// InboundAnnouncers is the registry for inbound announcers (kind
// announcer). There is no exec type: inbound routes are injected routes.
var InboundAnnouncers = NewRegistry[InboundAnnouncer](KindAnnouncer)

// InboundMbps is the figure inbound commit control compares with
// CommitMbps: the inbound 95th percentile of the open period. Steering
// inbound traffic cannot lower the outbound figure, so the direction is
// fixed whatever the billing mode. ok is false when no sample is stored or
// the commit is not positive.
func (u Usage) InboundMbps() (float64, bool) {
	if u.Samples <= 0 || u.CommitMbps <= 0 {
		return 0, false
	}
	return u.InMbps95, true
}
