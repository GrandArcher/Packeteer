package plugin

import (
	"context"
	"net/netip"
)

// KindHijackFeed is the hijack incident feed extension point (#401). A
// feed says whether an outside monitor reports a hijack for a prefix. It
// is evidence only: the core reads it to class an RPKI-invalid only path,
// and nothing it reports announces, withdraws, or changes a decision.
const KindHijackFeed Kind = "hijack_feed"

// HijackFeeds holds the hijack feed plugin types.
var HijackFeeds = NewRegistry[HijackFeed](KindHijackFeed)

// HijackIncident is one reported incident. Origin is the AS the monitor
// saw announcing the prefix, 0 when the report does not name one.
type HijackIncident struct {
	Prefix netip.Prefix
	Origin uint32
	// Detail is the feed's own description, possibly empty.
	Detail string
}

// HijackFeed reports the incidents whose prefix equals, covers, or is
// covered by prefix. An error means the feed could not answer, which the
// core treats as no evidence either way.
type HijackFeed interface {
	Lifecycle
	Incidents(ctx context.Context, prefix netip.Prefix) ([]HijackIncident, error)
}
