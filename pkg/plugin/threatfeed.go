package plugin

import (
	"context"
	"net/netip"
)

// ---- Threat-intelligence feeds (#134) ----
//
// A threat feed fetches a list of networks from an external source. It
// never announces and never adds a mitigation rule itself: the core turns
// a listed network into a mitigation rule only when an explicit
// threat_feeds rule in config names the feed, rate-limited and capped, and
// the mitigation controller still applies its own allowlist, exact learned
// prefix check, cap, TTL, community, and NO_EXPORT. It is in-process only,
// because its output can lead to an announcement.

// KindThreatFeed is the threat-intelligence feed extension point.
const KindThreatFeed Kind = "threat_feed"

// ThreatFeeds holds the threat feed plugin types.
var ThreatFeeds = NewRegistry[ThreatFeed](KindThreatFeed)

// ThreatEntry is one listed network. Prefix is masked and never a default
// route. Comment is the feed's own note for it, possibly empty.
type ThreatEntry struct {
	Prefix  netip.Prefix
	Comment string
}

// ThreatFeed fetches the current list. Fetch returns the whole list in the
// feed's order, without duplicates, or an error; a partial list is an
// error, so the core never acts on half a feed.
type ThreatFeed interface {
	Lifecycle
	Fetch(ctx context.Context) ([]ThreatEntry, error)
}
