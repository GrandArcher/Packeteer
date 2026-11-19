package plugin

import (
	"context"
	"net/netip"
)

// KindOriginCollector is the public route collector extension point
// (#671). A collector says which origin ASes a public vantage set, such as
// RIPE RIS or RouteViews, sees announcing a prefix. It is evidence only:
// the core compares the answer with the local origin to class an
// RPKI-invalid only path, and nothing it reports announces, withdraws, or
// changes a decision.
const KindOriginCollector Kind = "origin_collector"

// OriginCollectors holds the origin collector plugin types.
var OriginCollectors = NewRegistry[OriginCollector](KindOriginCollector)

// OriginCollector reports the origin ASes seen for exactly prefix. An empty
// answer with no error means the collector saw no announcement of the
// prefix. An error means it could not answer; the core treats that, like
// an empty answer, as no agreement.
type OriginCollector interface {
	Lifecycle
	Origins(ctx context.Context, prefix netip.Prefix) ([]uint32, error)
}
