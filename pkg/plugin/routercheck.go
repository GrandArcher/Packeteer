package plugin

import (
	"context"
	"net/netip"
)

// KindRouterCheck is the read-only router reader behind the import_filter
// preflight check (preflight.router_check, #626).
const KindRouterCheck Kind = "router_check"

// RouterChecks holds the router reader types.
var RouterChecks = NewRegistry[RouterCheck](KindRouterCheck)

// FilterQuery names what the import_filter check asks the router about.
type FilterQuery struct {
	// Community is packeteer_community as text: "64512:666", or
	// "65536:666:1" for a large community.
	Community string
	// Packeteer is Packeteer's address as the router's BGP neighbor.
	Packeteer netip.Addr
}

// Verdict is the outcome of one fact read from the router.
type Verdict string

// Verdicts. Unknown means the reader could not tell: the check then falls
// back to an administrator's confirmation.
const (
	VerdictPass    Verdict = "pass"
	VerdictFail    Verdict = "fail"
	VerdictUnknown Verdict = "unknown"
)

// FilterFinding is one fact read from the router: one session's policy in
// one address family.
type FilterFinding struct {
	Verdict Verdict
	// Detail says what was read, naming the session and the policy.
	Detail string
	// Fix is the change to make on the router. Set when Verdict is fail.
	Fix string
}

// RouterCheck reads one router's BGP policy. It must only read: every
// command it sends is on a fixed allowlist of show commands, and it never
// changes, saves, or announces anything. Credentials and socket paths come
// from the environment and never appear in an error or a finding. It is
// in-process only.
type RouterCheck interface {
	Lifecycle
	// CheckFilters reports whether the import policy from q.Packeteer
	// accepts only routes with q.Community, and whether every eBGP
	// session's export policy rejects it. An error means the router could
	// not be read at all.
	CheckFilters(ctx context.Context, q FilterQuery) ([]FilterFinding, error)
}
