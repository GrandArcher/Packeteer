package plugin

import (
	"net/netip"
	"time"
)

// ---- Policy ----
//
// A policy is a filter in front of the scorer. The controller asks the
// configured policy chain about every probed prefix before each decision.
// The first policy that matches decides the prefix's verdict. Policies only
// restrict or pin what Decide may choose; they cannot bypass the allowlist,
// the learned RIB, community tagging, the improvement cap, or withdraw on
// failure. A policy must not announce routes or touch the network.

// Policy actions.
const (
	// PolicyIgnore leaves the prefix on native routing. Any active
	// improvement is retired and no new one is made.
	PolicyIgnore = "ignore"
	// PolicyAllow lets only the listed providers carry an improvement.
	PolicyAllow = "allow"
	// PolicyDeny never lets the listed providers carry an improvement.
	PolicyDeny = "deny"
	// PolicyStatic pins the prefix to one provider while its path is
	// usable, regardless of performance thresholds.
	PolicyStatic = "static"
	// PolicyVIP ranks the prefix's performance moves ahead of other
	// performance moves when max_improvements binds.
	PolicyVIP = "vip"
)

// CauseStatic is an improvement made by a static policy. It is not a
// performance win.
const CauseStatic = "static"

// PolicySubject is what a policy may match on.
type PolicySubject struct {
	Prefix netip.Prefix
	// ASPath is the learned AS path of the prefix, origin last. It is
	// empty when the prefix is not in the RIB or no RIB is configured.
	ASPath []uint32
}

// OriginASN is the last ASN on the path, or 0 when the path is empty.
func (s PolicySubject) OriginASN() uint32 {
	if len(s.ASPath) == 0 {
		return 0
	}
	return s.ASPath[len(s.ASPath)-1]
}

// PolicyVerdict is the outcome of a match.
type PolicyVerdict struct {
	Action string
	// Providers is the allow or deny list, or the single pinned provider
	// for PolicyStatic. It is empty for PolicyIgnore and PolicyVIP.
	Providers []string
	// Rule names the rule that matched, and Match says why (for example
	// "prefix 198.51.100.0/24"). Both are for operators and logs.
	Rule  string
	Match string
}

// Policy matches prefixes to verdicts. Match must be safe for concurrent
// use and must not block on I/O.
type Policy interface {
	Lifecycle
	Match(s PolicySubject) (PolicyVerdict, bool)
}

// MaintenanceWindow is a period during which providers carry no
// improvements.
type MaintenanceWindow struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Providers []string  `json:"providers"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	// Source is "schedule" for a configured window or "api" for one opened
	// on demand.
	Source string `json:"source"`
	Reason string `json:"reason,omitempty"`
}

// Maintenance is optional on a Policy. Active returns the windows open at
// now. Decide treats every provider in an open window as excluded: active
// improvements on it are retired and no move may land on it.
type Maintenance interface {
	Active(now time.Time) []MaintenanceWindow
}
