package plugin

import (
	"context"
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
	// usable and inside the rule's loss (and optional latency) ceiling.
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
	// Traffic is the prefix's traffic class from flow data: TrafficTransit
	// when most of its bytes come from customer (transiting) sources,
	// TrafficLocal otherwise. It is empty when no source classifies the
	// prefix.
	Traffic string
}

// Traffic classes of a probed prefix.
const (
	// TrafficLocal is traffic sourced by the operator's own network.
	TrafficLocal = "local"
	// TrafficTransit is traffic that transits the network: its source is
	// a customer network, not the operator's own.
	TrafficTransit = "transit"
)

// TrafficMix is the classified traffic toward one prefix over a source's
// window. Bytes whose source address is unknown are in neither count.
// Class is TrafficTransit or TrafficLocal, decided by the source.
type TrafficMix struct {
	Prefix       netip.Prefix
	LocalBytes   uint64
	TransitBytes uint64
	Class        string
}

// TransitPct is the transit share of the classified bytes, 0-100.
func (m TrafficMix) TransitPct() float64 {
	total := m.LocalBytes + m.TransitBytes
	if total == 0 {
		return 0
	}
	return 100 * float64(m.TransitBytes) / float64(total)
}

// TrafficClassifier is optional on a TargetSource. It reports how the
// traffic toward each prefix splits between local and transit sources and
// the resulting class. The controller passes the class to the policy chain
// in PolicySubject.Traffic. It does not announce.
type TrafficClassifier interface {
	TrafficMix(ctx context.Context) ([]TrafficMix, error)
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
	// MaxLossPct and MaxRTT are the ceiling a PolicyStatic path must stay
	// inside, before the pin is announced and while it is held. MaxRTT 0
	// means no latency ceiling.
	MaxLossPct float64
	MaxRTT     time.Duration
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
