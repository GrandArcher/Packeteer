package plugin

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventSpec describes one event kind in the catalog. docs/EVENTS.md is the
// operator-facing copy of this table.
type EventSpec struct {
	// Kind is the dotted name carried in Event.Kind.
	Kind string `json:"kind"`
	// Severity is the default severity.
	Severity Severity `json:"severity"`
	// Summary says when the event fires.
	Summary string `json:"summary"`
	// Group ties a problem to the event that clears it (provider.down and
	// provider.up share "provider"). Keys are the fields that identify one
	// incident inside the group. Together they form Event.DedupKey.
	Group string   `json:"group"`
	Keys  []string `json:"keys,omitempty"`
	// Resolves is true when this kind clears an open problem of its group.
	Resolves bool `json:"resolves,omitempty"`
	// TrapID is the last arc of the SNMP notification OID. It is stable:
	// new kinds get new numbers and numbers are never reused.
	TrapID int `json:"trap_id"`
}

// Event kinds. Every kind the controller emits is in EventCatalog.
const (
	EventControllerStarted  = "controller.started"
	EventControllerStopping = "controller.stopping"
	EventImprovementAdded   = "improvement.added"
	EventImprovementSwitch  = "improvement.switched"
	EventImprovementRemoved = "improvement.removed"
	EventProviderDown       = "provider.down"
	EventProviderUp         = "provider.up"
	EventProviderDegraded   = "provider.degraded"
	EventBGPSessionDown     = "bgp.session_down"
	EventBGPSessionUp       = "bgp.session_up"
	EventBGPSessionStuck    = "bgp.session_not_established"
	EventCommitExceeded     = "commit.exceeded"
	EventCommitCleared      = "commit.cleared"
	EventAnnounceFailed     = "announce.failed"
	EventAnnounceRecovered  = "announce.recovered"
	EventOutageAS           = "outage.as"
	EventOutageCircuit      = "outage.circuit"
	EventOutageCleared      = "outage.cleared"
	EventInboundSteered     = "inbound.steered"
	EventInboundReleased    = "inbound.released"
	EventMitigationAdded    = "mitigation.added"
	EventMitigationOn       = "mitigation.announced"
	EventMitigationOff      = "mitigation.withdrawn"
	EventMitigationEnded    = "mitigation.ended"
	EventAnomalyDetected    = "anomaly.detected"
	EventAnomalyMitigated   = "anomaly.mitigated"
	EventAnomalyHeld        = "anomaly.held"
	EventAnomalyCleared     = "anomaly.cleared"
	EventLeakDetected       = "leak.detected"
	EventLeakCleared        = "leak.cleared"
	EventFlapQuarantined    = "flap.quarantined"
	EventFlapReleased       = "flap.released"
	EventExchangeDegraded   = "exchange.degraded"
	EventExchangeRecovered  = "exchange.recovered"
	EventExchangePeerDown   = "exchange.peer_down"
	EventExchangePeerUp     = "exchange.peer_up"
	EventExchangeMaxPrefix  = "exchange.max_prefix"
	// EventExchangeMaxPrefixCleared resolves EventExchangeMaxPrefix.
	EventExchangeMaxPrefixCleared = "exchange.max_prefix_cleared"
	// EventIXPKeyExpiring fires when the IXP Manager API key has 14 days
	// or fewer left, or is already past its expiry date (#161).
	EventIXPKeyExpiring = "ixp.api_key_expiring"
	// EventIXPKeyOK resolves EventIXPKeyExpiring once the key is more
	// than 14 days from expiry.
	EventIXPKeyOK = "ixp.api_key_ok"
	// Route-server watch (#164). Each problem has a resolving event.
	EventRSUnreachable      = "ixp.rs_unreachable"
	EventRSReachable        = "ixp.rs_reachable"
	EventRSSessionDown      = "ixp.rs_session_down"
	EventRSSessionUp        = "ixp.rs_session_up"
	EventRSMaxPrefix        = "ixp.rs_max_prefix"
	EventRSMaxPrefixCleared = "ixp.rs_max_prefix_cleared"
	EventRSFiltered         = "ixp.rs_filtered"
	EventRSFilteredCleared  = "ixp.rs_filtered_cleared"
	// Route-server signals (#165). Each problem has a resolving event.
	EventRSOriginChange        = "ixp.rs_origin_change"
	EventRSOriginChangeCleared = "ixp.rs_origin_change_cleared"
	EventRSMoreSpecific        = "ixp.rs_morespecific_burst"
	EventRSMoreSpecificCleared = "ixp.rs_morespecific_burst_cleared"
	EventRSFilterSpike         = "ixp.rs_filter_spike"
	EventRSFilterSpikeCleared  = "ixp.rs_filter_spike_cleared"
	// Fabric incident correlation (#163). Each problem has a resolving event.
	EventFabricDegraded  = "ixp.fabric_degraded"
	EventFabricRecovered = "ixp.fabric_recovered"
	EventMemberDegraded  = "ixp.member_degraded"
	EventMemberRecovered = "ixp.member_recovered"
	// EventHerdRestarted fires when a herd goroutine panics and is restarted
	// with backoff (#260). Probing and BGP are not affected.
	EventHerdRestarted = "herd.restarted"
	EventHAStandby     = "ha.standby"
	EventHAActive      = "ha.active"
	// EventAudit is one audit log record (#32): a change or sign-in on
	// the ops API, or a config reload.
	EventAudit = "audit.recorded"
	// EventTest is sent by hand to check a notifier's delivery path.
	EventTest = "notifier.test"
)

var eventCatalog = []EventSpec{
	{Kind: EventControllerStarted, Severity: SeverityInfo, Group: "controller", TrapID: 1,
		Summary: "The controller started and its plugins are running.", Resolves: true},
	{Kind: EventControllerStopping, Severity: SeverityWarning, Group: "controller", TrapID: 2,
		Summary: "The controller is shutting down and has withdrawn its routes."},
	{Kind: EventImprovementAdded, Severity: SeverityInfo, Group: "improvement", Keys: []string{"prefix"}, TrapID: 3,
		Summary: "A prefix was steered to a better provider (announced in inject; in observe and suggest a recommendation that is logged only)."},
	{Kind: EventImprovementSwitch, Severity: SeverityInfo, Group: "improvement", Keys: []string{"prefix"}, TrapID: 4,
		Summary: "An existing improvement moved to another provider."},
	{Kind: EventImprovementRemoved, Severity: SeverityInfo, Group: "improvement", Keys: []string{"prefix"}, TrapID: 5, Resolves: true,
		Summary: "An improvement was retired: native path recovered, stale data, RIB loss, policy, maintenance, or TTL."},
	{Kind: EventProviderDown, Severity: SeverityCritical, Group: "provider", Keys: []string{"provider"}, TrapID: 6,
		Summary: "A provider is down: its probe source failed, every probe through it got no reply, or its mean loss is at or above probe.down_loss_pct."},
	{Kind: EventProviderUp, Severity: SeverityInfo, Group: "provider", Keys: []string{"provider"}, TrapID: 7, Resolves: true,
		Summary: "A provider is healthy again. Resolves provider.down and provider.degraded."},
	{Kind: EventBGPSessionDown, Severity: SeverityCritical, Group: "bgp", Keys: []string{"neighbor"}, TrapID: 8,
		Summary: "An established iBGP session to an edge router went down."},
	{Kind: EventBGPSessionUp, Severity: SeverityInfo, Group: "bgp", Keys: []string{"neighbor"}, TrapID: 9, Resolves: true,
		Summary: "An iBGP session to an edge router reached Established. Resolves bgp.session_down and bgp.session_not_established."},
	{Kind: EventProviderDegraded, Severity: SeverityWarning, Group: "provider", Keys: []string{"provider"}, TrapID: 61,
		Summary: "A provider's mean loss is at or above probe.degraded_loss_pct but below probe.down_loss_pct."},
	{Kind: EventBGPSessionStuck, Severity: SeverityCritical, Group: "bgp", Keys: []string{"neighbor"}, TrapID: 62,
		Summary: "An iBGP session has not reached Established within bgp.not_established_after of the start."},
	{Kind: EventCommitExceeded, Severity: SeverityWarning, Group: "commit", Keys: []string{"provider"}, TrapID: 10,
		Summary: "A provider's billable 95th percentile for the open period is above its commit."},
	{Kind: EventCommitCleared, Severity: SeverityInfo, Group: "commit", Keys: []string{"provider"}, TrapID: 11, Resolves: true,
		Summary: "A provider's billable 95th percentile is back at or below its commit."},
	{Kind: EventAnnounceFailed, Severity: SeverityCritical, Group: "announce", TrapID: 12,
		Summary: "Syncing improvements to the announcer failed."},
	{Kind: EventAnnounceRecovered, Severity: SeverityInfo, Group: "announce", TrapID: 13, Resolves: true,
		Summary: "Syncing improvements to the announcer succeeded after a failure."},
	{Kind: EventOutageAS, Severity: SeverityCritical, Group: "outage", Keys: []string{"asn", "provider"}, TrapID: 14,
		Summary: "The outage source found several prefixes degraded behind one ASN on every provider."},
	{Kind: EventOutageCircuit, Severity: SeverityCritical, Group: "outage", Keys: []string{"asn", "provider"}, TrapID: 15,
		Summary: "The outage source found several prefixes degraded on one provider only."},
	{Kind: EventOutageCleared, Severity: SeverityWarning, Group: "outage", Keys: []string{"asn", "provider"}, TrapID: 16, Resolves: true,
		Summary: "An AS or circuit incident recovered."},
	{Kind: EventTest, Severity: SeverityInfo, Group: "notifier", TrapID: 17,
		Summary: "A test event, sent only by -notify-test."},
	{Kind: EventInboundSteered, Severity: SeverityWarning, Group: "inbound", Keys: []string{"provider"}, TrapID: 18,
		Summary: "Inbound commit control is steering inbound traffic away from a provider (announced in inject, suggested only in observe and suggest)."},
	{Kind: EventInboundReleased, Severity: SeverityInfo, Group: "inbound", Keys: []string{"provider"}, TrapID: 19, Resolves: true,
		Summary: "An inbound steer was released: back under commit, stale telemetry, or TTL."},
	{Kind: EventMitigationAdded, Severity: SeverityWarning, Group: "mitigation", Keys: []string{"rule"}, TrapID: 20,
		Summary: "A threat mitigation rule (RTBH, redirect, or FlowSpec) was added or replaced (a dry run in observe)."},
	{Kind: EventMitigationOn, Severity: SeverityWarning, Group: "mitigation", Keys: []string{"rule"}, TrapID: 21,
		Summary: "Every route of a threat mitigation rule is on the wire."},
	{Kind: EventMitigationOff, Severity: SeverityWarning, Group: "mitigation", Keys: []string{"rule"}, TrapID: 22,
		Summary: "A threat mitigation rule's routes were withdrawn while the rule is still held (RIB loss, shutdown, announce failure)."},
	{Kind: EventMitigationEnded, Severity: SeverityInfo, Group: "mitigation", Keys: []string{"rule"}, TrapID: 23, Resolves: true,
		Summary: "A threat mitigation rule ended: expired, removed, or replaced. Its routes are withdrawn."},
	{Kind: EventHAStandby, Severity: SeverityWarning, Group: "ha", TrapID: 24,
		Summary: "This instance stopped being the active one of its HA pair and withdrew its routes (lease lost or not renewed, RIB not ready, or shutdown)."},
	{Kind: EventHAActive, Severity: SeverityWarning, Group: "ha", TrapID: 25, Resolves: true,
		Summary: "This instance became the active one of its HA pair and may announce."},
	{Kind: EventAudit, Severity: SeverityInfo, Group: "audit", TrapID: 26,
		Summary: "An audit log record: a change, denied change, or sign-in on the ops API, or a config reload."},
	{Kind: EventAnomalyDetected, Severity: SeverityCritical, Group: "anomaly", Keys: []string{"anomaly"}, TrapID: 27,
		Summary: "Traffic toward a prefix and protocol is far above its learned baseline (a possible DDoS)."},
	{Kind: EventAnomalyMitigated, Severity: SeverityWarning, Group: "anomaly", Keys: []string{"anomaly"}, TrapID: 28,
		Summary: "An anomaly rule matched and the detector added a mitigation rule (a dry run when mitigation.mode is observe)."},
	{Kind: EventAnomalyHeld, Severity: SeverityWarning, Group: "anomaly", Keys: []string{"anomaly"}, TrapID: 29,
		Summary: "An anomaly rule matched but no mitigation rule was added, or it ended early: not an exact learned prefix, HA standby, max_active, max_actions_per_hour, max_rules, or refused."},
	{Kind: EventAnomalyCleared, Severity: SeverityInfo, Group: "anomaly", Keys: []string{"anomaly"}, TrapID: 30, Resolves: true,
		Summary: "An anomaly ended (traffic back within its baseline, or flow data unavailable); the mitigation rule it added is removed."},
	{Kind: EventLeakDetected, Severity: SeverityCritical, Group: "leak", Keys: []string{"prefix"}, TrapID: 31,
		Summary: "A route carrying packeteer_community, or an injected prefix with the local ASN in its path, was seen outside the AS. The route is withdrawn and held out until an operator clears it."},
	{Kind: EventLeakCleared, Severity: SeverityInfo, Group: "leak", Keys: []string{"prefix"}, TrapID: 32, Resolves: true,
		Summary: "An operator cleared the hold on a leaked prefix; it may be announced again."},
	{Kind: EventFlapQuarantined, Severity: SeverityWarning, Group: "flap", Keys: []string{"prefix"}, TrapID: 33,
		Summary: "A prefix changed its chosen provider too often. Its route is withdrawn and it stays on the native path until the cool-down ends or an operator releases it."},
	{Kind: EventFlapReleased, Severity: SeverityInfo, Group: "flap", Keys: []string{"prefix"}, TrapID: 34, Resolves: true,
		Summary: "A flap quarantine ended: the cool-down elapsed, an operator released the prefix, or the feature was turned off."},
	{Kind: EventExchangeDegraded, Severity: SeverityWarning, Group: "exchange", Keys: []string{"exchange"}, TrapID: 35,
		Summary: "Enough peers on one exchange fail their next-hop probe inside the window to point at the exchange or our port, not one member. Measurement only."},
	{Kind: EventExchangeRecovered, Severity: SeverityInfo, Group: "exchange", Keys: []string{"exchange"}, TrapID: 36, Resolves: true,
		Summary: "Too few peers on the exchange are degraded for the alert to hold."},
	{Kind: EventExchangePeerDown, Severity: SeverityWarning, Group: "exchange_peer", Keys: []string{"exchange", "peer", "router"}, TrapID: 37,
		Summary: "A monitored router reported an exchange peer's BGP session down; the reason is decoded from BMP (including Cease subcode 1, maximum prefixes)."},
	{Kind: EventExchangePeerUp, Severity: SeverityInfo, Group: "exchange_peer", Keys: []string{"exchange", "peer", "router"}, TrapID: 38, Resolves: true,
		Summary: "A monitored router reported the exchange peer's BGP session up."},
	{Kind: EventExchangeMaxPrefix, Severity: SeverityWarning, Group: "exchange_prefix", Keys: []string{"exchange", "peer", "router"}, TrapID: 39,
		Summary: "An exchange peer's Adj-RIB-In reached the configured share of its max_prefix (exchanges[].max_prefix_warn_pct)."},
	{Kind: EventExchangeMaxPrefixCleared, Severity: SeverityInfo, Group: "exchange_prefix", Keys: []string{"exchange", "peer", "router"}, TrapID: 40, Resolves: true,
		Summary: "The exchange peer's Adj-RIB-In fell back below the max-prefix warning share."},
	{Kind: EventIXPKeyExpiring, Severity: SeverityWarning, Group: "ixp_api_key", Keys: []string{"identifier"}, TrapID: 41,
		Summary: "The IXP Manager API key expires within 14 days, or has already expired. The field identifier is the key id; the secret is not included."},
	{Kind: EventIXPKeyOK, Severity: SeverityInfo, Group: "ixp_api_key", Keys: []string{"identifier"}, TrapID: 42, Resolves: true,
		Summary: "The IXP Manager API key has more than 14 days left. Resolves ixp.api_key_expiring."},
	{Kind: EventRSUnreachable, Severity: SeverityWarning, Group: "ixp_rs", Keys: []string{"server"}, TrapID: 43,
		Summary: "Birdseye on a route server failed two polls in a row. Its sessions keep their last state until the data is stale."},
	{Kind: EventRSReachable, Severity: SeverityInfo, Group: "ixp_rs", Keys: []string{"server"}, TrapID: 44, Resolves: true,
		Summary: "Birdseye on the route server answered again. Resolves ixp.rs_unreachable."},
	{Kind: EventRSSessionDown, Severity: SeverityWarning, Group: "ixp_rs_session", Keys: []string{"server", "session"}, TrapID: 45,
		Summary: "A member session on a route server is not Established."},
	{Kind: EventRSSessionUp, Severity: SeverityInfo, Group: "ixp_rs_session", Keys: []string{"server", "session"}, TrapID: 46, Resolves: true,
		Summary: "The member session is Established again, or is no longer on the route server. Resolves ixp.rs_session_down."},
	{Kind: EventRSMaxPrefix, Severity: SeverityWarning, Group: "ixp_rs_prefix", Keys: []string{"server", "session"}, TrapID: 47,
		Summary: "Accepted routes from a member session reached the warning share of its max_prefix."},
	{Kind: EventRSMaxPrefixCleared, Severity: SeverityInfo, Group: "ixp_rs_prefix", Keys: []string{"server", "session"}, TrapID: 48, Resolves: true,
		Summary: "Accepted routes fell back below the warning share, or the session is gone. Resolves ixp.rs_max_prefix."},
	{Kind: EventRSFiltered, Severity: SeverityWarning, Group: "ixp_rs_filtered", Keys: []string{"server", "session"}, TrapID: 49,
		Summary: "A member session has at least the warning share of its routes tagged rs-asn:1101:x (filtered by the route server)."},
	{Kind: EventRSFilteredCleared, Severity: SeverityInfo, Group: "ixp_rs_filtered", Keys: []string{"server", "session"}, TrapID: 50, Resolves: true,
		Summary: "The filtered share fell back below the warning share, or the session is gone. Resolves ixp.rs_filtered."},
	{Kind: EventFabricDegraded, Severity: SeverityWarning, Group: "ixp_fabric", Keys: []string{"scope", "ixp_id", "group"}, TrapID: 51,
		Summary: "Many members behind one switch, colo, or core bundle are past the ping tolerance together: a fabric problem, not a member problem."},
	{Kind: EventFabricRecovered, Severity: SeverityInfo, Group: "ixp_fabric", Keys: []string{"scope", "ixp_id", "group"}, TrapID: 52, Resolves: true,
		Summary: "The group is below the thresholds, has no measured members, or the fabric data went stale. Resolves ixp.fabric_degraded."},
	{Kind: EventMemberDegraded, Severity: SeverityWarning, Group: "ixp_member", Keys: []string{"asn"}, TrapID: 53,
		Summary: "One member is past the ping tolerance on every measured address while the groups behind it are not degraded: a member problem."},
	{Kind: EventMemberRecovered, Severity: SeverityInfo, Group: "ixp_member", Keys: []string{"asn"}, TrapID: 54, Resolves: true,
		Summary: "The member is back within tolerance, is part of a degraded group, or the fabric data went stale. Resolves ixp.member_degraded."},
	{Kind: EventRSOriginChange, Severity: SeverityWarning, Group: "ixp_rs_origin", Keys: []string{"server", "session"}, TrapID: 55,
		Summary: "A member session announces a prefix with an origin AS that no other member's accepted route for the same prefix has: a possible hijack or leak."},
	{Kind: EventRSOriginChangeCleared, Severity: SeverityInfo, Group: "ixp_rs_origin", Keys: []string{"server", "session"}, TrapID: 56, Resolves: true,
		Summary: "The conflicting routes are gone, or the session is gone. Resolves ixp.rs_origin_change."},
	{Kind: EventRSMoreSpecific, Severity: SeverityWarning, Group: "ixp_rs_morespecific", Keys: []string{"server", "session"}, TrapID: 57,
		Summary: "A member session announced a burst of more-specifics of prefixes another member's route covers, with a different origin AS."},
	{Kind: EventRSMoreSpecificCleared, Severity: SeverityInfo, Group: "ixp_rs_morespecific", Keys: []string{"server", "session"}, TrapID: 58, Resolves: true,
		Summary: "The burst's more-specifics are gone, or the session is gone. Resolves ixp.rs_morespecific_burst."},
	{Kind: EventRSFilterSpike, Severity: SeverityWarning, Group: "ixp_rs_spike", Keys: []string{"server", "session", "reason"}, TrapID: 59,
		Summary: "The routes a route server filtered from a member for one reason (RPKI invalid, IRR prefix or origin, transit-free ASN) jumped above the recent level."},
	{Kind: EventRSFilterSpikeCleared, Severity: SeverityInfo, Group: "ixp_rs_spike", Keys: []string{"server", "session", "reason"}, TrapID: 60, Resolves: true,
		Summary: "The filtered count fell back below the spike threshold, or the session is gone. Resolves ixp.rs_filter_spike."},
	{Kind: EventHerdRestarted, Severity: SeverityInfo, Group: "herd", TrapID: 61,
		Summary: "A herd goroutine (recorder or puller) panicked and was restarted with backoff. Probing, decisions, and the announcer are not affected."},
}

// EventCatalog returns a copy of every event kind the controller emits.
func EventCatalog() []EventSpec {
	out := make([]EventSpec, len(eventCatalog))
	for i, s := range eventCatalog {
		s.Keys = append([]string(nil), s.Keys...)
		out[i] = s
	}
	return out
}

// LookupEvent returns the catalog entry for kind.
func LookupEvent(kind string) (EventSpec, bool) {
	for _, s := range eventCatalog {
		if s.Kind == kind {
			return s, true
		}
	}
	return EventSpec{}, false
}

// NewEvent builds an event with the catalog severity for kind. An unknown
// kind is info.
func NewEvent(kind string, now time.Time, msg string, fields map[string]string) Event {
	sev := SeverityInfo
	if s, ok := LookupEvent(kind); ok {
		sev = s.Severity
	}
	return Event{Time: now, Kind: kind, Severity: sev, Message: msg, Fields: fields}
}

// DedupKey identifies one incident: the catalog group plus the key fields
// that are set. A problem and the event that resolves it share the key,
// so a pager can open and close the same alert. Unknown kinds use the kind.
func (e Event) DedupKey() string {
	s, ok := LookupEvent(e.Kind)
	if !ok {
		return "packeteer/" + e.Kind
	}
	parts := []string{"packeteer", s.Group}
	for _, k := range s.Keys {
		if v := e.Fields[k]; v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, "/")
}

// Resolves reports whether e clears an open problem (catalog Resolves).
func (e Event) Resolves() bool {
	s, ok := LookupEvent(e.Kind)
	return ok && s.Resolves
}

var severityRank = map[Severity]int{SeverityInfo: 0, SeverityWarning: 1, SeverityCritical: 2}

// groupRank is the highest severity of the problem kinds in each group. A
// resolving event is filtered at that rank, so whoever was told about
// provider.down (critical) is also told about provider.up (info).
var groupRank = func() map[string]int {
	m := map[string]int{}
	for _, s := range eventCatalog {
		if s.Resolves {
			continue
		}
		if r := severityRank[s.Severity]; r > m[s.Group] {
			m[s.Group] = r
		}
	}
	return m
}()

// SeverityRank orders severities: info < warning < critical.
func SeverityRank(s Severity) (int, bool) {
	r, ok := severityRank[s]
	return r, ok
}

// SeveritiesFrom lists the severities at min or above, lowest first. An
// empty or unknown min lists them all.
func SeveritiesFrom(min Severity) []Severity {
	var out []Severity
	for _, s := range []Severity{SeverityInfo, SeverityWarning, SeverityCritical} {
		if severityRank[s] >= severityRank[min] {
			out = append(out, s)
		}
	}
	return out
}

// EventFilter is the per-notifier filter and rate limit. Notifiers embed it
// inline in their config block, so the keys sit next to the plugin's own.
type EventFilter struct {
	// Events lists kinds to deliver. An entry is a kind ("provider.down"),
	// a group wildcard ("improvement.*"), or "*". Empty means every kind.
	Events []string `yaml:"events"`
	// MinSeverity drops events below this level (info, warning, critical).
	MinSeverity Severity `yaml:"min_severity"`
	// RateLimit caps deliveries per RateWindow. Zero is unlimited.
	RateLimit int `yaml:"rate_limit"`
	// RateWindow is the rate-limit window (default 1m).
	RateWindow time.Duration `yaml:"rate_window"`
}

// Rate-limit bounds.
const (
	DefaultRateWindow = time.Minute
	MaxRateLimit      = 100000
	MaxRateWindow     = 24 * time.Hour
)

// EventGate applies an EventFilter. Match is stateless; Allow also spends
// the rate limit. It is safe for concurrent use.
type EventGate struct {
	patterns []string
	min      int
	limit    int
	window   time.Duration

	mu         sync.Mutex
	start      time.Time
	count      int
	suppressed int
}

// NewEventGate validates f. Every pattern must match at least one catalog
// kind, so a typo is a startup error instead of silence.
func NewEventGate(f EventFilter) (*EventGate, error) {
	g := &EventGate{}
	if f.MinSeverity == "" {
		f.MinSeverity = SeverityInfo
	}
	r, ok := SeverityRank(f.MinSeverity)
	if !ok {
		return nil, fmt.Errorf("min_severity %q is invalid (want info, warning, critical)", f.MinSeverity)
	}
	g.min = r
	for i, p := range f.Events {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("events[%d]: empty", i)
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("events[%d]: bad pattern %q", i, p)
		}
		hit := false
		for _, s := range eventCatalog {
			if ok, _ := path.Match(p, s.Kind); ok {
				hit = true
				break
			}
		}
		if !hit {
			return nil, fmt.Errorf("events[%d]: %q matches no event kind (see docs/EVENTS.md)", i, p)
		}
		g.patterns = append(g.patterns, p)
	}
	if f.RateLimit < 0 || f.RateLimit > MaxRateLimit {
		return nil, fmt.Errorf("rate_limit %d must be between 0 and %d", f.RateLimit, MaxRateLimit)
	}
	if f.RateWindow < 0 || f.RateWindow > MaxRateWindow {
		return nil, fmt.Errorf("rate_window %s must be between 0 and %s", f.RateWindow, MaxRateWindow)
	}
	if f.RateWindow > 0 && f.RateWindow < time.Second {
		return nil, fmt.Errorf("rate_window %s must be at least 1s", f.RateWindow)
	}
	if f.RateWindow == 0 {
		f.RateWindow = DefaultRateWindow
	}
	g.limit, g.window = f.RateLimit, f.RateWindow
	return g, nil
}

// Match reports whether e passes the kind and severity filters. A resolving
// kind passes min_severity when the problem it clears would. A nil gate
// matches everything.
func (g *EventGate) Match(e Event) bool {
	if g == nil {
		return true
	}
	if r, ok := SeverityRank(e.Severity); ok && r < g.min {
		s, known := LookupEvent(e.Kind)
		if !known || !s.Resolves || groupRank[s.Group] < g.min {
			return false
		}
	}
	if len(g.patterns) == 0 {
		return true
	}
	for _, p := range g.patterns {
		if ok, _ := path.Match(p, e.Kind); ok {
			return true
		}
	}
	return false
}

// Allow is Match plus the rate limit, in fixed windows. When it returns
// true, suppressed is how many matching events the limit dropped since the
// last delivery, so the receiver can see that it missed some.
func (g *EventGate) Allow(e Event, now time.Time) (ok bool, suppressed int) {
	if g == nil {
		return true, 0
	}
	if !g.Match(e) {
		return false, 0
	}
	if g.limit == 0 {
		return true, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.start.IsZero() || now.Sub(g.start) >= g.window || now.Before(g.start) {
		g.start, g.count = now, 0
	}
	if g.count >= g.limit {
		g.suppressed++
		return false, 0
	}
	g.count++
	suppressed, g.suppressed = g.suppressed, 0
	return true, suppressed
}

// Gated is implemented by notifiers that carry an EventGate. The
// controller's dispatcher consults it before calling Notify, so filters
// and rate limits apply the same way to every notifier type.
type Gated interface {
	EventGate() *EventGate
}

// WithSuppressed returns a copy of e with the suppressed count in Fields.
func (e Event) WithSuppressed(n int) Event {
	if n <= 0 {
		return e
	}
	f := make(map[string]string, len(e.Fields)+1)
	for k, v := range e.Fields {
		f[k] = v
	}
	f["suppressed"] = strconv.Itoa(n)
	e.Fields = f
	return e
}

// Source names where an event comes from: the catalog group, or the part
// of the kind before the first dot for a kind that is not in the catalog.
func (e Event) Source() string {
	if s, ok := LookupEvent(e.Kind); ok {
		return s.Group
	}
	group, _, _ := strings.Cut(e.Kind, ".")
	return group
}

// EventQuery selects stored events whose Time is in [From, To). A zero
// bound is open. MinSeverity keeps events at that severity or above; an
// empty value keeps all. Text keeps events whose kind, message, or field
// names and values contain it, ignoring case. Limit caps the rows
// (newest first); zero means no cap.
type EventQuery struct {
	From        time.Time
	To          time.Time
	MinSeverity Severity
	Text        string
	Limit       int
}

// Match reports whether e is selected by q. Limit is not checked.
func (q EventQuery) Match(e Event) bool {
	if !q.From.IsZero() && e.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && !e.Time.Before(q.To) {
		return false
	}
	if q.MinSeverity != "" && severityRank[e.Severity] < severityRank[q.MinSeverity] {
		return false
	}
	if q.Text == "" {
		return true
	}
	text := strings.ToLower(q.Text)
	if strings.Contains(strings.ToLower(e.Kind), text) || strings.Contains(strings.ToLower(e.Message), text) {
		return true
	}
	for k, v := range e.Fields {
		if strings.Contains(strings.ToLower(k), text) || strings.Contains(strings.ToLower(v), text) {
			return true
		}
	}
	return false
}

// EventStore is optional on a storage plugin: recent events for the Events
// page. Rows older than the plugin's retention are deleted. It never
// announces and never changes a decision.
type EventStore interface {
	AppendEvent(ctx context.Context, e Event) error
	// Events returns matching events, newest first.
	Events(ctx context.Context, q EventQuery) ([]Event, error)
}
