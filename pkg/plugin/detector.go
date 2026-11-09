package plugin

import (
	"context"
	"net/netip"
	"time"
)

// ---- Traffic anomaly detection (#33) ----
//
// A detector learns a baseline of traffic toward each destination prefix
// and IP protocol from flow data and reports the keys that are far above
// it. A detector never announces and never adds a mitigation rule itself:
// the core turns an anomaly into a mitigation rule only when an explicit
// anomaly rule in config matches it, rate-limited and capped, and the
// mitigation controller still applies its own allowlist, exact learned
// prefix check, cap, TTL, community, and NO_EXPORT. It is in-process only,
// because its output can lead to an announcement.

// KindDetector is the anomaly detection extension point.
const KindDetector Kind = "detector"

// Detectors holds the detector plugin types.
var Detectors = NewRegistry[Detector](KindDetector)

// FlowCounter is traffic seen toward one destination prefix with one IP
// protocol, counted since the source started. Bytes only grows, except
// when the source forgets an idle key; the core treats a counter that went
// down as restarted. Protocol is 0 when the export did not carry one.
type FlowCounter struct {
	Prefix   netip.Prefix
	Protocol IPProtocol
	Bytes    uint64
}

// FlowCounterSource is optional on a target source that sees flows. The
// anomaly controller reads it on its own interval and turns the counter
// deltas into rates. It must not announce routes.
type FlowCounterSource interface {
	FlowCounters(ctx context.Context) ([]FlowCounter, error)
}

// TrafficKey names one baseline: a destination prefix and an IP protocol.
type TrafficKey struct {
	Prefix   netip.Prefix
	Protocol IPProtocol
}

// String is "prefix/proto", e.g. "198.51.100.0/24 udp".
func (k TrafficKey) String() string {
	if k.Protocol == 0 {
		return k.Prefix.String() + " any"
	}
	return k.Prefix.String() + " " + k.Protocol.String()
}

// TrafficSample is the rate toward one key over one detection interval,
// in decimal megabits per second.
type TrafficSample struct {
	Key  TrafficKey
	Mbps float64
}

// Anomaly is one key the detector finds far above its baseline.
type Anomaly struct {
	Key TrafficKey
	// Mbps is the latest rate; PeakMbps the highest since Since.
	Mbps     float64
	PeakMbps float64
	// BaselineMbps is the learned normal rate (zero when the key had no
	// baseline yet and a static ceiling fired).
	BaselineMbps float64
	// Reason says which test fired, e.g. "4.2 standard deviations and
	// 12.0x above baseline" or "above max_mbps 1000".
	Reason string
	// Since is when the anomaly was first reported.
	Since time.Time
}

// Detector keeps baselines and reports anomalies. Observe is called once
// per detection interval with one sample per key that had traffic; keys it
// tracks and that are missing had none. It returns every anomaly that is
// active after the round, sorted by key. It must not block and must not do
// I/O; it is called from a single goroutine.
type Detector interface {
	Lifecycle
	Observe(now time.Time, samples []TrafficSample) []Anomaly
	// Tracked is how many keys have a baseline.
	Tracked() int
	// Reset forgets every baseline and open anomaly. The core calls it
	// when the flow data went stale, so detection starts learning again.
	Reset()
}
