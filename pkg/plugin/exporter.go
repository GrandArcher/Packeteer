package plugin

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// KindExporter is the extension point that pushes decisions, events,
// enriched flow records, and metric samples to an external pipeline (#207,
// #287). An exporter only reads: it never announces and never feeds Decide.
const KindExporter Kind = "exporter"

// Export streams. An exporter lists the ones it takes in its config.
const (
	StreamEvents    = "events"
	StreamDecisions = "decisions"
	StreamFlows     = "flows"
	StreamMetrics   = "metrics"
)

// Exporters is the registry of exporter types.
var Exporters = NewRegistry[Exporter](KindExporter)

// DecisionRecord is one change to an improvement, as the decision loop
// reported it. It is sent in every mode, and in observe and suggest it
// says what Packeteer recommends, not what was announced.
type DecisionRecord struct {
	Time time.Time `json:"time"`
	// ID names the improvement. It is the same on the flow records the
	// improvement tags and on the improvement.* events.
	ID       string `json:"id"`
	Action   string `json:"action"` // improve, switch, retire
	Mode     string `json:"mode"`
	Prefix   string `json:"prefix"`
	Provider string `json:"provider"`
	Native   string `json:"native"`
	Cause    string `json:"cause,omitempty"`
	Reason   string `json:"reason,omitempty"`
	// Previous and PreviousID name the provider and improvement a switch
	// replaced. Empty for improve and retire.
	Previous   string `json:"previous,omitempty"`
	PreviousID string `json:"previous_id,omitempty"`
	// Since is when the improvement started, so a retire record carries
	// the span's start.
	Since time.Time `json:"since"`
}

// FlowRecord is one flow observation for a learned prefix, tagged with the
// provider traffic to that prefix uses. In inject mode a steered prefix
// carries the improvement that moved it; in observe and suggest nothing has
// moved, so the tag is the native provider.
type FlowRecord struct {
	Time     time.Time  `json:"time"`
	Src      netip.Addr `json:"src"`
	Dst      netip.Addr `json:"dst"`
	Proto    uint8      `json:"proto"`
	Bytes    uint64     `json:"bytes"`
	Prefix   string     `json:"prefix"`
	Provider string     `json:"provider,omitempty"`
	// ImprovementID is empty when the prefix is on its native provider.
	ImprovementID string `json:"improvement_id,omitempty"`
}

// MetricSample is one series of GET /metrics at the time of a snapshot.
type MetricSample struct {
	Name string
	// Counter is true for a monotonic counter and false for a gauge.
	Counter bool
	Labels  map[string]string
	Value   float64
}

// MetricsRecord is one snapshot of every series GET /metrics renders, taken
// at Time. The controller takes one every MetricsInterval.
type MetricsRecord struct {
	Time    time.Time
	Samples []MetricSample
}

// MetricsInterval is how often the metrics stream takes a snapshot.
const MetricsInterval = 30 * time.Second

// ExportRecord carries one value of Stream. Exactly one of the pointers is
// set.
type ExportRecord struct {
	Stream   string
	Event    *Event
	Decision *DecisionRecord
	Flow     *FlowRecord
	Metrics  *MetricsRecord
}

// Exporter delivers records to an external system (Kafka, NATS, an OTLP
// collector, an IPFIX collector, InfluxDB). The host batches records per exporter
// on a bounded queue, so a slow sink never delays probing, decisions, or
// withdrawals; Export may block until ctx expires.
type Exporter interface {
	Lifecycle
	// Streams lists the streams this instance takes, from its config.
	Streams() []string
	// Export delivers a batch. Every record's Stream is one of Streams.
	Export(ctx context.Context, batch []ExportRecord) error
}

// ParseStreams checks a configured stream list against the streams a
// plugin type supports and returns def when the list is empty.
func ParseStreams(got, def, supported []string) ([]string, error) {
	if len(got) == 0 {
		return def, nil
	}
	seen := map[string]bool{}
	for _, s := range got {
		ok := false
		for _, sup := range supported {
			ok = ok || s == sup
		}
		if !ok {
			return nil, fmt.Errorf("stream %q is not supported here (want %v)", s, supported)
		}
		if seen[s] {
			return nil, fmt.Errorf("stream %q is listed twice", s)
		}
		seen[s] = true
	}
	return got, nil
}

// FlowObservation is one flow record the flow source matched to a learned
// prefix. It is what the flow tap hands the controller, which tags it and
// turns it into a FlowRecord.
type FlowObservation struct {
	At     time.Time
	Src    netip.Addr
	Dst    netip.Addr
	Proto  uint8
	Bytes  uint64
	Prefix netip.Prefix
}
