//go:build sink

package otlp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestSinkOTLP posts to a real OpenTelemetry collector (CI starts the
// contrib image with lab/exporters/otelcol.yaml, see the exporters job) and
// reads the span, the log record, and the metric back from the collector's
// file exporters. PACKETEER_SINK_OTLP_FILE is the traces file; the logs and
// metrics files sit next to it.
func TestSinkOTLP(t *testing.T) {
	endpoint, file := os.Getenv("PACKETEER_SINK_OTLP"), os.Getenv("PACKETEER_SINK_OTLP_FILE")
	if endpoint == "" || file == "" {
		t.Fatal("PACKETEER_SINK_OTLP and PACKETEER_SINK_OTLP_FILE must be set")
	}
	x, err := build(t, "endpoint: "+endpoint+"\nservice_name: packeteer-sink\nstreams: [decisions, events, metrics]\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	at := time.Now()
	rec := []plugin.ExportRecord{{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{
		Time: at, Since: at, ID: "00000000000000cd", Action: "improve", Mode: "observe", Prefix: "198.51.100.0/24",
		Provider: "transit-b", Native: "transit-a", Cause: "performance"}},
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: at, Kind: "provider.down", Severity: plugin.SeverityCritical, Message: "transit-a is down"}},
		{Stream: plugin.StreamMetrics, Metrics: &plugin.MetricsRecord{Time: at, Samples: []plugin.MetricSample{
			{Name: "packeteer_probe_rtt_seconds", Labels: map[string]string{"provider": "transit-b"}, Value: 0.0125},
			{Name: "packeteer_export_records_total", Counter: true, Labels: map[string]string{"result": "sent"}, Value: 7}}}}}
	// The collector may still be starting.
	for {
		if err = x.Export(ctx, rec); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("export: %v", err)
		}
		time.Sleep(time.Second)
	}
	dir := filepath.Dir(file)
	for _, want := range []struct {
		file string
		all  []string
	}{
		{file, []string{"packeteer.decision.improve", "198.51.100.0/24", "transit-b", "packeteer-sink", traceID("00000000000000cd")}},
		{filepath.Join(dir, "logs.json"), []string{"provider.down", "transit-a is down", "packeteer-sink"}},
		{filepath.Join(dir, "metrics.json"), []string{"packeteer_probe_rtt_seconds", "packeteer_export_records_total", "isMonotonic", "transit-b", "packeteer-sink"}},
	} {
		for {
			b, _ := os.ReadFile(want.file)
			s := string(b)
			if hasAll(s, want.all) {
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("%s never held %v; it has:\n%s", want.file, want.all, s)
			}
			time.Sleep(time.Second)
		}
	}
}

func hasAll(s string, parts []string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}
