//go:build sink

package otlp

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestSinkOTLP posts to a real OpenTelemetry collector (CI starts the
// contrib image with lab/exporters/otelcol.yaml, see the exporters job) and
// reads the span back from the collector's file exporter.
func TestSinkOTLP(t *testing.T) {
	endpoint, file := os.Getenv("PACKETEER_SINK_OTLP"), os.Getenv("PACKETEER_SINK_OTLP_FILE")
	if endpoint == "" || file == "" {
		t.Fatal("PACKETEER_SINK_OTLP and PACKETEER_SINK_OTLP_FILE must be set")
	}
	x, err := build(t, "endpoint: "+endpoint+"\nservice_name: packeteer-sink\n")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	at := time.Now()
	rec := []plugin.ExportRecord{{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{
		Time: at, Since: at, ID: "00000000000000cd", Action: "improve", Mode: "observe", Prefix: "198.51.100.0/24",
		Provider: "transit-b", Native: "transit-a", Cause: "performance"}}}
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
	for {
		b, _ := os.ReadFile(file)
		s := string(b)
		if strings.Contains(s, "packeteer.decision.improve") && strings.Contains(s, "198.51.100.0/24") &&
			strings.Contains(s, "transit-b") && strings.Contains(s, "packeteer-sink") && strings.Contains(s, traceID("00000000000000cd")) {
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("the collector never wrote the span; file has:\n%s", s)
		}
		time.Sleep(time.Second)
	}
}
