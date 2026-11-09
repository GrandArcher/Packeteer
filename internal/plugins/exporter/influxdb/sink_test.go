//go:build sink

package influxdb

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestSinkInfluxDB writes to a real InfluxDB 2 (CI starts the image with a
// preset org, bucket, and token, see the exporters job) and reads the points
// back with a Flux query.
func TestSinkInfluxDB(t *testing.T) {
	server, token := os.Getenv("PACKETEER_SINK_INFLUXDB"), os.Getenv("PACKETEER_SINK_INFLUXDB_TOKEN")
	if server == "" || token == "" {
		t.Fatal("PACKETEER_SINK_INFLUXDB and PACKETEER_SINK_INFLUXDB_TOKEN must be set")
	}
	t.Setenv("INFLUX_TOKEN", token)
	c, err := plugin.ConfigFromYAML(fmt.Sprintf("url: %s\norg: packeteer\nbucket: packeteer\ntoken_env: INFLUX_TOKEN\nstreams: [events, decisions, metrics]\n", server))
	if err != nil {
		t.Fatal(err)
	}
	x, err := plugin.Exporters.New(TypeName, c, plugin.Env{Name: "influx", Getenv: os.Getenv})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	at := time.Now()
	rec := []plugin.ExportRecord{
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: at, Kind: "provider.down", Severity: plugin.SeverityCritical,
			Message: "transit-a is down", Fields: map[string]string{"provider": "transit-a"}}},
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{Time: at, Since: at, ID: "00000000000000ef", Action: "improve",
			Mode: "observe", Prefix: "198.51.100.0/24", Provider: "transit-b", Native: "transit-a"}},
		{Stream: plugin.StreamMetrics, Metrics: &plugin.MetricsRecord{Time: at, Samples: []plugin.MetricSample{
			{Name: "packeteer_probe_rtt_seconds", Labels: map[string]string{"provider": "transit-b", "prefix": "198.51.100.0/24"}, Value: 0.0125}}}},
	}
	// The server may still be starting or setting up.
	for {
		if err = x.Export(ctx, rec); err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("export: %v", err)
		}
		time.Sleep(time.Second)
	}
	for _, want := range []struct{ measurement, contains string }{
		{"packeteer_event", "transit-a is down"},
		{"packeteer_decision", "00000000000000ef"},
		{"packeteer_probe_rtt_seconds", "0.0125"},
	} {
		for {
			out := query(t, ctx, server, token, `from(bucket: "packeteer") |> range(start: -1h) |> filter(fn: (r) => r._measurement == "`+want.measurement+`")`)
			if strings.Contains(out, want.contains) {
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("%s never held %q; the query returned:\n%s", want.measurement, want.contains, out)
			}
			time.Sleep(time.Second)
		}
	}
}

func query(t *testing.T, ctx context.Context, server, token, flux string) string {
	t.Helper()
	body := fmt.Sprintf(`{"type":"flux","query":%q}`, flux)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/api/v2/query?"+url.Values{"org": {"packeteer"}}.Encode(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Token "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/csv")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
