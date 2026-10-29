package otlp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string) (plugin.Exporter, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Exporters.New(TypeName, c, plugin.Env{Name: "o", Getenv: func(k string) string {
		if k == "OTEL_TOKEN" {
			return "tok"
		}
		return ""
	}})
}

func TestConfigValidation(t *testing.T) {
	x, err := build(t, "endpoint: http://collector.example.net:4318\n")
	if err != nil {
		t.Fatal(err)
	}
	if s := x.Streams(); len(s) != 1 || s[0] != plugin.StreamDecisions {
		t.Fatalf("streams = %v, traces carry decisions only", s)
	}
	for name, y := range map[string]string{
		"no endpoint":      "service_name: x\n",
		"not http":         "endpoint: grpc://c:4317\n",
		"credentials":      "endpoint: http://u:p@c:4318\n",
		"query":            "endpoint: http://c:4318/?a=b\n",
		"ca on http":       "endpoint: http://c:4318\nca_file: /x.pem\n",
		"bad header":       "endpoint: http://c:4318\nheaders: {\"a b\": x}\n",
		"unset header env": "endpoint: http://c:4318\nheaders: {authorization: \"Bearer ${NOPE}\"}\n",
		"timeout is fixed": "endpoint: http://c:4318\ntimeout: 5s\n",
		"unknown field":    "endpoint: http://c:4318\ninterval: 5s\n",
		"flows":            "endpoint: http://c:4318\nstreams: [flows]\n",
		"duplicate stream": "endpoint: http://c:4318\nstreams: [events, events]\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

type sentSpan struct {
	TraceID      string `json:"traceId"`
	SpanID       string `json:"spanId"`
	ParentSpanID string `json:"parentSpanId"`
	Name         string `json:"name"`
	Kind         int    `json:"kind"`
	Start        string `json:"startTimeUnixNano"`
	End          string `json:"endTimeUnixNano"`
	Attributes   []struct {
		Key   string `json:"key"`
		Value struct {
			S string `json:"stringValue"`
		} `json:"value"`
	} `json:"attributes"`
	Links []struct{ TraceID, SpanID string } `json:"links"`
}

type sentRequest struct {
	ResourceSpans []struct {
		Resource struct {
			Attributes []struct {
				Key   string `json:"key"`
				Value struct {
					S string `json:"stringValue"`
				} `json:"value"`
			} `json:"attributes"`
		} `json:"resource"`
		ScopeSpans []struct {
			Spans []sentSpan `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

func attrs(s sentSpan) map[string]string {
	m := map[string]string{}
	for _, a := range s.Attributes {
		m[a.Key] = a.Value.S
	}
	return m
}

func TestExportSpansPerDecision(t *testing.T) {
	var path, auth, ctype string
	var req sentRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth, ctype = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &req)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	x, err := build(t, "endpoint: "+srv.URL+"\nservice_name: edge1\nheaders: {Authorization: \"Bearer ${OTEL_TOKEN}\"}\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer x.Stop(context.Background())

	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(5 * time.Minute)
	add := plugin.DecisionRecord{Time: t0, ID: "00000000000000a1", Action: "improve", Mode: "observe", Prefix: "192.0.2.0/24",
		Provider: "transit-b", Native: "transit-a", Cause: "performance", Reason: "loss 4% lower", Since: t0}
	sw := plugin.DecisionRecord{Time: t0.Add(time.Minute), ID: "00000000000000a2", Action: "switch", Mode: "observe", Prefix: "192.0.2.0/24",
		Provider: "transit-c", Native: "transit-a", Previous: "transit-b", PreviousID: "00000000000000a1", Since: t0.Add(time.Minute)}
	ret := add
	ret.Time, ret.Action = t1, "retire"
	err = x.Export(context.Background(), []plugin.ExportRecord{
		{Stream: plugin.StreamDecisions, Decision: &add},
		{Stream: plugin.StreamDecisions, Decision: &sw},
		{Stream: plugin.StreamDecisions, Decision: &ret},
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != "/v1/traces" || auth != "Bearer tok" || ctype != "application/json" {
		t.Fatalf("path %q auth %q content-type %q", path, auth, ctype)
	}
	rs := req.ResourceSpans[0]
	if got := rs.Resource.Attributes[0]; got.Key != "service.name" || got.Value.S != "edge1" {
		t.Fatalf("resource = %+v", rs.Resource.Attributes)
	}
	spans := rs.ScopeSpans[0].Spans
	if len(spans) != 3 {
		t.Fatalf("spans = %d", len(spans))
	}
	a, s, r := spans[0], spans[1], spans[2]
	if len(a.TraceID) != 32 || len(a.SpanID) != 16 || a.Name != "packeteer.decision.improve" || a.Kind != 1 {
		t.Fatalf("improve span = %+v", a)
	}
	at := attrs(a)
	for k, v := range map[string]string{"packeteer.prefix": "192.0.2.0/24", "packeteer.provider": "transit-b", "packeteer.native": "transit-a",
		"packeteer.improvement.id": "00000000000000a1", "packeteer.cause": "performance", "packeteer.mode": "observe"} {
		if at[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, at[k], v)
		}
	}
	if r.TraceID != a.TraceID || r.ParentSpanID != a.SpanID || r.SpanID == a.SpanID {
		t.Fatalf("retire must share the improve trace and name it as parent: improve %+v retire %+v", a, r)
	}
	if r.Start != strconv.FormatInt(t0.UnixNano(), 10) || r.End != strconv.FormatInt(t1.UnixNano(), 10) {
		t.Fatalf("retire span covers %s..%s", r.Start, r.End)
	}
	if s.TraceID == a.TraceID || len(s.Links) != 1 || s.Links[0].TraceID != a.TraceID || s.Links[0].SpanID != a.SpanID {
		t.Fatalf("switch must start a new trace linked to the previous improvement: %+v", s)
	}
	if attrs(s)["packeteer.previous_provider"] != "transit-b" {
		t.Fatalf("switch attrs = %v", attrs(s))
	}
}

func TestExportErrors(t *testing.T) {
	status := http.StatusServiceUnavailable
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
	x, err := build(t, "endpoint: "+srv.URL+"/otlp/v1/traces\n")
	if err != nil {
		t.Fatal(err)
	}
	rec := []plugin.ExportRecord{{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{ID: "01", Action: "improve", Time: time.Now()}}}
	if err := x.Export(context.Background(), rec); err == nil {
		t.Fatal("a 503 must be an error")
	}
	if err := x.Export(context.Background(), nil); err != nil {
		t.Fatalf("an empty batch sends nothing: %v", err)
	}
	srv.Close()
	if err := x.Export(context.Background(), rec); err == nil {
		t.Fatal("a closed collector must be an error")
	}
}

// collector records every request by path, with the decoded JSON body.
type collector struct {
	mu   sync.Mutex
	reqs map[string][]map[string]any
	fail map[string]bool
}

func newCollector() (*collector, *httptest.Server) {
	c := &collector{reqs: map[string][]map[string]any{}, fail: map[string]bool{}}
	return c, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.reqs[r.URL.Path] = append(c.reqs[r.URL.Path], m)
		if c.fail[r.URL.Path] {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
}

// at walks a decoded JSON value by keys and indexes.
func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, p := range path {
		switch k := p.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("%v: not an object at %q", v, k)
			}
			v = m[k]
		case int:
			a, ok := v.([]any)
			if !ok || k >= len(a) {
				t.Fatalf("%v: no index %d", v, k)
			}
			v = a[k]
		}
	}
	return v
}

func attrMap(t *testing.T, v any) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, a := range v.([]any) {
		m[at(t, a, "key").(string)] = at(t, a, "value", "stringValue").(string)
	}
	return m
}

func TestExportEventsAsLogRecords(t *testing.T) {
	c, srv := newCollector()
	defer srv.Close()
	x, err := build(t, "endpoint: "+srv.URL+"/otlp/\nstreams: [decisions, events]\n")
	if err != nil {
		t.Fatal(err)
	}
	if s := strings.Join(x.Streams(), ","); s != "decisions,events" {
		t.Fatalf("streams = %s", s)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	err = x.Export(context.Background(), []plugin.ExportRecord{
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: t0, Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical,
			Message: "transit-a is down", Fields: map[string]string{"provider": "transit-a", "prefix": "192.0.2.0/24"}}},
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: t0, Kind: plugin.EventProviderUp, Severity: plugin.SeverityInfo, Message: "up"}},
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: t0, Kind: plugin.EventProviderDegraded, Severity: plugin.SeverityWarning, Message: "slow"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 1 || len(c.reqs["/otlp/v1/logs"]) != 1 {
		t.Fatalf("requests by path = %v", c.reqs)
	}
	body := c.reqs["/otlp/v1/logs"][0]
	if got := attrMap(t, at(t, body, "resourceLogs", 0, "resource", "attributes")); got["service.name"] != "packeteer" {
		t.Fatalf("resource = %v", got)
	}
	recs := at(t, body, "resourceLogs", 0, "scopeLogs", 0, "logRecords").([]any)
	if len(recs) != 3 {
		t.Fatalf("records = %d", len(recs))
	}
	r := recs[0]
	if at(t, r, "timeUnixNano") != strconv.FormatInt(t0.UnixNano(), 10) || at(t, r, "severityNumber").(float64) != 17 ||
		at(t, r, "severityText") != "critical" || at(t, r, "body", "stringValue") != "transit-a is down" {
		t.Fatalf("critical record = %v", r)
	}
	a := attrMap(t, at(t, r, "attributes"))
	if a["event.name"] != "provider.down" || a["packeteer.field.provider"] != "transit-a" || a["packeteer.field.prefix"] != "192.0.2.0/24" {
		t.Fatalf("attributes = %v", a)
	}
	if at(t, recs[1], "severityNumber").(float64) != 9 || at(t, recs[2], "severityNumber").(float64) != 13 {
		t.Fatalf("info and warning severities = %v %v", recs[1], recs[2])
	}
}

func TestExportMetricsAsGaugesAndSums(t *testing.T) {
	c, srv := newCollector()
	defer srv.Close()
	x, err := build(t, "endpoint: "+srv.URL+"\nstreams: [metrics]\n")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	err = x.Export(context.Background(), []plugin.ExportRecord{{Stream: plugin.StreamMetrics, Metrics: &plugin.MetricsRecord{Time: t0, Samples: []plugin.MetricSample{
		{Name: "packeteer_probe_rtt_seconds", Labels: map[string]string{"provider": "transit-a", "prefix": "192.0.2.0/24"}, Value: 0.012},
		{Name: "packeteer_probe_rtt_seconds", Labels: map[string]string{"provider": "transit-b", "prefix": "192.0.2.0/24"}, Value: 0.02},
		{Name: "packeteer_export_records_total", Counter: true, Labels: map[string]string{"exporter": "influx", "result": "sent"}, Value: 7},
		{Name: "packeteer_up", Value: 1},
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 1 || len(c.reqs["/v1/metrics"]) != 1 {
		t.Fatalf("requests by path = %v", c.reqs)
	}
	ms := at(t, c.reqs["/v1/metrics"][0], "resourceMetrics", 0, "scopeMetrics", 0, "metrics").([]any)
	if len(ms) != 3 {
		t.Fatalf("metrics = %d, want the two rtt series grouped under one name", len(ms))
	}
	rtt := ms[0]
	pts := at(t, rtt, "gauge", "dataPoints").([]any)
	if at(t, rtt, "name") != "packeteer_probe_rtt_seconds" || len(pts) != 2 || at(t, pts[1], "asDouble").(float64) != 0.02 ||
		attrMap(t, at(t, pts[1], "attributes"))["provider"] != "transit-b" || at(t, pts[0], "timeUnixNano") != strconv.FormatInt(t0.UnixNano(), 10) {
		t.Fatalf("gauge = %v", rtt)
	}
	cnt := ms[1]
	if at(t, cnt, "sum", "aggregationTemporality").(float64) != 2 || at(t, cnt, "sum", "isMonotonic") != true ||
		at(t, cnt, "sum", "dataPoints", 0, "asDouble").(float64) != 7 || at(t, cnt, "sum", "dataPoints", 0, "startTimeUnixNano") == "" {
		t.Fatalf("counter = %v", cnt)
	}
	if at(t, ms[2], "gauge", "dataPoints", 0, "attributes") != nil {
		t.Fatalf("an unlabelled series carries no attributes: %v", ms[2])
	}
}

func TestExportOneRequestPerSignalAndJoinedErrors(t *testing.T) {
	c, srv := newCollector()
	defer srv.Close()
	x, err := build(t, "endpoint: "+srv.URL+"/v1/traces\nstreams: [decisions, events, metrics]\n")
	if err != nil {
		t.Fatal(err)
	}
	batch := []plugin.ExportRecord{
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{ID: "01", Action: "improve", Time: time.Now()}},
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: time.Now(), Kind: plugin.EventProviderUp}},
		{Stream: plugin.StreamMetrics, Metrics: &plugin.MetricsRecord{Time: time.Now(), Samples: []plugin.MetricSample{{Name: "packeteer_up", Value: 1}}}},
	}
	if err := x.Export(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/v1/traces", "/v1/logs", "/v1/metrics"} {
		if len(c.reqs[p]) != 1 {
			t.Errorf("%s got %d requests, want 1 (an endpoint naming /v1/traces is still a base)", p, len(c.reqs[p]))
		}
	}
	c.fail["/v1/logs"] = true
	if err := x.Export(context.Background(), batch); err == nil {
		t.Fatal("a failing signal must fail the batch")
	}
	if len(c.reqs["/v1/metrics"]) != 2 {
		t.Fatal("one failing signal must not stop the others from being sent")
	}
}
