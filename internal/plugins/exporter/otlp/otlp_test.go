package otlp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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
		"negative timeout": "endpoint: http://c:4318\ntimeout: -1s\n",
		"unknown field":    "endpoint: http://c:4318\nstreams: [events]\n",
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
	x, err := build(t, "endpoint: "+srv.URL+"/otlp/v1/traces\ntimeout: 1s\n")
	if err != nil {
		t.Fatal(err)
	}
	rec := []plugin.ExportRecord{{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{ID: "01", Action: "improve", Time: time.Now()}}}
	if err := x.Export(context.Background(), rec); err == nil {
		t.Fatal("a 503 must be an error")
	}
	if err := x.Export(context.Background(), []plugin.ExportRecord{{Stream: plugin.StreamEvents, Event: &plugin.Event{}}}); err != nil {
		t.Fatalf("a batch with no decisions sends nothing: %v", err)
	}
	srv.Close()
	if err := x.Export(context.Background(), rec); err == nil {
		t.Fatal("a closed collector must be an error")
	}
}
