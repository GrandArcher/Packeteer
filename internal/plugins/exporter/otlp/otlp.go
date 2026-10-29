// Package otlp implements the "otlp" exporter, sending OTLP/HTTP JSON to a
// collector: each decision change is a span (POST /v1/traces, the spans of
// one improvement share a trace), each event a log record (/v1/logs), and
// each metrics snapshot a set of gauges and sums (/v1/metrics).
package otlp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "otlp"

// DefaultServiceName is the service.name resource attribute.
const DefaultServiceName = "packeteer"

// OTLP/HTTP paths, one per signal.
const (
	tracesPath  = "/v1/traces"
	logsPath    = "/v1/logs"
	metricsPath = "/v1/metrics"
)

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the otlp exporter's config block.
type Config struct {
	// Endpoint is the collector's OTLP/HTTP base URL, for example
	// http://collector:4318. The signal paths /v1/traces, /v1/logs, and
	// /v1/metrics are added.
	Endpoint string `yaml:"endpoint"`
	// Streams defaults to decisions, so existing configs keep sending
	// spans only. events become log records and metrics become metrics.
	Streams []string `yaml:"streams"`
	// Headers are added to each request. Values may reference ${VAR} from
	// the environment so tokens stay out of the config file.
	Headers     map[string]string `yaml:"headers"`
	CAFile      string            `yaml:"ca_file"`
	ServiceName string            `yaml:"service_name"`
}

// Exporter sends spans, log records, and metrics to an OTLP/HTTP collector.
type Exporter struct {
	base    url.URL
	streams []string
	headers http.Header
	service string
	client  *http.Client
	// started is the start time of the cumulative sums: every counter
	// Packeteer renders counts since the process started.
	started time.Time
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// New is the plugin factory. It opens no connection.
func New(c plugin.Config, e plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := sinkcfg.HTTPURL(cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("endpoint %w", err)
	}
	// An endpoint that already names the traces path is a base all the same.
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), tracesPath)
	streams, err := plugin.ParseStreams(cfg.Streams, []string{plugin.StreamDecisions},
		[]string{plugin.StreamDecisions, plugin.StreamEvents, plugin.StreamMetrics})
	if err != nil {
		return nil, err
	}
	tlsConf, err := sinkcfg.TLS(u.Scheme == "https", cfg.CAFile)
	if err != nil {
		return nil, err
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = DefaultServiceName
	}
	getenv := e.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	hdr := http.Header{"Content-Type": {"application/json"}}
	for k, v := range cfg.Headers {
		if !headerName.MatchString(k) {
			return nil, fmt.Errorf("header name %q is invalid", k)
		}
		var missing string
		val := os.Expand(v, func(n string) string {
			s := getenv(n)
			if s == "" && missing == "" {
				missing = n
			}
			return s
		})
		if missing != "" {
			return nil, fmt.Errorf("header %s: %s is not set", k, missing)
		}
		hdr.Set(k, val)
	}
	return &Exporter{base: *u, streams: streams, headers: hdr, service: cfg.ServiceName, started: time.Now(),
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}}, nil
}

// Streams implements plugin.Exporter.
func (x *Exporter) Streams() []string { return x.streams }

// Start implements plugin.Lifecycle.
func (x *Exporter) Start(context.Context) error { return nil }

// Stop implements plugin.Lifecycle.
func (x *Exporter) Stop(context.Context) error {
	x.client.CloseIdleConnections()
	return nil
}

// Export posts one request per signal the batch holds: spans for
// decisions, log records for events, metrics for snapshots.
func (x *Exporter) Export(ctx context.Context, batch []plugin.ExportRecord) error {
	var spans []span
	var logs []logRecord
	var metrics []metric
	for _, r := range batch {
		switch {
		case r.Decision != nil:
			spans = append(spans, spanOf(*r.Decision))
		case r.Event != nil:
			logs = append(logs, logOf(*r.Event))
		case r.Metrics != nil:
			metrics = append(metrics, metricsOf(*r.Metrics, x.started)...)
		}
	}
	res := resource{Attributes: []attr{str("service.name", x.service)}}
	sc := scope{Name: "packeteer"}
	var errs []error
	if len(spans) > 0 {
		errs = append(errs, x.post(ctx, tracesPath, request{ResourceSpans: []resourceSpans{{
			Resource: res, ScopeSpans: []scopeSpans{{Scope: sc, Spans: spans}}}}}))
	}
	if len(logs) > 0 {
		errs = append(errs, x.post(ctx, logsPath, logsRequest{ResourceLogs: []resourceLogs{{
			Resource: res, ScopeLogs: []scopeLogs{{Scope: sc, LogRecords: logs}}}}}))
	}
	if len(metrics) > 0 {
		errs = append(errs, x.post(ctx, metricsPath, metricsRequest{ResourceMetrics: []resourceMetrics{{
			Resource: res, ScopeMetrics: []scopeMetrics{{Scope: sc, Metrics: metrics}}}}}))
	}
	return errors.Join(errs...)
}

func (x *Exporter) post(ctx context.Context, path string, req any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	u := x.base
	u.Path += path
	return sinkcfg.Post(ctx, x.client, u.String(), x.headers, body)
}

// OTLP/JSON types. IDs are lowercase hex and times are decimal strings of
// nanoseconds, as the OTLP JSON encoding requires.
type (
	request struct {
		ResourceSpans []resourceSpans `json:"resourceSpans"`
	}
	resourceSpans struct {
		Resource   resource     `json:"resource"`
		ScopeSpans []scopeSpans `json:"scopeSpans"`
	}
	resource struct {
		Attributes []attr `json:"attributes"`
	}
	scopeSpans struct {
		Scope scope  `json:"scope"`
		Spans []span `json:"spans"`
	}
	scope struct {
		Name string `json:"name"`
	}
	span struct {
		TraceID      string `json:"traceId"`
		SpanID       string `json:"spanId"`
		ParentSpanID string `json:"parentSpanId,omitempty"`
		Name         string `json:"name"`
		Kind         int    `json:"kind"`
		Start        string `json:"startTimeUnixNano"`
		End          string `json:"endTimeUnixNano"`
		Attributes   []attr `json:"attributes"`
		Links        []link `json:"links,omitempty"`
	}
	link struct {
		TraceID string `json:"traceId"`
		SpanID  string `json:"spanId"`
	}
	logsRequest struct {
		ResourceLogs []resourceLogs `json:"resourceLogs"`
	}
	resourceLogs struct {
		Resource  resource    `json:"resource"`
		ScopeLogs []scopeLogs `json:"scopeLogs"`
	}
	scopeLogs struct {
		Scope      scope       `json:"scope"`
		LogRecords []logRecord `json:"logRecords"`
	}
	logRecord struct {
		Time         string `json:"timeUnixNano"`
		SeverityNum  int    `json:"severityNumber"`
		SeverityText string `json:"severityText"`
		Body         value  `json:"body"`
		Attributes   []attr `json:"attributes"`
	}
	metricsRequest struct {
		ResourceMetrics []resourceMetrics `json:"resourceMetrics"`
	}
	resourceMetrics struct {
		Resource     resource       `json:"resource"`
		ScopeMetrics []scopeMetrics `json:"scopeMetrics"`
	}
	scopeMetrics struct {
		Scope   scope    `json:"scope"`
		Metrics []metric `json:"metrics"`
	}
	// metric holds exactly one of Gauge and Sum.
	metric struct {
		Name  string `json:"name"`
		Gauge *gauge `json:"gauge,omitempty"`
		Sum   *sum   `json:"sum,omitempty"`
	}
	gauge struct {
		DataPoints []dataPoint `json:"dataPoints"`
	}
	sum struct {
		DataPoints             []dataPoint `json:"dataPoints"`
		AggregationTemporality int         `json:"aggregationTemporality"`
		IsMonotonic            bool        `json:"isMonotonic"`
	}
	dataPoint struct {
		Attributes []attr  `json:"attributes,omitempty"`
		Start      string  `json:"startTimeUnixNano,omitempty"`
		Time       string  `json:"timeUnixNano"`
		AsDouble   float64 `json:"asDouble"`
	}
	attr struct {
		Key   string `json:"key"`
		Value value  `json:"value"`
	}
	value struct {
		String string `json:"stringValue"`
	}
)

// aggregationCumulative is OTLP's AGGREGATION_TEMPORALITY_CUMULATIVE.
const aggregationCumulative = 2

// OTLP severity numbers: INFO, WARN, and ERROR.
const (
	sevInfo    = 9
	sevWarning = 13
	sevError   = 17
)

func logOf(e plugin.Event) logRecord {
	n := sevInfo
	switch e.Severity {
	case plugin.SeverityWarning:
		n = sevWarning
	case plugin.SeverityCritical:
		n = sevError
	}
	l := logRecord{Time: strconv.FormatInt(e.Time.UnixNano(), 10), SeverityNum: n, SeverityText: string(e.Severity),
		Body: value{String: e.Message}, Attributes: []attr{str("event.name", e.Kind)}}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		l.Attributes = append(l.Attributes, str("packeteer.field."+k, e.Fields[k]))
	}
	return l
}

// metricsOf groups a snapshot's series by name: a counter is a cumulative
// monotonic sum from start, anything else a gauge.
func metricsOf(r plugin.MetricsRecord, start time.Time) []metric {
	at := strconv.FormatInt(r.Time.UnixNano(), 10)
	from := strconv.FormatInt(start.UnixNano(), 10)
	var out []metric
	byName := map[string]int{}
	for _, s := range r.Samples {
		i, ok := byName[s.Name]
		if !ok {
			i = len(out)
			byName[s.Name] = i
			m := metric{Name: s.Name}
			if s.Counter {
				m.Sum = &sum{AggregationTemporality: aggregationCumulative, IsMonotonic: true}
			} else {
				m.Gauge = &gauge{}
			}
			out = append(out, m)
		}
		dp := dataPoint{Time: at, AsDouble: s.Value}
		keys := make([]string, 0, len(s.Labels))
		for k := range s.Labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			dp.Attributes = append(dp.Attributes, str(k, s.Labels[k]))
		}
		if m := &out[i]; m.Sum != nil {
			dp.Start = from
			m.Sum.DataPoints = append(m.Sum.DataPoints, dp)
		} else {
			m.Gauge.DataPoints = append(m.Gauge.DataPoints, dp)
		}
	}
	return out
}

func str(k, v string) attr { return attr{Key: k, Value: value{String: v}} }

const spanKindInternal = 1

func hexID(n int, parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:n])
}

// traceID and startSpanID are derived from the improvement ID, so every
// span of an improvement lands in one trace and a retire span can name the
// span that started it.
func traceID(id string) string     { return hexID(16, "trace", id) }
func startSpanID(id string) string { return hexID(8, "span", id) }

func spanOf(d plugin.DecisionRecord) span {
	at := d.Time.UnixNano()
	s := span{
		TraceID: traceID(d.ID), SpanID: startSpanID(d.ID),
		Name: "packeteer.decision." + d.Action, Kind: spanKindInternal,
		Start: strconv.FormatInt(at, 10), End: strconv.FormatInt(at, 10),
		Attributes: []attr{
			str("packeteer.improvement.id", d.ID), str("packeteer.action", d.Action), str("packeteer.mode", d.Mode),
			str("packeteer.prefix", d.Prefix), str("packeteer.provider", d.Provider), str("packeteer.native", d.Native),
		},
	}
	for _, o := range []attr{str("packeteer.cause", d.Cause), str("packeteer.reason", d.Reason), str("packeteer.previous_provider", d.Previous)} {
		if o.Value.String != "" {
			s.Attributes = append(s.Attributes, o)
		}
	}
	switch {
	case d.Action == "retire":
		// The retire span covers the improvement's whole life.
		s.SpanID, s.ParentSpanID = hexID(8, "span-end", d.ID), startSpanID(d.ID)
		if !d.Since.IsZero() {
			s.Start = strconv.FormatInt(d.Since.UnixNano(), 10)
		}
	case d.PreviousID != "":
		s.Links = []link{{TraceID: traceID(d.PreviousID), SpanID: startSpanID(d.PreviousID)}}
	}
	return s
}
