// Package otlp implements the "otlp" exporter: each decision change becomes
// one OpenTelemetry span, sent to a collector as OTLP/HTTP JSON
// (POST /v1/traces). Spans of one improvement share a trace.
package otlp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "otlp"

// DefaultServiceName is the service.name resource attribute.
const DefaultServiceName = "packeteer"

const tracesPath = "/v1/traces"

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the otlp exporter's config block.
type Config struct {
	// Endpoint is the collector's OTLP/HTTP base URL, for example
	// http://collector:4318. The path /v1/traces is added.
	Endpoint string `yaml:"endpoint"`
	// Headers are added to each request. Values may reference ${VAR} from
	// the environment so tokens stay out of the config file.
	Headers     map[string]string `yaml:"headers"`
	CAFile      string            `yaml:"ca_file"`
	ServiceName string            `yaml:"service_name"`
}

// Exporter sends spans to an OTLP/HTTP collector.
type Exporter struct {
	url     string
	headers http.Header
	service string
	client  *http.Client
}

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// New is the plugin factory. It opens no connection.
func New(c plugin.Config, e plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("endpoint must be an absolute http(s) URL without credentials or query")
	}
	if !strings.HasSuffix(u.Path, tracesPath) {
		u.Path = strings.TrimSuffix(u.Path, "/") + tracesPath
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
	return &Exporter{url: u.String(), headers: hdr, service: cfg.ServiceName,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}}, nil
}

// Streams implements plugin.Exporter. Traces carry decisions only.
func (x *Exporter) Streams() []string { return []string{plugin.StreamDecisions} }

// Start implements plugin.Lifecycle.
func (x *Exporter) Start(context.Context) error { return nil }

// Stop implements plugin.Lifecycle.
func (x *Exporter) Stop(context.Context) error {
	x.client.CloseIdleConnections()
	return nil
}

// Export posts one trace request holding a span per decision.
func (x *Exporter) Export(ctx context.Context, batch []plugin.ExportRecord) error {
	var spans []span
	for _, r := range batch {
		if r.Decision != nil {
			spans = append(spans, spanOf(*r.Decision))
		}
	}
	if len(spans) == 0 {
		return nil
	}
	body, err := json.Marshal(request{ResourceSpans: []resourceSpans{{
		Resource:   resource{Attributes: []attr{str("service.name", x.service)}},
		ScopeSpans: []scopeSpans{{Scope: scope{Name: "packeteer"}, Spans: spans}},
	}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header = x.headers.Clone()
	resp, err := x.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("collector answered %s", resp.Status)
	}
	return nil
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
	attr struct {
		Key   string `json:"key"`
		Value value  `json:"value"`
	}
	value struct {
		String string `json:"stringValue"`
	}
)

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
