// Package influxdb implements the "influxdb" exporter: events, decision
// changes, and metric snapshots as line protocol, written to the InfluxDB
// v2 write API (POST /api/v2/write). InfluxDB 1.8 and 3 accept the same call.
package influxdb

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "influxdb"

const writePath = "/api/v2/write"

func init() { plugin.Exporters.Register(TypeName, New) }

// Config is the influxdb exporter's config block.
type Config struct {
	// URL is the server's base URL, for example http://influxdb:8086.
	URL    string `yaml:"url"`
	Org    string `yaml:"org"`
	Bucket string `yaml:"bucket"`
	// TokenEnv names the environment variable holding an API token with
	// write access to the bucket.
	TokenEnv string `yaml:"token_env"`
	CAFile   string `yaml:"ca_file"`
	// Streams defaults to events and decisions. metrics is opt-in: it
	// writes every /metrics series each snapshot.
	Streams []string `yaml:"streams"`
}

// Exporter writes line protocol to an InfluxDB server.
type Exporter struct {
	target  string
	streams []string
	header  http.Header
	client  *http.Client
}

// New is the plugin factory. It opens no connection.
func New(c plugin.Config, e plugin.Env) (plugin.Exporter, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := sinkcfg.HTTPURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("url %w", err)
	}
	if cfg.Org == "" || cfg.Bucket == "" {
		return nil, errors.New("org and bucket are required")
	}
	token, err := sinkcfg.Secret(e.Getenv, "token_env", cfg.TokenEnv)
	if err != nil {
		return nil, err
	}
	tlsConf, err := sinkcfg.TLS(u.Scheme == "https", cfg.CAFile)
	if err != nil {
		return nil, err
	}
	streams, err := plugin.ParseStreams(cfg.Streams, []string{plugin.StreamEvents, plugin.StreamDecisions},
		[]string{plugin.StreamEvents, plugin.StreamDecisions, plugin.StreamMetrics})
	if err != nil {
		return nil, err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + writePath
	u.RawQuery = url.Values{"org": {cfg.Org}, "bucket": {cfg.Bucket}, "precision": {"ns"}}.Encode()
	return &Exporter{target: u.String(), streams: streams,
		header: http.Header{"Authorization": {"Token " + token}, "Content-Type": {"text/plain; charset=utf-8"}},
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

// Export writes the batch as one request.
func (x *Exporter) Export(ctx context.Context, batch []plugin.ExportRecord) error {
	var b strings.Builder
	for _, r := range batch {
		switch {
		case r.Event != nil:
			eventLine(&b, *r.Event)
		case r.Decision != nil:
			decisionLine(&b, *r.Decision)
		case r.Metrics != nil:
			metricLines(&b, *r.Metrics)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return sinkcfg.Post(ctx, x.client, x.target, x.header, []byte(b.String()))
}

// Line protocol: `measurement,tag=v field=v timestamp`. Tags are the
// dimensions to filter on, so they hold only short enumerable values.

func eventLine(b *strings.Builder, e plugin.Event) {
	f := []kv{{"message", quote(e.Message)}}
	for _, k := range slices.Sorted(maps.Keys(e.Fields)) {
		f = append(f, kv{"field_" + k, quote(e.Fields[k])})
	}
	line(b, "packeteer_event", []kv{{"kind", e.Kind}, {"severity", string(e.Severity)}}, f, e.Time)
}

func decisionLine(b *strings.Builder, d plugin.DecisionRecord) {
	f := []kv{{"improvement_id", quote(d.ID)}}
	for _, o := range []kv{{"cause", d.Cause}, {"reason", d.Reason}, {"previous", d.Previous}, {"previous_id", d.PreviousID}} {
		if o.v != "" {
			f = append(f, kv{o.k, quote(o.v)})
		}
	}
	if !d.Since.IsZero() {
		f = append(f, kv{"since_ns", strconv.FormatInt(d.Since.UnixNano(), 10) + "i"})
	}
	line(b, "packeteer_decision", []kv{{"action", d.Action}, {"mode", d.Mode}, {"prefix", d.Prefix},
		{"provider", d.Provider}, {"native", d.Native}}, f, d.Time)
}

// metricLines writes each series as a point named after it, with its labels
// as tags and the reading in the field value.
func metricLines(b *strings.Builder, m plugin.MetricsRecord) {
	for _, s := range m.Samples {
		tags := make([]kv, 0, len(s.Labels))
		for k, v := range s.Labels {
			tags = append(tags, kv{k, v})
		}
		line(b, s.Name, tags, []kv{{"value", strconv.FormatFloat(s.Value, 'g', -1, 64)}}, m.Time)
	}
}

type kv struct{ k, v string }

// line appends one point. A tag with an empty value is left out, as the
// server rejects it. Tags are sorted by key, which InfluxDB recommends.
func line(b *strings.Builder, measurement string, tags, fields []kv, at time.Time) {
	b.WriteString(measurementEscaper.Replace(oneLine(measurement)))
	sort.SliceStable(tags, func(i, j int) bool { return tags[i].k < tags[j].k })
	for _, t := range tags {
		if t.v == "" {
			continue
		}
		b.WriteByte(',')
		b.WriteString(keyEscaper.Replace(oneLine(t.k)))
		b.WriteByte('=')
		b.WriteString(keyEscaper.Replace(oneLine(t.v)))
	}
	for i, f := range fields {
		if i == 0 {
			b.WriteByte(' ')
		} else {
			b.WriteByte(',')
		}
		b.WriteString(keyEscaper.Replace(oneLine(f.k)))
		b.WriteByte('=')
		b.WriteString(f.v)
	}
	b.WriteByte(' ')
	b.WriteString(strconv.FormatInt(at.UnixNano(), 10))
	b.WriteByte('\n')
}

var (
	measurementEscaper = strings.NewReplacer(",", `\,`, " ", `\ `)
	keyEscaper         = strings.NewReplacer(",", `\,`, "=", `\=`, " ", `\ `)
	stringEscaper      = strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	newlines           = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")
)

// oneLine keeps a value on its own line: a newline would end the point.
func oneLine(s string) string { return newlines.Replace(s) }

// quote renders a string field value.
func quote(s string) string { return `"` + stringEscaper.Replace(oneLine(s)) + `"` }
