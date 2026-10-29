package influxdb

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	return plugin.Exporters.New(TypeName, c, plugin.Env{Name: "i", Getenv: func(k string) string {
		if k == "INFLUX_TOKEN" {
			return "tok"
		}
		return ""
	}})
}

const base = "url: http://influxdb.example.net:8086\norg: ops\nbucket: packeteer\ntoken_env: INFLUX_TOKEN\n"

func TestConfigValidation(t *testing.T) {
	x, err := build(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(x.Streams(), ","); got != "events,decisions" {
		t.Fatalf("default streams = %s, metrics must be opt-in", got)
	}
	if x, err = build(t, base+"streams: [metrics]\n"); err != nil || len(x.Streams()) != 1 {
		t.Fatalf("metrics stream: %v %v", x, err)
	}
	for name, y := range map[string]string{
		"no url":         "org: o\nbucket: b\ntoken_env: INFLUX_TOKEN\n",
		"not http":       "url: udp://h:8089\norg: o\nbucket: b\ntoken_env: INFLUX_TOKEN\n",
		"credentials":    "url: http://u:p@h:8086\norg: o\nbucket: b\ntoken_env: INFLUX_TOKEN\n",
		"no org":         "url: http://h:8086\nbucket: b\ntoken_env: INFLUX_TOKEN\n",
		"no bucket":      "url: http://h:8086\norg: o\ntoken_env: INFLUX_TOKEN\n",
		"no token_env":   "url: http://h:8086\norg: o\nbucket: b\n",
		"token unset":    "url: http://h:8086\norg: o\nbucket: b\ntoken_env: NOPE\n",
		"token is a key": "url: http://h:8086\norg: o\nbucket: b\ntoken_env: \"a b\"\n",
		"ca on http":     base + "ca_file: /x.pem\n",
		"flows":          base + "streams: [flows]\n",
		"unknown field":  base + "interval: 5s\n",
	} {
		if _, err := build(t, y); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

type write struct {
	method, path, org, bucket, precision, auth, body string
}

func server(status int, got *write) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		q := r.URL.Query()
		*got = write{r.Method, r.URL.Path, q.Get("org"), q.Get("bucket"), q.Get("precision"), r.Header.Get("Authorization"), string(b)}
		w.WriteHeader(status)
	}))
}

func TestExportWritesLineProtocol(t *testing.T) {
	var got write
	srv := server(http.StatusNoContent, &got)
	defer srv.Close()
	x, err := build(t, "url: "+srv.URL+"/\norg: ops team\nbucket: packeteer\ntoken_env: INFLUX_TOKEN\nstreams: [events, decisions, metrics]\n")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	err = x.Export(context.Background(), []plugin.ExportRecord{
		{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: t0, Kind: plugin.EventProviderDown, Severity: plugin.SeverityCritical,
			Message: "transit-a is \"down\"\nsince 12:00", Fields: map[string]string{"provider": "transit-a", "path": `a\b`}}},
		{Stream: plugin.StreamDecisions, Decision: &plugin.DecisionRecord{Time: t0, Since: t0.Add(-time.Minute), ID: "00000000000000a1",
			Action: "improve", Mode: "observe", Prefix: "192.0.2.0/24", Provider: "transit-b", Native: "transit-a", Cause: "performance"}},
		{Stream: plugin.StreamMetrics, Metrics: &plugin.MetricsRecord{Time: t0, Samples: []plugin.MetricSample{
			{Name: "packeteer_probe_rtt_seconds", Labels: map[string]string{"provider": "transit a", "prefix": "198.51.100.0/24", "empty": ""}, Value: 0.0125},
			{Name: "packeteer_up", Value: 1},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.method != "POST" || got.path != "/api/v2/write" || got.org != "ops team" || got.bucket != "packeteer" ||
		got.precision != "ns" || got.auth != "Token tok" {
		t.Fatalf("request = %+v", got)
	}
	const ts = "1790856000000000000"
	want := []string{
		`packeteer_event,kind=provider.down,severity=critical message="transit-a is \"down\" since 12:00",field_path="a\\b",field_provider="transit-a" ` + ts,
		`packeteer_decision,action=improve,mode=observe,native=transit-a,prefix=192.0.2.0/24,provider=transit-b improvement_id="00000000000000a1",cause="performance",since_ns=1790855940000000000i ` + ts,
		`packeteer_probe_rtt_seconds,prefix=198.51.100.0/24,provider=transit\ a value=0.0125 ` + ts,
		`packeteer_up value=1 ` + ts,
	}
	if lines := strings.Split(strings.TrimSuffix(got.body, "\n"), "\n"); strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("body:\n%s\nwant:\n%s", got.body, strings.Join(want, "\n"))
	}
}

func TestExportErrors(t *testing.T) {
	var got write
	srv := server(http.StatusUnauthorized, &got)
	x, err := build(t, "url: "+srv.URL+"\norg: o\nbucket: b\ntoken_env: INFLUX_TOKEN\n")
	if err != nil {
		t.Fatal(err)
	}
	rec := []plugin.ExportRecord{{Stream: plugin.StreamEvents, Event: &plugin.Event{Time: time.Now(), Kind: plugin.EventProviderUp}}}
	if err := x.Export(context.Background(), rec); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("a 401 must be an error: %v", err)
	}
	got = write{}
	if err := x.Export(context.Background(), nil); err != nil || got.method != "" {
		t.Fatalf("an empty batch sends nothing: %v %+v", err, got)
	}
	srv.Close()
	if err := x.Export(context.Background(), rec); err == nil {
		t.Fatal("a closed server must be an error")
	}
}
