package httpapi

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func findSample(t *testing.T, got []plugin.MetricSample, name string, labels map[string]string) plugin.MetricSample {
	t.Helper()
	for _, s := range got {
		if s.Name != name || len(s.Labels) != len(labels) {
			continue
		}
		match := true
		for k, v := range labels {
			match = match && s.Labels[k] == v
		}
		if match {
			return s
		}
	}
	t.Fatalf("no sample %s%v in %d samples", name, labels, len(got))
	return plugin.MetricSample{}
}

func TestParseMetricsReadsWhatMetricsRenders(t *testing.T) {
	got := parseMetrics(dashboardSnapshot())
	if s := findSample(t, got, "packeteer_up", nil); s.Value != 1 || s.Counter {
		t.Fatalf("packeteer_up = %+v", s)
	}
	if s := findSample(t, got, "packeteer_probe_loss_ratio", map[string]string{"provider": "transit-a", "prefix": "192.0.2.0/24"}); s.Value != 0.01 {
		t.Fatalf("loss = %+v", s)
	}
	s := findSample(t, got, "packeteer_export_records_total", map[string]string{"exporter": "pipeline", "stream": "decisions", "result": "dropped"})
	if s.Value != 2 || !s.Counter {
		t.Fatalf("a counter must keep its type and value: %+v", s)
	}
	// Every non-comment line of the rendered text becomes one sample.
	lines := 0
	for _, l := range strings.Split(string(dashboardSnapshot()), "\n") {
		if l != "" && l[0] != '#' {
			lines++
		}
	}
	if lines != len(got) {
		t.Fatalf("%d series rendered, %d parsed", lines, len(got))
	}
}

func TestParseMetricsLabelEscapesAndBadLines(t *testing.T) {
	var b strings.Builder
	writeGauge(&b, "packeteer_x", "h", sample{labels: []lbl{{"a", `q"u\o` + "\nte}, {x=\"y\"}"}, {"b", "plain"}}, value: 2.5})
	b.WriteString("packeteer_nan NaN\npacketeer_inf +Inf\nbroken{a=\"x\n\npacketeer_ok 3\n")
	got := parseMetrics([]byte(b.String()))
	if len(got) != 2 {
		t.Fatalf("got %+v, want the escaped sample and packeteer_ok only", got)
	}
	if v := got[0].Labels["a"]; v != `q"u\o`+"\nte}, {x=\"y\"}" || got[0].Labels["b"] != "plain" || got[0].Value != 2.5 {
		t.Fatalf("labels did not round trip: %+v", got[0])
	}
	if got[1].Name != "packeteer_ok" || got[1].Value != 3 {
		t.Fatalf("got %+v", got[1])
	}
}
