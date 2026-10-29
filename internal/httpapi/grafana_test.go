package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/export"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// dashboardSnapshot fills every series the shipped dashboards read, so the
// dashboards are checked against what /metrics renders and not against a
// list kept by hand.
func dashboardSnapshot() []byte {
	polled := time.Now()
	usage := 40.0
	snap := Snapshot{
		Version: "test", Mode: "observe", Started: true, At: polled, BGPConfigured: true, RIBReady: true, RIBPrefixes: 3,
		Providers:    []Provider{{Name: "transit-a", Up: true}},
		Probes:       []Probe{{Provider: "transit-a", Prefix: "192.0.2.0/24", OK: true, RTTAvgMs: 12, LossPct: 1, JitterMs: 2}},
		Decisions:    []Decision{{Prefix: "192.0.2.0/24", Action: "improve", Native: "transit-a", Recommended: "transit-b"}},
		Improvements: []Improvement{{Prefix: "192.0.2.0/24", Provider: "transit-b", Native: "transit-a", Cause: "performance", EstSavings: 5}},
		Quarantined:  []Quarantine{{Prefix: "198.51.100.0/24", Strikes: 1}},
		Peers:        []Peer{{Address: "198.51.100.1", State: "ESTABLISHED", Established: true}},
		Telemetry: []Telemetry{{Provider: "transit-a", Interface: "ether1", Percentile: "greater", CommitMbps: 100,
			InMbps: 10, OutMbps: 20, InMbps95: 15, OutMbps95: 25, UsageMbps: &usage, Samples: 3, Polled: &polled}},
	}
	out := Metrics(snap)
	out = append(out, ExportMetrics([]export.Stat{{Exporter: "pipeline", Stream: plugin.StreamDecisions, Sent: 3, Failed: 1, Dropped: 2}})...)
	return out
}

var (
	metricName = regexp.MustCompile(`packeteer_[a-z0-9_]+`)
	byClause   = regexp.MustCompile(`by \(([^)]*)\)`)
	selector   = regexp.MustCompile(`[{,]\s*([a-z_]+)\s*(?:=~|!~|!=|=)`)
	legendVar  = regexp.MustCompile(`\{\{\s*([a-z_]+)\s*\}\}`)
)

// series maps each rendered metric to the label names it carries.
func series(t *testing.T, text []byte) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, line := range strings.Split(string(text), "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		var name string
		labels := map[string]bool{}
		if i := strings.IndexByte(line, '{'); i >= 0 {
			name = line[:i]
			body := line[i+1 : strings.IndexByte(line, '}')]
			for _, kv := range strings.Split(body, `",`) {
				if k, _, ok := strings.Cut(kv, "="); ok {
					labels[strings.TrimSpace(k)] = true
				}
			}
		} else {
			name, _, _ = strings.Cut(line, " ")
		}
		if out[name] == nil {
			out[name] = map[string]bool{}
		}
		for l := range labels {
			out[name][l] = true
		}
	}
	return out
}

type dashboard struct {
	UID    string `json:"uid"`
	Title  string `json:"title"`
	Inputs []struct {
		Name     string `json:"name"`
		PluginID string `json:"pluginId"`
	} `json:"__inputs"`
	Panels []struct {
		ID         int    `json:"id"`
		Type       string `json:"type"`
		Title      string `json:"title"`
		Datasource struct {
			UID string `json:"uid"`
		} `json:"datasource"`
		Targets []struct {
			Expr   string `json:"expr"`
			Legend string `json:"legendFormat"`
		} `json:"targets"`
	} `json:"panels"`
}

// TestGrafanaDashboardsMatchMetrics imports every shipped dashboard against
// what /metrics renders: the JSON parses, each panel reads the declared
// Prometheus input, and every metric and label a query or legend names
// exists on the series it reads.
func TestGrafanaDashboardsMatchMetrics(t *testing.T) {
	rendered := series(t, dashboardSnapshot())
	files, err := filepath.Glob("../../deploy/grafana/*.json")
	if err != nil || len(files) < 3 {
		t.Fatalf("dashboards: %v, %v", files, err)
	}
	uids := map[string]string{}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var d dashboard
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if d.UID == "" || d.Title == "" || uids[d.UID] != "" {
			t.Fatalf("%s: uid %q title %q (duplicate of %q)", f, d.UID, d.Title, uids[d.UID])
		}
		uids[d.UID] = f
		if len(d.Inputs) != 1 || d.Inputs[0].Name != "DS_PROMETHEUS" || d.Inputs[0].PluginID != "prometheus" {
			t.Fatalf("%s: __inputs = %+v", f, d.Inputs)
		}
		if len(d.Panels) == 0 {
			t.Fatalf("%s: no panels", f)
		}
		ids := map[int]bool{}
		for _, p := range d.Panels {
			if ids[p.ID] || p.Title == "" || p.Type == "" {
				t.Fatalf("%s: panel %d %q (%s) is duplicated or unnamed", f, p.ID, p.Title, p.Type)
			}
			ids[p.ID] = true
			if p.Datasource.UID != "${DS_PROMETHEUS}" || len(p.Targets) == 0 {
				t.Fatalf("%s panel %q: datasource %q, %d targets", f, p.Title, p.Datasource.UID, len(p.Targets))
			}
			for _, tg := range p.Targets {
				names := metricName.FindAllString(tg.Expr, -1)
				if len(names) == 0 {
					t.Fatalf("%s panel %q: no packeteer_ metric in %q", f, p.Title, tg.Expr)
				}
				have := map[string]bool{}
				for _, n := range names {
					if _, ok := rendered[n]; !ok {
						t.Fatalf("%s panel %q: %s is not rendered by /metrics", f, p.Title, n)
					}
					for l := range rendered[n] {
						have[l] = true
					}
				}
				var want []string
				for _, m := range byClause.FindAllStringSubmatch(tg.Expr, -1) {
					for _, l := range strings.Split(m[1], ",") {
						want = append(want, strings.TrimSpace(l))
					}
				}
				for _, m := range selector.FindAllStringSubmatch(tg.Expr, -1) {
					want = append(want, m[1])
				}
				for _, m := range legendVar.FindAllStringSubmatch(tg.Legend, -1) {
					want = append(want, m[1])
				}
				sort.Strings(want)
				for _, l := range want {
					if !have[l] {
						t.Errorf("%s panel %q: label %q is not on %v", f, p.Title, l, names)
					}
				}
			}
		}
	}
}

func TestExportMetrics(t *testing.T) {
	if got := ExportMetrics(nil); len(got) != 0 {
		t.Fatalf("no exporters must render nothing, got %q", got)
	}
	out := string(ExportMetrics([]export.Stat{{Exporter: "k", Stream: "events", Sent: 5, Failed: 2, Dropped: 1}}))
	for _, want := range []string{
		`packeteer_export_records_total{exporter="k",stream="events",result="sent"} 5`,
		`packeteer_export_records_total{exporter="k",stream="events",result="failed"} 2`,
		`packeteer_export_records_total{exporter="k",stream="events",result="dropped"} 1`,
		"# TYPE packeteer_export_records_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}
