package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestAnomalyEndpointAndMetrics(t *testing.T) {
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetBasicAuth("ops", "secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	off, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	rec := get(off.Handler(), "/api/anomalies")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) || !strings.Contains(rec.Body.String(), `"anomalies":[]`) {
		t.Fatalf("not configured: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(get(off.Handler(), "/metrics").Body.String(), "packeteer_anomal") {
		t.Fatal("anomaly metrics without detection")
	}
	st := anomaly.Status{Detector: "baseline", Tracked: 3, Mitigating: 1, ActionsLastHour: 1, Rules: []anomaly.Rule{},
		Anomalies: []anomaly.Anomaly{{ID: "a1", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Protocol: 17, Mbps: 400, State: anomaly.StateMitigating,
			Mitigation: "m1", Since: time.Unix(1_700_000_000, 0)}},
		Feed: []anomaly.Change{}}
	on, err := New(Options{User: "ops", Password: "secret", Anomaly: func() anomaly.Status { return st }, Snapshot: func() Snapshot { return Assemble(sampleInput()) }})
	if err != nil {
		t.Fatal(err)
	}
	rec = get(on.Handler(), "/api/anomalies")
	var body struct {
		Enabled   bool `json:"enabled"`
		Anomalies []struct {
			Prefix   string            `json:"prefix"`
			Protocol plugin.IPProtocol `json:"protocol"`
			State    string            `json:"state"`
		} `json:"anomalies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || len(body.Anomalies) != 1 || body.Anomalies[0].Prefix != "198.51.100.0/24" || body.Anomalies[0].Protocol != 17 ||
		!strings.Contains(rec.Body.String(), `"protocol":"udp"`) {
		t.Fatalf("body = %s", rec.Body)
	}
	m := get(on.Handler(), "/metrics").Body.String()
	for _, want := range []string{"packeteer_anomalies_active 1", "packeteer_anomaly_mitigating 1", "packeteer_anomaly_baselines 3", "packeteer_anomaly_actions_last_hour 1"} {
		if !strings.Contains(m, want) {
			t.Fatalf("metrics lack %q:\n%s", want, m)
		}
	}
}
