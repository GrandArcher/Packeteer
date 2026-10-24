package httpapi

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// explainEngine runs the real decision engine over one held-back prefix
// (198.51.100.0/24, 10 ms faster via lab-b, under the 15 ms threshold) and
// one that moves (203.0.113.0/24).
func explainEngine(t *testing.T) (*policy.Engine, time.Time) {
	t.Helper()
	sc, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	held, moved := netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")
	res := func(p netip.Prefix, prov string, rtt time.Duration) probe.Result {
		return probe.Result{Provider: prov, Prefix: p, Time: at, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: rtt}}
	}
	e := policy.NewEngine(policy.Config{Mode: "observe", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
		HoldTime: 5 * time.Minute, MaxImprovements: 10, MaxResultAge: 2 * time.Minute}, sc)
	e.Evaluate(policy.Input{
		Results: []probe.Result{
			res(held, "lab-a", 50*time.Millisecond), res(held, "lab-b", 40*time.Millisecond),
			res(moved, "lab-a", 90*time.Millisecond), res(moved, "lab-b", 30*time.Millisecond),
		},
		ProviderUp: map[string]bool{"lab-a": true, "lab-b": true},
		RIBEnabled: true, RIBReady: true,
		Native: map[netip.Prefix]string{held: "lab-a", moved: "lab-a"},
	}, at)
	return e, at
}

// explainServer serves the decisions of explainEngine.
func explainServer(t *testing.T) http.Handler {
	t.Helper()
	e, at := explainEngine(t)
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot {
		decisions, decidedAt := e.Decisions()
		return Assemble(Input{Mode: "observe", At: at, Decisions: decisions, DecidedAt: decidedAt})
	}})
	if err != nil {
		t.Fatal(err)
	}
	s.SetExplainer(e)
	return s.Handler()
}

func TestDecisionExplainAPI(t *testing.T) {
	h := explainServer(t)
	var body struct {
		Prefix  string `json:"prefix"`
		Action  string `json:"action"`
		Explain struct {
			Outcome        string `json:"outcome"`
			BlockedBy      string `json:"blocked_by"`
			Counterfactual string `json:"counterfactual"`
			Gates          []struct {
				Gate, Status, Value, Limit, Detail string
			} `json:"gates"`
			Samples []struct {
				Provider string  `json:"provider"`
				Role     string  `json:"role"`
				RTTMs    float64 `json:"rtt_ms"`
			} `json:"samples"`
		} `json:"explain"`
	}
	rec := mdo(h, http.MethodGet, "/api/decisions/198.51.100.0/24", "", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Prefix != "198.51.100.0/24" || body.Action != policy.ActionNone {
		t.Fatalf("body = %s", rec.Body)
	}
	ex := body.Explain
	if ex.Outcome != "held" || ex.BlockedBy != "thresholds" {
		t.Fatalf("explain = %+v", ex)
	}
	if want := "would move to lab-b if its RTT delta reached >= 15 ms (now 10 ms) with loss no higher than 0%, or its loss were >= 1 pt lower (now 0 pt)"; ex.Counterfactual != want {
		t.Fatalf("counterfactual = %q, want %q", ex.Counterfactual, want)
	}
	var names []string
	for _, g := range ex.Gates {
		names = append(names, g.Gate)
		if g.Gate == "thresholds" && (g.Status != "fail" || !strings.Contains(g.Value, "lab-b vs lab-a: loss gain 0 pt, rtt gain 10 ms (20%)")) {
			t.Fatalf("thresholds gate = %+v", g)
		}
	}
	if got := strings.Join(names, " "); got != "rib freshness thresholds confirm_rounds hold_time cap policy allowlist route_check rpki irr" {
		t.Fatalf("gates = %s", got)
	}
	if len(ex.Samples) != 2 || ex.Samples[0].Role != "current" || ex.Samples[1].Role != "challenger" || ex.Samples[1].RTTMs != 40 {
		t.Fatalf("samples = %+v", ex.Samples)
	}

	rec = mdo(h, http.MethodGet, "/api/decisions/203.0.113.0/24", "", "", true)
	var moved struct {
		Action  string `json:"action"`
		Explain struct {
			Outcome   string `json:"outcome"`
			BlockedBy string `json:"blocked_by"`
		} `json:"explain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &moved); err != nil {
		t.Fatal(err)
	}
	if moved.Action != policy.ActionImprove || moved.Explain.Outcome != "moved" || moved.Explain.BlockedBy != "" {
		t.Fatalf("moved prefix: %s", rec.Body)
	}
}

func TestDecisionExplainAPIErrors(t *testing.T) {
	h := explainServer(t)
	for path, want := range map[string]int{
		"/api/decisions/not-a-prefix":      http.StatusBadRequest,
		"/api/decisions/198.51.100.7/24":   http.StatusBadRequest,
		"/api/decisions/192.0.2.0/24":      http.StatusNotFound,
		"/api/decisions/2001:db8::/32":     http.StatusNotFound,
		"/api/decisions/198.51.100.0%2F24": http.StatusOK,
	} {
		if rec := mdo(h, http.MethodGet, path, "", "", true); rec.Code != want {
			t.Errorf("%s: status %d, want %d: %s", path, rec.Code, want, rec.Body)
		}
	}
	if rec := mdo(h, http.MethodGet, "/api/decisions/198.51.100.0/24", "", "", false); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: status %d", rec.Code)
	}
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Snapshot{} }})
	if err != nil {
		t.Fatal(err)
	}
	if rec := mdo(s.Handler(), http.MethodGet, "/api/decisions/198.51.100.0/24", "", "", true); rec.Code != http.StatusNotFound {
		t.Errorf("no engine: status %d", rec.Code)
	}
}

// The row and the explanation both come from the engine's latest round, not
// from the published snapshot, which may be one round behind.
func TestDecisionExplainIgnoresSnapshotRound(t *testing.T) {
	e, _ := explainEngine(t)
	s, err := New(Options{User: "ops", Password: "secret", Snapshot: func() Snapshot { return Snapshot{Mode: "observe"} }})
	if err != nil {
		t.Fatal(err)
	}
	s.SetExplainer(e)
	rec := mdo(s.Handler(), http.MethodGet, "/api/decisions/203.0.113.0/24", "", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		DecidedAt string `json:"decided_at"`
		Action    string `json:"action"`
		Explain   struct {
			Outcome string `json:"outcome"`
		} `json:"explain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Action != policy.ActionImprove || body.Explain.Outcome != "moved" || body.DecidedAt != "2026-10-17T12:00:00Z" {
		t.Fatalf("body = %s", rec.Body)
	}
}
