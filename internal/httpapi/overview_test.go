package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

func hintIDs(h []Hint) []string {
	var out []string
	for _, x := range h {
		out = append(out, x.ID)
	}
	return out
}

func hasHint(h []Hint, id string) bool {
	for _, x := range h {
		if x.ID == id {
			return true
		}
	}
	return false
}

// firstRun is the stock image with config.example.yaml mounted: two
// providers, no sources, no BGP, history on.
func firstRun() Input {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return Input{
		Version: "test", Mode: config.ModeObserve, Started: true, At: at,
		Providers: []config.Provider{
			{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"},
			{Name: "transit-b", SourceIP: "192.0.2.12", NextHop: "192.0.2.2"},
		},
		Status: []probe.ProviderStatus{
			{Name: "transit-a", Up: true, Since: at},
			{Name: "transit-b", Up: true, Since: at},
		},
	}
}

func TestOverviewFirstRunChecklist(t *testing.T) {
	o := BuildOverview(Assemble(firstRun()), Setup{MaxImprovements: 50}, []Feature{{"history", true}})
	if o.Mode != "observe" || !o.Ready || !o.Started {
		t.Fatalf("meta = %+v", o.meta)
	}
	if len(o.Setup) == 0 || o.Setup[0].ID != "sources" || o.Setup[0].Level != HintTodo {
		t.Fatalf("first hint must be the missing sources: %v", hintIDs(o.Setup))
	}
	if !hasHint(o.Setup, "bgp") {
		t.Errorf("no-BGP hint missing: %v", hintIDs(o.Setup))
	}
	if hasHint(o.Setup, "history") || hasHint(o.Setup, "first-round") || hasHint(o.Setup, "providers-down") {
		t.Errorf("unexpected hints: %v", hintIDs(o.Setup))
	}
	if o.Counts.Providers != 2 || o.Counts.ProvidersUp != 2 || o.Counts.Prefixes != 0 || o.Counts.MaxImprovements != 50 {
		t.Errorf("counts = %+v", o.Counts)
	}
	if o.Sources == nil || o.Providers == nil || o.Features == nil {
		t.Error("lists must encode as [] not null")
	}
}

func TestOverviewMeasuringWithRIB(t *testing.T) {
	in := sampleInput()
	in.Peers[0].Established = true
	o := BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, MaxImprovements: 50}, []Feature{{"history", true}})
	if hasHint(o.Setup, "sources") || hasHint(o.Setup, "bgp") || hasHint(o.Setup, "bgp-down") || hasHint(o.Setup, "rib") {
		t.Errorf("unexpected hints: %v", hintIDs(o.Setup))
	}
	if o.Counts.Prefixes != 2 || o.Counts.Measured != 1 || o.Counts.InRIB != 1 || o.Counts.Recommended != 1 || o.Counts.Improvements != 1 {
		t.Errorf("counts = %+v", o.Counts)
	}
	if o.BGP.Established != 1 || o.BGP.Peers != 1 {
		t.Errorf("bgp = %+v", o.BGP)
	}
	var a, b ProviderHealth
	for _, p := range o.Providers {
		switch p.Name {
		case "transit-a":
			a = p
		case "transit-b":
			b = p
		}
	}
	if a.OK != 1 || a.Failed != 0 || !a.Up || b.Up || !b.Excluded {
		t.Errorf("providers = %+v", o.Providers)
	}
	if o.Counts.ProvidersUp != 1 {
		t.Errorf("providers up = %d", o.Counts.ProvidersUp)
	}
}

func TestOverviewWarnings(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p := netip.MustParsePrefix("198.51.100.0/24")
	in := firstRun()
	in.Status[1].Up = false
	in.Results = []probe.Result{
		{Provider: "transit-a", Prefix: p, Err: "sendto: permission denied", Time: at},
		{Provider: "transit-b", Prefix: p, Err: "source down", Time: at},
	}
	in.BGPConfigured = true
	in.Peers = []rib.PeerState{{Address: netip.MustParseAddr("192.0.2.254"), State: "active"}}
	o := BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, nil)
	for _, id := range []string{"provider-transit-a", "bgp-down", "history"} {
		if !hasHint(o.Setup, id) {
			t.Errorf("missing %s: %v", id, hintIDs(o.Setup))
		}
	}
	// transit-b is down: its own warning would repeat the health column.
	if hasHint(o.Setup, "provider-transit-b") || hasHint(o.Setup, "providers-down") {
		t.Errorf("unexpected hints: %v", hintIDs(o.Setup))
	}
	if o.Ready {
		t.Error("BGP configured with no session must not be ready")
	}
	for i := 1; i < len(o.Setup); i++ {
		order := map[string]int{HintTodo: 0, HintWarn: 1, HintInfo: 2}
		if order[o.Setup[i-1].Level] > order[o.Setup[i].Level] {
			t.Fatalf("hints not ordered by level: %+v", o.Setup)
		}
	}

	// Every provider down; a session up but no probed prefix learned.
	in.Status[0].Up = false
	in.Peers[0].Established = true
	in.RIBReady = true
	in.Results = []probe.Result{{Provider: "transit-a", Prefix: p, Prober: "icmp", Stats: probe.Stats{Sent: 1, Received: 1}, Time: at}}
	o = BuildOverview(Assemble(in), Setup{Sources: []string{"flow"}}, nil)
	if !hasHint(o.Setup, "providers-down") || !hasHint(o.Setup, "rib") {
		t.Errorf("hints = %v", hintIDs(o.Setup))
	}
	// Without a learned exit there is nothing to differ from.
	if o.Counts.Measured != 1 || o.Counts.Recommended != 0 {
		t.Errorf("counts = %+v", o.Counts)
	}

	// Not started yet, sources but no prefixes.
	in = firstRun()
	in.Started = false
	o = BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, nil)
	if !hasHint(o.Setup, "starting") || hasHint(o.Setup, "first-round") {
		t.Errorf("hints = %v", hintIDs(o.Setup))
	}
	in.Started = true
	o = BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, nil)
	if !hasHint(o.Setup, "first-round") {
		t.Errorf("hints = %v", hintIDs(o.Setup))
	}
}

func TestOverviewEndpoint(t *testing.T) {
	srv, err := New(Options{
		Snapshot: func() Snapshot { return Assemble(firstRun()) },
		Setup:    Setup{MaxImprovements: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/overview", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var o struct {
		Mode     string    `json:"mode"`
		Setup    []Hint    `json:"setup"`
		Features []Feature `json:"features"`
		Sources  []string  `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.Mode != "observe" || o.Sources == nil || !hasHint(o.Setup, "sources") || !hasHint(o.Setup, "history") {
		t.Errorf("overview = %s", rec.Body)
	}
	for _, f := range o.Features {
		if f.On {
			t.Errorf("feature %s on with nothing configured", f.Name)
		}
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/overview", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status %d", rec.Code)
	}
}

// The controller always installs a federation reader; a standalone
// instance reports it off.
func TestOverviewFederationFeature(t *testing.T) {
	for _, on := range []bool{false, true} {
		srv, err := New(Options{
			Snapshot:   func() Snapshot { return Assemble(firstRun()) },
			Federation: func() federation.Status { return federation.Status{Enabled: on} },
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range srv.overview().Features {
			if f.Name == "federation" && f.On != on {
				t.Errorf("federation on = %v, want %v", f.On, on)
			}
		}
	}
}

func healthInput(res ...probe.Result) Input {
	in := firstRun()
	in.Providers = append(in.Providers, config.Provider{Name: "transit-c", SourceIP: "192.0.2.13", NextHop: "192.0.2.3"})
	in.Status = append(in.Status, probe.ProviderStatus{Name: "transit-c", Up: true})
	in.Results = res
	return in
}

func answered(name string, p netip.Prefix, sent, got int) probe.Result {
	st := probe.Stats{Sent: sent, Received: got, LossPct: 100 * float64(sent-got) / float64(sent)}
	if got > 0 {
		st.RTTAvg, st.RTTMin, st.RTTMax = 12*time.Millisecond, 12*time.Millisecond, 12*time.Millisecond
	}
	return probe.Result{Provider: name, Prefix: p, Stats: st, Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
}

// A provider with 100% loss or no answer is down, partial loss above the
// threshold is degraded, and the rest stay up (#343).
func TestOverviewProviderHealthFromMeasurement(t *testing.T) {
	p1 := netip.MustParsePrefix("198.51.100.0/24")
	p2 := netip.MustParsePrefix("203.0.113.0/24")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	in := healthInput(
		answered("transit-a", p1, 10, 10), answered("transit-a", p2, 10, 10),
		answered("transit-b", p1, 10, 0), answered("transit-b", p2, 10, 0),
		probe.Result{Provider: "transit-c", Prefix: p1, Err: "fixed prober: no result", Time: at},
		probe.Result{Provider: "transit-c", Prefix: p2, Err: "fixed prober: no result", Time: at},
	)
	o := BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, []Feature{{"history", true}})
	state := map[string]ProviderHealth{}
	for _, h := range o.Providers {
		state[h.Name] = h
	}
	if state["transit-a"].State != HealthUp || state["transit-a"].OK != 2 {
		t.Errorf("transit-a = %+v", state["transit-a"])
	}
	b := state["transit-b"]
	if b.State != HealthDown || b.OK != 0 || b.Failed != 2 || b.LossPct != 100 {
		t.Errorf("a provider at 100%% loss must be down and not counted ok: %+v", b)
	}
	if c := state["transit-c"]; c.State != HealthDown || c.Failed != 2 {
		t.Errorf("transit-c = %+v", c)
	}
	if o.Counts.ProvidersUp != 3 || o.Counts.ProvidersHealthy != 1 || o.Counts.Providers != 3 {
		t.Errorf("counts = %+v", o.Counts)
	}
	want := []Problem{
		{Provider: "transit-b", State: HealthDown, Detail: "100% loss"},
		{Provider: "transit-c", State: HealthDown, Detail: "no answer"},
	}
	if len(o.Problems) != 2 || o.Problems[0] != want[0] || o.Problems[1] != want[1] {
		t.Errorf("problems = %+v", o.Problems)
	}
	if !hasHint(o.Setup, "provider-transit-b") || o.Counts.Warnings != 2 {
		t.Errorf("warnings = %d, hints %v", o.Counts.Warnings, hintIDs(o.Setup))
	}
}

func TestOverviewProviderHealthThresholds(t *testing.T) {
	p1 := netip.MustParsePrefix("198.51.100.0/24")
	in := healthInput(answered("transit-a", p1, 10, 10), answered("transit-b", p1, 10, 9), answered("transit-c", p1, 10, 4))
	o := BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, nil)
	got := map[string]string{}
	for _, h := range o.Providers {
		got[h.Name] = h.State
	}
	if got["transit-a"] != HealthUp || got["transit-b"] != HealthDegraded || got["transit-c"] != HealthDown {
		t.Errorf("states = %v", got)
	}
	// Down providers are listed before degraded ones.
	if len(o.Problems) != 2 || o.Problems[0].Provider != "transit-c" || o.Problems[0].Detail != "60% loss" ||
		o.Problems[1].Provider != "transit-b" || o.Problems[1].State != HealthDegraded || o.Problems[1].Detail != "10% loss" {
		t.Errorf("problems = %+v", o.Problems)
	}
	if o.Counts.ProvidersHealthy != 1 {
		t.Errorf("healthy = %d", o.Counts.ProvidersHealthy)
	}
	// Raised thresholds move transit-b to up and transit-c to degraded.
	o = BuildOverview(Assemble(in), Setup{DegradedLossPct: 20, DownLossPct: 70}, nil)
	for _, h := range o.Providers {
		if h.Name == "transit-b" && h.State != HealthUp {
			t.Errorf("transit-b at 10%% loss with degraded_loss_pct 20 = %s", h.State)
		}
		if h.Name == "transit-c" && h.State != HealthDegraded {
			t.Errorf("transit-c at 60%% loss with down_loss_pct 70 = %s", h.State)
		}
	}
}

func TestOverviewHealthyHasNoProblems(t *testing.T) {
	p1 := netip.MustParsePrefix("198.51.100.0/24")
	in := healthInput(answered("transit-a", p1, 10, 10), answered("transit-b", p1, 10, 10))
	o := BuildOverview(Assemble(in), Setup{Sources: []string{"static"}, DegradedLossPct: 5, DownLossPct: 50}, []Feature{{"history", true}})
	// transit-c has no result yet: not a problem, and not counted healthy.
	if o.Problems == nil || len(o.Problems) != 0 || o.Counts.ProvidersHealthy != 2 {
		t.Errorf("problems %+v healthy %d", o.Problems, o.Counts.ProvidersHealthy)
	}
	raw, err := json.Marshal(o)
	if err != nil || !strings.Contains(string(raw), `"problems":[]`) || !strings.Contains(string(raw), `"state":"unknown"`) {
		t.Errorf("json = %s %v", raw, err)
	}
}

func TestOverviewSourceDownIsDown(t *testing.T) {
	in := healthInput()
	in.Status[1] = probe.ProviderStatus{Name: "transit-b", Up: false, Reason: "bind: cannot assign requested address"}
	o := BuildOverview(Assemble(in), Setup{DegradedLossPct: 5, DownLossPct: 50}, nil)
	if len(o.Problems) != 1 || o.Problems[0].Provider != "transit-b" ||
		o.Problems[0].Detail != "probe source down: bind: cannot assign requested address" {
		t.Errorf("problems = %+v", o.Problems)
	}
}

// A provider that is starting, measured by a federation peer, or not
// reported yet has no probe status and no failure: it is unknown, never a
// problem (#343).
func TestOverviewUnprobedProvidersAreNotProblems(t *testing.T) {
	setup := Setup{DegradedLossPct: 5, DownLossPct: 50}
	for _, tc := range []struct {
		name    string
		started bool
		domain  string
	}{
		{"starting", false, ""},
		{"federated", true, "east"},
		{"unreported", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := firstRun()
			in.Started = tc.started
			in.Status = nil
			in.Providers = []config.Provider{{Name: "far", SourceIP: "192.0.2.14", NextHop: "192.0.2.4", Domain: tc.domain}}
			o := BuildOverview(Assemble(in), setup, nil)
			if len(o.Providers) != 1 || o.Providers[0].State != HealthUnknown || o.Providers[0].Detail != "" {
				t.Fatalf("providers = %+v", o.Providers)
			}
			if len(o.Problems) != 0 || o.Counts.ProvidersHealthy != 0 || o.Counts.Providers != 1 {
				t.Errorf("problems %+v counts %+v", o.Problems, o.Counts)
			}
		})
	}
}
