package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/atlas"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const atlasTestKey = "k3y-1111-fake-test-value"

// atlasFake counts creates and answers the three calls the client makes.
func atlasFake(t *testing.T, creates *atomic.Int32) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/measurements/":
			creates.Add(1)
			_, _ = w.Write([]byte(`{"measurements":[4242]}`))
		case strings.HasSuffix(r.URL.Path, "/results/"):
			_, _ = w.Write([]byte(`[{"type":"ping","prb_id":7,"sent":3,"rcvd":3,"avg":21.5},{"type":"ping","prb_id":8,"sent":3,"rcvd":3,"avg":25.5},{"type":"ping","prb_id":9,"sent":3,"rcvd":0,"avg":-1}]`))
		case r.URL.Path == "/credits/":
			_, _ = w.Write([]byte(`{"current_balance": 777}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

func atlasSnap(target string) Snapshot {
	return Snapshot{Probes: []Probe{
		{Provider: "transit-a", Prefix: "198.51.100.0/24", Target: target, OK: true, Received: 3, RTTAvgMs: 12.5, LossPct: 0, Confidence: probe.Confidence{Level: "high"}},
		{Provider: "transit-b", Prefix: "198.51.100.0/24", Target: target, OK: true, Received: 3, RTTAvgMs: 9.5, LossPct: 1, Confidence: probe.Confidence{Level: "medium"}},
	}}
}

func atlasServer(t *testing.T, c *atlas.Client, snap Snapshot, user string) string {
	t.Helper()
	s, err := New(Options{User: user, Password: map[bool]string{true: "pw"}[user != ""], Snapshot: func() Snapshot { return snap }, Atlas: c})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts.URL
}

func atlasClient(t *testing.T, base string, cfg atlas.Config) *atlas.Client {
	t.Helper()
	cfg.Enabled, cfg.BaseURL, cfg.StateFile = true, base, t.TempDir()+"/atlas.json"
	return atlas.New(cfg, atlasTestKey, "test", nil)
}

func postAtlas(t *testing.T, base, body string, user string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/api/atlas/measure", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.SetBasicAuth(user, "pw")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

func getAtlas(t *testing.T, base, prefix, user string) AtlasView {
	t.Helper()
	code, _, raw := do(t, http.MethodGet, base+"/api/atlas?prefix="+url.QueryEscape(prefix), user, map[bool]string{true: "pw"}[user != ""])
	if code != http.StatusOK {
		t.Fatalf("GET status %d: %s", code, raw)
	}
	var v AtlasView
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return v
}

func TestAtlasOffByDefault(t *testing.T) {
	for name, c := range map[string]*atlas.Client{"unset": nil, "disabled": atlas.New(atlas.Config{}, atlasTestKey, "test", nil)} {
		base := atlasServer(t, c, atlasSnap("198.51.100.7"), "op")
		// A bad prefix is not even examined while the integration is off.
		for _, p := range []string{"198.51.100.0/24", "not-a-prefix"} {
			v := getAtlas(t, base, p, "op")
			if v.State != atlas.StateOff || v.Status != nil || len(v.Local) != 0 || v.CanMeasure {
				t.Errorf("%s %q: %+v", name, p, v)
			}
		}
		if code, body := postAtlas(t, base, `{"prefix":"198.51.100.0/24","type":"ping"}`, "op"); code != http.StatusNotFound || !strings.Contains(body, "not enabled") {
			t.Errorf("%s POST: %d %s", name, code, body)
		}
	}
}

func TestAtlasNoKey(t *testing.T) {
	c := atlas.New(atlas.Config{Enabled: true, StateFile: t.TempDir() + "/a.json"}, "", "test", nil)
	base := atlasServer(t, c, atlasSnap("198.51.100.7"), "op")
	v := getAtlas(t, base, "198.51.100.0/24", "op")
	if v.State != atlas.StateNoKey || v.CanMeasure {
		t.Errorf("view = %+v", v)
	}
	if code, body := postAtlas(t, base, `{"prefix":"198.51.100.0/24","type":"ping"}`, "op"); code != http.StatusServiceUnavailable || !strings.Contains(body, atlas.KeyEnv) {
		t.Errorf("POST: %d %s", code, body)
	}
}

func TestAtlasMeasureAndShowBesideLocal(t *testing.T) {
	var creates atomic.Int32
	c := atlasClient(t, atlasFake(t, &creates), atlas.Config{MaxMeasurementsPerHour: 2})
	base := atlasServer(t, c, atlasSnap("198.51.100.7"), "op")

	v := getAtlas(t, base, "198.51.100.0/24", "op")
	if v.State != atlas.StateOK || v.Target != "198.51.100.7" || !v.CanMeasure || len(v.Measurements) != 0 ||
		len(v.Local) != 2 || v.Local[1].Provider != "transit-b" || v.Local[1].RTTAvgMs != 9.5 || v.Local[1].Confidence != "medium" {
		t.Fatalf("before: %+v", v)
	}
	code, body := postAtlas(t, base, `{"prefix":"198.51.100.0/24","type":"ping"}`, "op")
	if code != http.StatusOK {
		t.Fatalf("POST: %d %s", code, body)
	}
	var rec atlas.Record
	if err := json.Unmarshal([]byte(body), &rec); err != nil || rec.ID != 4242 || rec.Trigger != atlas.TriggerManual || rec.Type != "ping" || rec.Target != "198.51.100.7" {
		t.Fatalf("record = %+v %v", rec, err)
	}
	v = getAtlas(t, base, "198.51.100.0/24", "op")
	if len(v.Measurements) != 1 || v.Measurements[0].State != atlas.RecordPending || v.Status.CreditsToday != rec.Credits {
		t.Fatalf("after: %+v", v)
	}
	if strings.Contains(body, atlasTestKey) {
		t.Error("the key is in the response")
	}

	// The cap answers 429 and the fake sees no further create.
	postAtlas(t, base, `{"prefix":"198.51.100.0/24","type":"ping"}`, "op")
	if code, body := postAtlas(t, base, `{"prefix":"198.51.100.0/24","type":"ping"}`, "op"); code != http.StatusTooManyRequests || !strings.Contains(body, "hourly measurement cap") {
		t.Errorf("over the cap: %d %s", code, body)
	}
	if creates.Load() != 2 {
		t.Errorf("creates = %d, want 2", creates.Load())
	}
}

func TestAtlasMeasureRefusals(t *testing.T) {
	var creates atomic.Int32
	c := atlasClient(t, atlasFake(t, &creates), atlas.Config{})
	base := atlasServer(t, c, atlasSnap("198.51.100.7"), "op")
	cases := []struct {
		body string
		want int
	}{
		{`{"prefix":"nope","type":"ping"}`, http.StatusBadRequest},
		{`{"prefix":"198.51.100.0/24","type":"http"}`, http.StatusBadRequest},
		{`{"prefix":"203.0.113.0/24","type":"ping"}`, http.StatusNotFound}, // no test address
		{`{"prefix":"198.51.100.0/24","type":"ping","target":"192.0.2.1"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if code, body := postAtlas(t, base, tc.body, "op"); code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.body, code, body, tc.want)
		}
	}
	// A private test address is never sent out.
	priv := atlasServer(t, c, atlasSnap("10.1.2.3"), "op")
	if code, _ := postAtlas(t, priv, `{"prefix":"198.51.100.0/24","type":"ping"}`, "op"); code != http.StatusBadRequest {
		t.Errorf("private target: %d", code)
	}
	if v := getAtlas(t, priv, "198.51.100.0/24", "op"); v.CanMeasure {
		t.Errorf("private target can be measured: %+v", v)
	}
	// Without auth the server does not spend credits.
	open := atlasServer(t, c, atlasSnap("198.51.100.7"), "")
	if code, body := postAtlas(t, open, `{"prefix":"198.51.100.0/24","type":"ping"}`, ""); code != http.StatusForbidden || !strings.Contains(body, "require auth") {
		t.Errorf("no auth: %d %s", code, body)
	}
	if v := getAtlas(t, open, "198.51.100.0/24", ""); v.CanMeasure {
		t.Errorf("no auth can measure: %+v", v)
	}
	if creates.Load() != 0 {
		t.Errorf("creates = %d, want 0", creates.Load())
	}
}

func TestAtlasEnabledChecksThePrefix(t *testing.T) {
	var creates atomic.Int32
	base := atlasServer(t, atlasClient(t, atlasFake(t, &creates), atlas.Config{}), atlasSnap("198.51.100.7"), "op")
	for _, p := range []string{"", "not-a-prefix", "198.51.100.1"} {
		if code, _, _ := do(t, http.MethodGet, base+"/api/atlas?prefix="+url.QueryEscape(p), "op", "pw"); code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", p, code)
		}
	}
}

func TestSystemAtlasRow(t *testing.T) {
	bal := 777
	since := time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	checked := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ok := &atlas.Status{State: atlas.StateOK, ProbeID: 6001, ProbeURL: "https://atlas.ripe.net/probes/6001/", Probe: &atlas.ProbeStatus{Status: "Connected", Since: since},
		Balance: &bal, Checked: checked, CreditsToday: 36, MaxCreditsPerDay: 500, MeasurementsLastHour: 2, MaxMeasurementsPerHour: 4}
	row := func(st *atlas.Status) Component {
		return find(t, BuildSystem(healthySnap("observe"), SystemFacts{Atlas: st}, nil, nil), KindAtlas, "ripe-atlas")
	}
	c := row(ok)
	if c.State != StateOK || c.Link != "https://atlas.ripe.net/probes/6001/" ||
		c.Detail != "own probe 6001 Connected since 2026-10-20T10:00:00Z, 777 credits, today 36 of 500 credits, 2 of 4 measurements in the last hour" {
		t.Errorf("ok row = %+v", c)
	}
	down := *ok
	down.Probe = &atlas.ProbeStatus{Status: "Disconnected", Since: since}
	if c := row(&down); c.State != StateDegraded || !strings.Contains(c.Detail, "Disconnected") {
		t.Errorf("disconnected row = %+v", c)
	}
	failed := *ok
	failed.Error = "credits: atlas: GET /credits/: HTTP 403"
	if c := row(&failed); c.State != StateDegraded || c.Error == "" {
		t.Errorf("failed row = %+v", c)
	}
	fresh := atlas.Status{State: atlas.StateOK, MaxCreditsPerDay: 500, MaxMeasurementsPerHour: 4}
	if c := row(&fresh); c.State != StateIdle || strings.Contains(c.Detail, "own probe") {
		t.Errorf("unread row = %+v", c)
	}
	if c := row(&atlas.Status{State: atlas.StateNoKey}); c.State != StateIdle || !strings.Contains(c.Detail, atlas.KeyEnv) {
		t.Errorf("no key row = %+v", c)
	}
	for _, st := range []*atlas.Status{nil, {State: atlas.StateOff}} {
		for _, c := range BuildSystem(healthySnap("observe"), SystemFacts{Atlas: st}, nil, nil).Components {
			if c.Kind == KindAtlas {
				t.Errorf("off adds a row: %+v", c)
			}
		}
	}
}

func TestAtlasPanelWiring(t *testing.T) {
	html, js, sys := mustWeb(t, "web/prefix.html"), mustWeb(t, "web/atlas.js"), mustWeb(t, "web/system.js")
	for _, want := range []string{`id="atlas-panel" hidden`, `id="atlas-body"`, "Seen from RIPE Atlas", `src="/atlas.js"`} {
		if !strings.Contains(html, want) {
			t.Errorf("prefix.html lacks %q", want)
		}
	}
	for _, want := range []string{`"/api/atlas?prefix="`, `"/api/atlas/measure"`, `data.state === "off"`} {
		if !strings.Contains(js, want) {
			t.Errorf("atlas.js lacks %q", want)
		}
	}
	if !strings.Contains(sys, `["atlas", "RIPE Atlas"]`) || !strings.Contains(sys, "c.link") {
		t.Error("system.js does not list the RIPE Atlas row and its link")
	}
	if prefix := mustWeb(t, "web/prefix.js"); strings.Contains(prefix, "atlas") || strings.Contains(prefix, "postJSON") {
		t.Error("prefix.js must stay read-only; the Atlas panel lives in atlas.js")
	}
}

// A viewer may read the panel but is not offered the buttons that spend
// credits; an operator is.
func TestAtlasCanMeasureNeedsOperator(t *testing.T) {
	var creates atomic.Int32
	c := atlasClient(t, atlasFake(t, &creates), atlas.Config{})
	e := newUIWith(t, func(o *Options) {
		o.Atlas = c
		o.Snapshot = func() Snapshot { return atlasSnap("198.51.100.7") }
	})
	for role, want := range map[plugin.Role]bool{plugin.RoleViewer: false, plugin.RoleOperator: true, plugin.RoleAdmin: true} {
		rec, body := e.do(t, http.MethodGet, "/api/atlas?prefix=198.51.100.0/24", role, nil)
		if rec.Code != http.StatusOK || body["state"] != "ok" || body["can_measure"] != want {
			t.Errorf("%s: %d can_measure=%v, want %v: %s", role, rec.Code, body["can_measure"], want, rec.Body)
		}
	}
}

// The panel picks the test address by the same rule as the after-move
// ping: a row that received replies, else the first row with a target.
func TestAtlasTargetPrefersAnsweredRow(t *testing.T) {
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	snap := Snapshot{Probes: []Probe{
		{Provider: "transit-a", Prefix: prefix.String(), Target: "198.51.100.1", OK: false, Sent: 3, Received: 0},
		{Provider: "transit-b", Prefix: prefix.String(), Target: "198.51.100.9", OK: true, Sent: 3, Received: 3},
	}}
	if addr, _ := atlasTarget(snap, prefix); addr.String() != "198.51.100.9" {
		t.Errorf("target = %s, want the answered row's 198.51.100.9", addr)
	}
}
