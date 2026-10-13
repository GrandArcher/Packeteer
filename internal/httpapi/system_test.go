package httpapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var sysT0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func find(t *testing.T, s System, kind, name string) Component {
	t.Helper()
	for _, c := range s.Components {
		if c.Kind == kind && c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s row %q in %+v", kind, name, s.Components)
	return Component{}
}

func healthySnap(mode string) Snapshot {
	return Snapshot{
		Version: "v0.7.0-test", Mode: mode, Started: true, BGPConfigured: true, RIBReady: true,
		Peers: []Peer{{Address: "192.0.2.254", State: "ESTABLISHED", Established: true, Since: sysT0}},
		Providers: []Provider{
			{Name: "transit-a", Up: true, Since: sysT0},
			{Name: "transit-b", Up: false, Reason: "probe source address unavailable", Since: sysT0.Add(time.Minute)},
		},
		Probes: []Probe{{Provider: "transit-a", Prefix: "198.51.100.0/24", Prober: "icmp", OK: true}},
	}
}

func TestBuildSystemInjectedFailuresShowOnTheirRows(t *testing.T) {
	failedAt := sysT0.Add(time.Hour)
	facts := SystemFacts{
		Probers: []PluginFact{{Name: "icmp", Type: "icmp"}, {Name: "tcp", Type: "tcp"}},
		Sources: []SourceFact{{PluginFact: PluginFact{Name: "feed", Type: "static"}, Seen: true, Err: "feed unreachable", Since: failedAt}},
		Scorer:  &PluginFact{Name: "scorer", Type: "weighted"},
		Storage: &StorageFact{PluginFact: PluginFact{Name: "db", Type: "sqlite"},
			Last: &syshealth.Outcome{OK: false, Since: failedAt, At: failedAt, Err: "attempt to write a readonly database"}},
		Notifiers: []NotifierFact{
			{PluginFact: PluginFact{Name: "hook", Type: "webhook"}, Last: &syshealth.Outcome{OK: false, Since: failedAt, At: failedAt,
				Err: `webhook: Post "https://hooks.example.net/services/T000/B000/s3cr3t-token?key=abc": dial tcp 192.0.2.9:443: connection refused`}},
			{PluginFact: PluginFact{Name: "mail", Type: "smtp"}},
		},
		RIBSources: []RIBSourceFact{{PluginFact: PluginFact{Name: "bmp", Type: "bmp"},
			Routers: map[string]syshealth.Outcome{"192.0.2.254": {OK: false, Since: failedAt, Err: "monitoring session closed"}}}},
		Telemetry: []TelemetryFact{{PluginFact: PluginFact{Name: "snmp", Type: "snmp"}, Bindings: 2, Err: "transit-a: timeout"}},
	}
	got := BuildSystem(healthySnap("observe"), facts, nil, nil)

	if c := find(t, got, KindProbeSource, "transit-b"); c.State != StateDown || c.Error != "probe source address unavailable" {
		t.Errorf("probe source down row = %+v", c)
	}
	if c := find(t, got, KindProbeSource, "transit-a"); c.State != StateOK {
		t.Errorf("working probe source row = %+v", c)
	}
	if c := find(t, got, KindStorage, "db"); c.State != StateDown || !strings.Contains(c.Error, "readonly") || c.Since == nil || !c.Since.Equal(failedAt) {
		t.Errorf("storage row = %+v", c)
	}
	hook := find(t, got, KindNotifier, "hook")
	if hook.State != StateDown || !strings.Contains(hook.Error, "connection refused") || hook.Since == nil {
		t.Errorf("notifier row = %+v", hook)
	}
	if strings.Contains(hook.Error, "s3cr3t-token") || strings.Contains(hook.Error, "key=abc") || !strings.Contains(hook.Error, "https://hooks.example.net") {
		t.Errorf("notifier error leaks the URL path or query: %q", hook.Error)
	}
	if c := find(t, got, KindNotifier, "mail"); c.State != StateIdle {
		t.Errorf("a notifier that has not fired = %+v, want idle", c)
	}
	if c := find(t, got, KindSource, "feed"); c.State != StateDown || c.Error != "feed unreachable" {
		t.Errorf("source row = %+v", c)
	}
	if c := find(t, got, KindRIBSource, "bmp"); c.State != StateDown || !strings.Contains(c.Error, "192.0.2.254") {
		t.Errorf("rib source row = %+v", c)
	}
	if c := find(t, got, KindTelemetry, "snmp"); c.State != StateDown || c.Error != "transit-a: timeout" {
		t.Errorf("telemetry row = %+v", c)
	}
	if c := find(t, got, KindBGP, "192.0.2.254"); c.State != StateOK || c.Since == nil {
		t.Errorf("bgp row = %+v", c)
	}
	if c := find(t, got, KindVersion, "packeteer"); !strings.Contains(c.Detail, "v0.7.0-test") {
		t.Errorf("version row = %+v", c)
	}
	// Probers: every probe that ran was answered by icmp; tcp was not used.
	if c := find(t, got, KindProber, "icmp"); c.State != StateOK {
		t.Errorf("icmp row = %+v", c)
	}
	if c := find(t, got, KindProber, "tcp"); c.State != StateIdle {
		t.Errorf("tcp row = %+v", c)
	}
	if got.Summary.Total != len(got.Components) || got.Summary.Down < 6 {
		t.Errorf("summary = %+v", got.Summary)
	}
}

func TestBuildSystemProberErrorsComeFromTheirOwnLines(t *testing.T) {
	snap := healthySnap("observe")
	snap.Providers = []Provider{{Name: "transit-a", Up: true}}
	snap.Probes = []Probe{{Provider: "transit-a", Prefix: "198.51.100.0/24", Error: "icmp: no raw socket\ntcp: connection refused"}}
	got := BuildSystem(snap, SystemFacts{Probers: []PluginFact{{Name: "icmp", Type: "icmp"}, {Name: "tcp", Type: "tcp"}}}, nil, nil)
	if c := find(t, got, KindProber, "icmp"); c.State != StateDown || c.Error != "no raw socket" {
		t.Errorf("icmp = %+v", c)
	}
	if c := find(t, got, KindProber, "tcp"); c.State != StateDown || c.Error != "connection refused" {
		t.Errorf("tcp = %+v", c)
	}
	// A dead probe source is the provider's fault, not the prober's.
	snap.Providers[0].Up = false
	snap.Providers[0].Reason = "probe source address unavailable"
	got = BuildSystem(snap, SystemFacts{Probers: []PluginFact{{Name: "icmp", Type: "icmp"}}}, nil, nil)
	if c := find(t, got, KindProber, "icmp"); c.State != StateIdle {
		t.Errorf("prober blamed for a dead probe source: %+v", c)
	}
}

func TestBuildSystemAnnouncerSaysWhetherItMayAnnounce(t *testing.T) {
	ann := &PluginFact{Name: "gobgp", Type: "gobgp"}
	for _, mode := range []string{"observe", "suggest"} {
		for _, a := range []*PluginFact{nil, ann} {
			c := find(t, BuildSystem(healthySnap(mode), SystemFacts{Announcer: a}, nil, nil), KindAnnouncer, map[bool]string{true: "gobgp", false: "announcer"}[a != nil])
			if c.State == StateDown || !strings.Contains(c.Detail, "announces nothing") {
				t.Errorf("%s announcer %v = %+v, want announces nothing", mode, a, c)
			}
		}
	}
	if c := find(t, BuildSystem(healthySnap("inject"), SystemFacts{Announcer: ann}, nil, nil), KindAnnouncer, "gobgp"); c.State != StateOK || strings.Contains(c.Detail, "announces nothing") {
		t.Errorf("inject announcer = %+v", c)
	}
	standby := &plugin.ElectorStatus{ID: "b", Role: plugin.RoleStandby, Holder: "a", Eligible: true}
	if c := find(t, BuildSystem(healthySnap("inject"), SystemFacts{Announcer: ann}, standby, nil), KindAnnouncer, "gobgp"); !strings.Contains(c.Detail, "announces nothing") {
		t.Errorf("standby announcer = %+v", c)
	}
	lost := healthySnap("inject")
	lost.RIBReady = false
	if c := find(t, BuildSystem(lost, SystemFacts{Announcer: ann}, nil, nil), KindAnnouncer, "gobgp"); c.State != StateDegraded {
		t.Errorf("announcer without an iBGP session = %+v", c)
	}
	if c := find(t, BuildSystem(healthySnap("inject"), SystemFacts{}, nil, nil), KindAnnouncer, "announcer"); c.State != StateDown {
		t.Errorf("inject with no announcer = %+v", c)
	}
}

func TestBuildSystemHAFederationAndBGP(t *testing.T) {
	snap := healthySnap("observe")
	snap.Peers = []Peer{{Address: "192.0.2.254", State: "ACTIVE"}}
	ha := &plugin.ElectorStatus{ID: "a", Type: "lease", Role: plugin.RoleStandby, Eligible: true, Since: sysT0}
	fed := &federation.Status{Enabled: true, Peers: []federation.PeerView{
		{Name: "pop-b", Fresh: true, LastSeen: sysT0},
		{Name: "pop-c", Error: `Get "https://pop-c.example.net/fed?token=zzz": EOF`},
	}}
	got := BuildSystem(snap, SystemFacts{}, ha, fed)
	if c := find(t, got, KindBGP, "192.0.2.254"); c.State != StateDown || !strings.Contains(c.Error, "ACTIVE") {
		t.Errorf("bgp = %+v", c)
	}
	if c := find(t, got, KindHA, "a"); c.State != StateDegraded || c.Since == nil {
		t.Errorf("ha standby with no lease holder = %+v", c)
	}
	if c := find(t, got, KindFederation, "pop-b"); c.State != StateOK {
		t.Errorf("fresh peer = %+v", c)
	}
	c := find(t, got, KindFederation, "pop-c")
	if c.State != StateDown || c.Detail != "never seen" || strings.Contains(c.Error, "token=zzz") {
		t.Errorf("silent peer = %+v", c)
	}
	none := BuildSystem(Snapshot{Mode: "observe"}, SystemFacts{}, nil, nil)
	if c := find(t, none, KindBGP, "iBGP"); c.State != StateIdle {
		t.Errorf("no neighbors = %+v", c)
	}
	if c := find(t, none, KindStorage, "storage"); c.State != StateIdle {
		t.Errorf("no storage = %+v", c)
	}
	if c := find(t, none, KindHA, "role"); c.State != StateOK || !strings.Contains(c.Detail, "single instance") {
		t.Errorf("no ha = %+v", c)
	}
}

func TestRedactURLs(t *testing.T) {
	for in, want := range map[string]string{
		`Post "https://user:pw@hooks.example.net/a/b?k=v": refused`: `Post "https://hooks.example.net": refused`,
		"plain error": "plain error",
		"dial tcp 192.0.2.9:443: connection refused":   "dial tcp 192.0.2.9:443: connection refused",
		"see http://192.0.2.1:8080/path#frag and more": "see http://192.0.2.1:8080 and more",
	} {
		if got := redactURLs(in); got != want {
			t.Errorf("redactURLs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSystemAPIIsViewerReadableAndCarriesNoSecrets(t *testing.T) {
	secret := "s3cr3t-token"
	e := newUIWith(t, func(o *Options) {
		o.System = func() SystemFacts {
			return SystemFacts{Notifiers: []NotifierFact{{PluginFact: PluginFact{Name: "hook", Type: "webhook"},
				Last: &syshealth.Outcome{Err: errors.New("Post \"https://hooks.example.net/" + secret + "\": refused").Error(), At: sysT0, Since: sysT0}}}}
		}
	})
	rec, body := e.do(t, "GET", "/api/system", plugin.RoleViewer, nil)
	if rec.Code != 200 {
		t.Fatalf("viewer GET /api/system = %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("payload leaks a secret: %s", rec.Body)
	}
	var sys System
	if err := json.Unmarshal(rec.Body.Bytes(), &sys); err != nil {
		t.Fatal(err)
	}
	if c := find(t, sys, KindNotifier, "hook"); c.State != StateDown {
		t.Errorf("notifier row = %+v", c)
	}
	if body["summary"] == nil || body["components"] == nil {
		t.Errorf("body = %v", body)
	}
	if rec, _ := e.do(t, "POST", "/api/system", plugin.RoleAdmin, "{}"); rec.Code != 405 {
		t.Errorf("POST /api/system = %d, want 405", rec.Code)
	}
	_, ov := e.do(t, "GET", "/api/overview", plugin.RoleViewer, nil)
	sum, _ := ov["system"].(map[string]any)
	if sum == nil || sum["down"].(float64) < 1 {
		t.Errorf("overview system summary = %v", ov["system"])
	}
}
