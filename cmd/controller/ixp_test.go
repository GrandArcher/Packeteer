package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const ixpObserveYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
ixp: {}
`

func TestIXPModeBuildsNoRIB(t *testing.T) {
	cfg := mustParse(t, ixpObserveYAML)
	if cfg.IXP == nil || len(cfg.BGP.Neighbors) != 0 {
		t.Fatalf("ixp %v neighbors %d", cfg.IXP, len(cfg.BGP.Neighbors))
	}
	view, err := newRIB(cfg, nil)
	if err != nil || view != nil {
		t.Fatalf("IXP mode with no neighbors built a RIB view: view=%v err=%v", view, err)
	}
}

func TestIXPChangeNeedsRestart(t *testing.T) {
	base := strings.Replace(ixpObserveYAML, "ixp: {}\n", "", 1)
	cur := mustParse(t, base)
	next := mustParse(t, ixpObserveYAML)
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "ixp") || len(online) != 0 {
		t.Fatalf("restart %v online %v, want only ixp", restart, online)
	}
	if _, err := planReload(cur, next, nil); err == nil || !strings.Contains(err.Error(), "restart required: changed ixp") {
		t.Fatalf("planReload: %v", err)
	}
}

func TestRunIXPCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(ixpObserveYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{
		"mode: observe",
		"ixp: on (observe-only, never announces)",
		"announce: disabled",
		"bgp: disabled (no bgp.neighbors)",
		"check: ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}

	bad := strings.Replace(ixpObserveYAML, "mode: observe", "mode: inject", 1) +
		"announcer: {type: gobgp}\npacketeer_community: \"64512:666\"\nlocal_pref: 200\nhold_time: 15m\n" +
		"thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}\nallowlist: {prefixes: [198.51.100.0/24]}\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit %d, want 1; stdout %s stderr %s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"ixp forbids mode inject", "ixp forbids announcer"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("stderr missing %q:\n%s", want, errOut.String())
		}
	}
}

const ixpMembersYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
`

func TestIXPMembersBuildNoRIB(t *testing.T) {
	cfg := mustParse(t, ixpMembersYAML)
	if cfg.IXP == nil || cfg.IXP.Members == nil || len(cfg.BGP.Neighbors) != 0 {
		t.Fatalf("ixp %+v neighbors %d", cfg.IXP, len(cfg.BGP.Neighbors))
	}
	view, err := newRIB(cfg, nil)
	if err != nil || view != nil {
		t.Fatalf("members config built a RIB view: view=%v err=%v", view, err)
	}
}

func TestIXPMembersChangeNeedsRestart(t *testing.T) {
	cur := mustParse(t, ixpObserveYAML)
	next := mustParse(t, ixpMembersYAML)
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "ixp") || len(online) != 0 {
		t.Fatalf("restart %v online %v", restart, online)
	}
}

func TestRunIXPMembersCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(ixpMembersYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{
		"ixp: on (observe-only, never announces)",
		"ixp members: ixf (read-only, never announces)",
		"announce: disabled",
		"check: ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}

	secret := "SuperSecretValue99"
	leaked := strings.Replace(ixpMembersYAML, "https://ixp.example.invalid/members.json",
		"https://ixp.example.invalid/api/v4/member-export/ixf/1.0?apikey="+secret, 1)
	if err := os.WriteFile(path, []byte(leaked), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 1 {
		t.Fatalf("exit %d stdout %s stderr %s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), secret) || strings.Contains(errOut.String(), secret) {
		t.Fatalf("secret leaked stdout %s stderr %s", out.String(), errOut.String())
	}

	// Same vector as internal/plugins/ixpmember/ixf tests. Checksum is independent of the parser.
	const docKey = "ixpm_DocKeyIdent1_DocSecretDocSecretDocSecretDocSe3DqwgX"
	const docSecret = "DocSecretDocSecretDocSecretDocSe"
	keyed := strings.Replace(ixpMembersYAML, "https://ixp.example.invalid/members.json",
		"https://ixp.example.invalid/api/v4/member-export/ixf/1.0", 1)
	keyed += "      key_expires: \"2099-01-01\"\n"
	// 2099 is more than 366 days ahead and must fail closed without the secret.
	if err := os.WriteFile(path, []byte(keyed), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(k string) string {
		if k == "PACKETEER_IXP_MANAGER_API_KEY" {
			return docKey
		}
		return ""
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), []string{"-check", "-config", path}, getenv, &out, &errOut); code != 1 {
		t.Fatalf("far expiry exit %d stdout %s stderr %s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), docSecret) || strings.Contains(out.String()+errOut.String(), docKey) {
		t.Fatalf("key leaked stdout %s stderr %s", out.String(), errOut.String())
	}

	day := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	good := strings.Replace(keyed, "2099-01-01", day, 1)
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), []string{"-check", "-config", path}, getenv, &out, &errOut); code != 0 {
		t.Fatalf("keyed check exit %d stdout %s stderr %s", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), docSecret) || strings.Contains(out.String()+errOut.String(), docKey) {
		t.Fatalf("key leaked on success stdout %s stderr %s", out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "ixp members: ixf (read-only, never announces)") || !strings.Contains(out.String(), "announce: disabled") {
		t.Fatalf("stdout %s", out.String())
	}
}

const ixpFabricYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - name: lan1-v4
      vlan_id: 10
      address: 192.0.2.8
  fabric:
    type: icmp
`

func TestIXPFabricCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(ixpFabricYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{
		"ixp: on (observe-only, never announces)",
		"ixp members: ixf (read-only, never announces)",
		"ixp fabric: icmp (1 vantages, observe-only, never announces)",
		"announce: disabled",
		"check: ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
	cur := mustParse(t, ixpFabricYAML)
	next := mustParse(t, strings.Replace(ixpFabricYAML, "192.0.2.8", "192.0.2.9", 1))
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "ixp") || len(online) != 0 {
		t.Fatalf("restart %v online %v", restart, online)
	}
	if _, err := planReload(cur, next, nil); err == nil || !strings.Contains(err.Error(), "restart required: changed ixp") {
		t.Fatalf("planReload: %v", err)
	}
	got := fabricVantages(cur.IXP.Vantages)
	if len(got) != 1 || got[0].Name != "lan1-v4" || got[0].Address.String() != "192.0.2.8" || got[0].VLANID != 10 {
		t.Fatalf("%+v", got)
	}
}

const ixpRouteServersYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
ixp:
  routeservers:
    type: birdseye
    config:
      servers:
        - {name: rs1, url: "SERVER_URL", asn: 64496}
`

func TestIXPRouteServersCheck(t *testing.T) {
	yaml := strings.Replace(ixpRouteServersYAML, "SERVER_URL", "http://192.0.2.5", 1)
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{
		"ixp routeservers: birdseye (read-only, never announces)",
		"announce: disabled",
		"check: ok",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
	cur := mustParse(t, yaml)
	next := mustParse(t, strings.Replace(yaml, "192.0.2.5", "192.0.2.6", 1))
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "ixp") || len(online) != 0 {
		t.Fatalf("restart %v online %v", restart, online)
	}
}

// TestIXPRouteServersWiring runs the watch against a simulated Birdseye
// and reads it back through the HTTP API: events reach the sink, the view
// and history are served, and the only requests are GETs.
func TestIXPRouteServersWiring(t *testing.T) {
	var mu sync.Mutex
	var reqs []string
	bird := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.Method+" "+r.URL.Path)
		mu.Unlock()
		switch {
		case r.URL.Path == "/api/status":
			_, _ = io.WriteString(w, `{"api":{},"status":{"version":"2.0.8","message":"Daemon is up and running"}}`)
		case r.URL.Path == "/api/protocols/bgp":
			_, _ = io.WriteString(w, `{"api":{},"protocols":{"pb_a":{"bgp_state":"Established","neighbor_address":"192.0.2.10","neighbor_as":64497,"import_limit":10},"pb_b":{"bgp_state":"Idle","neighbor_address":"192.0.2.11","neighbor_as":64498}}}`)
		case strings.HasPrefix(r.URL.Path, "/api/routes/count/protocol/"):
			_, _ = io.WriteString(w, `{"api":{},"count":{"routes":10}}`)
		case r.URL.Path == "/api/routes/lc-zwild/protocol/pb_a/64496/1101":
			_, _ = io.WriteString(w, `{"api":{},"routes":[{"bgp":{"large_communities":[[64496,1101,2]]}}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer bird.Close()

	cfg := mustParse(t, strings.Replace(ixpRouteServersYAML, "SERVER_URL", bird.URL, 1))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{Version: "test", Mode: "observe", Started: true} }})
	if err != nil {
		t.Fatal(err)
	}
	var emu sync.Mutex
	var kinds []string
	wireIXPRouteServers(plugins, srv, func(e plugin.Event) {
		emu.Lock()
		kinds = append(kinds, e.Kind+" "+e.Fields["session"])
		emu.Unlock()
	})
	if err := plugins.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plugins.Stop(t.Context()) }()

	deadline := time.Now().Add(5 * time.Second)
	var body struct {
		Sessions []struct {
			Session  string `json:"session"`
			Accepted int    `json:"accepted"`
			Filtered int    `json:"filtered"`
			MaxPref  int    `json:"max_prefix"`
		} `json:"sessions"`
	}
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/routeservers", nil))
		body.Sessions = nil
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if len(body.Sessions) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(body.Sessions) != 2 || body.Sessions[0].Session != "pb_a" || body.Sessions[0].Filtered != 1 || body.Sessions[0].Accepted != 9 || body.Sessions[0].MaxPref != 10 {
		t.Fatalf("sessions %+v", body.Sessions)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/routeservers/history?server=rs1&session=pb_a", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"filtered":1`) {
		t.Fatalf("history %d %s", rec.Code, rec.Body)
	}
	emu.Lock()
	got := slices.Clone(kinds)
	emu.Unlock()
	slices.Sort(got)
	want := []string{"ixp.rs_max_prefix pb_a", "ixp.rs_session_down pb_b"}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, r := range reqs {
		if !strings.HasPrefix(r, "GET /api/") {
			t.Fatalf("request %q", r)
		}
	}
}

const ixpCorrelateYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - {name: lan1-v4, vlan_id: 10, address: 192.0.2.8}
  fabric: {type: icmp}
  correlate:
    type: topology
    config:
      rounds: 1
`

func TestIXPCorrelateCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(ixpCorrelateYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut strings.Builder
	if code := run(t.Context(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("exit %d stderr %s", code, errOut.String())
	}
	for _, want := range []string{"ixp correlate: topology (reads the fabric probes, never announces)", "announce: disabled", "check: ok"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q:\n%s", want, out.String())
		}
	}
	cur := mustParse(t, ixpCorrelateYAML)
	next := mustParse(t, strings.Replace(ixpCorrelateYAML, "rounds: 1", "rounds: 2", 1))
	restart, online := classify(cur, next)
	if !slices.Contains(restart, "ixp") || len(online) != 0 {
		t.Fatalf("restart %v online %v", restart, online)
	}
}

// fabricRound is a fabric prober that publishes one fixed round.
type fabricRound struct {
	plugin.FabricProbe
	view plugin.FabricView
}

func (f fabricRound) View() plugin.FabricView { return f.view }

// TestIXPCorrelateWiring connects the correlator to the fabric prober's
// view, the event sink, and the HTTP API. The prober is replaced by one
// that publishes a fixed round, so the correlator can only see that round
// through the view wireIXPCorrelate hands it.
func TestIXPCorrelateWiring(t *testing.T) {
	cfg := mustParse(t, ixpCorrelateYAML)
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{Version: "test", Mode: "observe", Started: true} }})
	if err != nil {
		t.Fatal(err)
	}
	sw := []plugin.FabricSwitch{{ID: 1, Name: "sw1", Colo: "colo-a"}}
	var samples []plugin.FabricSample
	for i := range 3 {
		samples = append(samples, plugin.FabricSample{
			Vantage: "lan1-v4", ASN: uint32(64496 + i), Address: "192.0.2." + strconv.Itoa(20+i),
			VLANID: 10, IXPID: 1, Switches: sw, Sent: 5, Received: 0, LossPct: 100, PastTolerance: true,
		})
	}
	plugins.IXPFabric.Plugin = fabricRound{FabricProbe: plugins.IXPFabric.Plugin, view: plugin.FabricView{
		Configured: true, Round: time.Unix(1000, 0).UTC(), Samples: samples,
	}}
	events := make(chan plugin.Event, 8)
	wireIXPFabric(cfg, plugins, srv)
	wireIXPCorrelate(plugins, srv, func(e plugin.Event) { events <- e })

	c := plugins.IXPCorrelate.Plugin
	if err := c.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Stop(t.Context()) }()

	var got []string
	for len(got) < 2 {
		select {
		case e := <-events:
			got = append(got, e.Kind+" "+e.Fields["scope"]+" "+e.Fields["group"])
		case <-time.After(5 * time.Second):
			t.Fatalf("events %v", got)
		}
	}
	slices.Sort(got)
	want := []string{"ixp.fabric_degraded colo colo-a", "ixp.fabric_degraded switch 1"}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/correlation", nil))
	var body struct {
		Configured bool `json:"configured"`
		Groups     []struct {
			Name   string `json:"name"`
			Active bool   `json:"active"`
		} `json:"groups"`
		Members []any `json:"members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Configured || len(body.Groups) != 2 || !body.Groups[0].Active || len(body.Members) != 0 {
		t.Fatalf("%s", rec.Body)
	}
}

// fakeCore is a core prober with a fixed view that records its links.
type fakeCore struct {
	plugin.Base
	links []plugin.CoreLink
	view  plugin.CoreView
}

func (f *fakeCore) SetLinks(l []plugin.CoreLink) { f.links = l }
func (f *fakeCore) View() plugin.CoreView        { return f.view }

const ixpSitesYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
domain: site-a
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
federation:
  type: mtls
ixp:
  core:
    type: icmp
  core_links:
    - {name: a-to-b, peer: site-b, address: 192.0.2.40, source: 192.0.2.30, max_rtt: 40ms}
`

// TestIXPSitesWiring: a site's snapshot to its peers carries its fabric
// round and core links, the sites view puts an incident at the peer that
// reports it, and the shutdown snapshot carries no IXP data.
func TestIXPSitesWiring(t *testing.T) {
	cfg := mustParse(t, ixpSitesYAML)
	ff := &fakeFed{}
	core := &fakeCore{view: plugin.CoreView{Configured: true, Round: time.Unix(1000, 0).UTC(), Links: []plugin.CoreLinkStatus{
		{Name: "a-to-b", Peer: "site-b", Address: "192.0.2.40", Sent: 5, LossPct: 0, RTTMs: 3.2, Up: true},
	}}}
	round := plugin.FabricView{Configured: true, Round: time.Unix(1000, 0).UTC(),
		Vantages: []plugin.FabricVantageStatus{{Name: "lan1-v4", Up: true}},
		Samples:  []plugin.FabricSample{{Vantage: "lan1-v4", ASN: 64496, VLANID: 10, Family: "ipv4", Address: "192.0.2.20", LossPct: 40, RTTMs: 310.5, PastTolerance: true}}}
	set := &pluginhost.Set{
		Federation: &pluginhost.Instance[plugin.Federation]{Name: "mtls", Type: "mtls", Plugin: ff},
		IXPCore:    &pluginhost.Instance[plugin.CoreProbe]{Name: "icmp", Type: "icmp", Plugin: core},
		IXPFabric:  &pluginhost.Instance[plugin.FabricProbe]{Name: "icmp", Type: "icmp", Plugin: fabricRound{view: round}},
	}
	fed := newFedState(cfg, set)
	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{Version: "test", Mode: "observe", Started: true} }})
	if err != nil {
		t.Fatal(err)
	}
	wireIXPSites(cfg, set, fed, srv)

	if len(core.links) != 1 {
		t.Fatalf("links = %+v", core.links)
	}
	l := core.links[0]
	if l.Name != "a-to-b" || l.Peer != "site-b" || l.Address.String() != "192.0.2.40" || l.Source.String() != "192.0.2.30" || l.MaxLossPct != 10 || l.MaxRTT != 40*time.Millisecond {
		t.Fatalf("link = %+v", l)
	}

	now := time.Unix(2000, 0).UTC()
	fed.publish(now, policy.Input{}, nil)
	x := ff.last().IXP
	if x == nil || len(x.Members) != 1 || x.Members[0].ASN != 64496 || !x.Members[0].PastTolerance || len(x.Core) != 1 || x.Core[0].RTTMs != 3.2 {
		t.Fatalf("published ixp = %+v", x)
	}

	ff.set([]plugin.PeerState{{Name: "site-b", Fresh: true, LastSeen: now, Snapshot: plugin.InstanceSnapshot{
		Instance: "site-b", Domain: "site-b", Time: now, IXP: &plugin.FederatedIXP{
			Vantages: []plugin.FabricVantageStatus{{Name: "lan1-v4", Up: true}},
			Groups:   []plugin.CorrelationGroup{{Scope: plugin.ScopeSwitch, Name: "sw2", Members: 4, Degraded: 3, Active: true}},
			Members:  []plugin.FabricPath{}, Core: []plugin.CoreLinkStatus{},
		}}}})
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/sites", nil))
	var body struct {
		Enabled bool `json:"enabled"`
		Sites   []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"sites"`
		Links []struct {
			Site string `json:"site"`
			Peer string `json:"peer"`
		} `json:"links"`
		Incidents []struct {
			Site   string `json:"site"`
			Scope  string `json:"scope"`
			Detail string `json:"detail"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.Enabled || len(body.Sites) != 2 || body.Sites[0].Name != "site-a" || body.Sites[0].Status != "ok" || body.Sites[1].Status != "degraded" {
		t.Fatalf("sites = %s", rec.Body)
	}
	if len(body.Links) != 1 || body.Links[0].Site != "site-a" || body.Links[0].Peer != "site-b" {
		t.Fatalf("links = %s", rec.Body)
	}
	if len(body.Incidents) != 1 || body.Incidents[0].Site != "site-b" || body.Incidents[0].Detail != "switch sw2: 3 of 4 members degraded" {
		t.Fatalf("incidents = %s", rec.Body)
	}

	fed.publishDown(now)
	if ff.last().IXP != nil {
		t.Fatalf("shutdown snapshot carries ixp data: %+v", ff.last().IXP)
	}
}

func TestIXPSitesNotWiredOutsideIXPModeOrWithoutFederation(t *testing.T) {
	plain := mustParse(t, ixpSitesYAML[:strings.Index(ixpSitesYAML, "ixp:")])
	ff := &fakeFed{}
	set := &pluginhost.Set{Federation: &pluginhost.Instance[plugin.Federation]{Plugin: ff}}
	fed := newFedState(plain, set)
	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{Mode: "observe", Started: true} }})
	if err != nil {
		t.Fatal(err)
	}
	wireIXPSites(plain, set, fed, srv)
	fed.publish(time.Unix(2000, 0).UTC(), policy.Input{}, nil)
	if ff.last().IXP != nil {
		t.Fatalf("an edge instance published ixp data: %+v", ff.last().IXP)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/ixp/sites", nil))
	if !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("view = %s", rec.Body)
	}

	ixp := mustParse(t, ixpSitesYAML)
	wireIXPSites(ixp, &pluginhost.Set{}, nil, srv)
}
