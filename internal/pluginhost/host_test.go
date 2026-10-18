package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var events []string

type rec struct {
	name    string
	failRun bool
}

func (r *rec) Start(context.Context) error {
	if r.failRun {
		return errors.New("nope")
	}
	events = append(events, "start "+r.name)
	return nil
}
func (r *rec) Stop(context.Context) error { events = append(events, "stop "+r.name); return nil }

type recSource struct{ rec }

func (*recSource) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }

type recNotifier struct{ rec }

func (*recNotifier) Notify(context.Context, plugin.Event) error { return nil }

type fakeCfg struct {
	Fail bool `yaml:"fail_start"`
}

func init() {
	plugin.Sources.Register("test-source", func(c plugin.Config, e plugin.Env) (plugin.TargetSource, error) {
		var fc fakeCfg
		if err := c.Decode(&fc); err != nil {
			return nil, err
		}
		return &recSource{rec{name: e.Name, failRun: fc.Fail}}, nil
	})
	plugin.Notifiers.Register("test-notifier", func(c plugin.Config, e plugin.Env) (plugin.Notifier, error) {
		var fc fakeCfg
		if err := c.Decode(&fc); err != nil {
			return nil, err
		}
		return &recNotifier{rec{name: e.Name, failRun: fc.Fail}}, nil
	})
	plugin.Storages.Register("test-sample-storage", func(plugin.Config, plugin.Env) (plugin.Storage, error) {
		return &memSamples{}, nil
	})
	plugin.Storages.Register("test-plain-storage", func(plugin.Config, plugin.Env) (plugin.Storage, error) {
		return &plainStore{}, nil
	})
	plugin.Telemetries.Register("test-sample-telemetry", func(plugin.Config, plugin.Env) (plugin.Telemetry, error) {
		return &telKeep{}, nil
	})
}

// memSamples is a storage plugin that keeps 95th-percentile samples.
type memSamples struct{ plugin.Base }

func (*memSamples) Write(context.Context, plugin.HistoryBatch) error { return nil }
func (*memSamples) Read(context.Context, plugin.HistoryQuery) (plugin.History, error) {
	return plugin.History{}, nil
}
func (*memSamples) PutUsageSamples(context.Context, []plugin.UsageSample) error { return nil }
func (*memSamples) UsageSamples(context.Context, plugin.UsageSampleQuery) ([]plugin.UsageSample, error) {
	return nil, nil
}
func (*memSamples) TrimUsageSamples(context.Context, string, string, string, time.Time, time.Time, time.Time) error {
	return nil
}

// plainStore keeps history and does not keep samples.
type plainStore struct{ plugin.Base }

func (*plainStore) Write(context.Context, plugin.HistoryBatch) error { return nil }
func (*plainStore) Read(context.Context, plugin.HistoryQuery) (plugin.History, error) {
	return plugin.History{}, nil
}

type telKeep struct {
	plugin.Base
	store plugin.SampleStore
}

func (*telKeep) Snapshot(context.Context) ([]plugin.Usage, error) { return nil, nil }
func (t *telKeep) UseSampleStore(s plugin.SampleStore)            { t.store = s }

func load(t *testing.T, extra string) *config.Config {
	t.Helper()
	base := "mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n"
	cfg, err := config.Parse([]byte(base + extra))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestIXPMembersIsNotARIBSource(t *testing.T) {
	cfg := load(t, `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
`)
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.IXPMembers == nil || s.IXPMembers.Type != "ixf" {
		t.Fatalf("%+v", s.IXPMembers)
	}
	if len(s.RIBSources) != 0 || s.Announcer != nil {
		t.Fatalf("rib %d announcer %v", len(s.RIBSources), s.Announcer)
	}
	if !slices.Contains(s.Summary(), "ixp_member ixf") {
		t.Fatalf("summary %v", s.Summary())
	}
	v := s.IXPMembers.Plugin.View()
	if !v.Configured || v.MemberCount != 0 || len(v.Members) != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestIXPFabricDoesNotAnnounce(t *testing.T) {
	cfg := load(t, `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - {name: lan1-v4, vlan_id: 10, address: 192.0.2.8}
  fabric:
    type: icmp
`)
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.IXPFabric == nil || s.IXPFabric.Type != "icmp" {
		t.Fatalf("%+v", s.IXPFabric)
	}
	if s.Announcer != nil || len(s.RIBSources) != 0 {
		t.Fatalf("announcer %v rib %d", s.Announcer, len(s.RIBSources))
	}
	sum := s.Summary()
	for _, want := range []string{"prober icmp", "prober tcp", "ixp_member ixf", "ixp_fabric icmp"} {
		if !slices.Contains(sum, want) {
			t.Fatalf("summary %v missing %s", sum, want)
		}
	}
	view := s.IXPFabric.Plugin.View()
	if !view.Configured || len(view.Samples) != 0 || len(view.Vantages) != 0 {
		t.Fatalf("%+v", view)
	}
	bad := load(t, `
ixp:
  members:
    type: ixf
    config:
      url: https://ixp.example.invalid/members.json
  vantages:
    - {name: lan1-v4, vlan_id: 10, address: 192.0.2.8}
  fabric:
    type: icmp
    config:
      rate_limit_pps: 1
      member_pps: 2
`)
	if _, err := Build(bad, Options{}); err == nil || !strings.Contains(err.Error(), "member_pps") {
		t.Fatalf("member_pps: %v", err)
	}
}

func TestIXPRouteServersDoNotAnnounce(t *testing.T) {
	cfg := load(t, `
ixp:
  routeservers:
    type: birdseye
    config:
      servers:
        - {name: rs1, url: "http://192.0.2.5", asn: 64496}
`)
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.IXPRouteServers == nil || s.IXPRouteServers.Type != "birdseye" {
		t.Fatalf("%+v", s.IXPRouteServers)
	}
	if s.Announcer != nil || len(s.RIBSources) != 0 || s.Inbound != nil || s.Mitigation != nil {
		t.Fatalf("announce path built: %v rib %d", s.Announcer, len(s.RIBSources))
	}
	if !slices.Contains(s.Summary(), "ixp_routeserver birdseye") {
		t.Fatalf("summary %v", s.Summary())
	}
	v := s.IXPRouteServers.Plugin.View()
	if !v.Configured || len(v.Sessions) != 0 || len(v.Servers) != 1 {
		t.Fatalf("%+v", v)
	}
	bad := load(t, `
ixp:
  routeservers:
    type: birdseye
    config:
      servers:
        - {name: rs1, url: "http://192.0.2.5?apikey=x", asn: 64496}
`)
	if _, err := Build(bad, Options{}); err == nil || !strings.Contains(err.Error(), "ixp.routeservers") {
		t.Fatalf("bad url: %v", err)
	}
}

func TestBuildAndLifecycle(t *testing.T) {
	events = nil
	cfg := load(t, "sources:\n  - type: test-source\n    name: s1\nnotifiers:\n  - type: test-notifier\n")
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.Summary(), ";"); got != "source s1;prober icmp;prober tcp;scorer weighted;notifier test-notifier" {
		t.Errorf("Summary = %s", got)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := "start s1,start test-notifier,stop test-notifier,stop s1"
	if got := strings.Join(events, ","); got != want {
		t.Errorf("events = %s, want %s", got, want)
	}
}

func TestStartFailureStopsStarted(t *testing.T) {
	events = nil
	cfg := load(t, "sources:\n  - type: test-source\n    name: s1\nnotifiers:\n  - type: test-notifier\n    config: {fail_start: true}\n")
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start notifier test-notifier: nope") {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(events, ","); got != "start s1,stop s1" {
		t.Errorf("events = %s", got)
	}
}

func TestBuildErrors(t *testing.T) {
	cfg := load(t, `
sources:
  - type: test-source
    config: {bogus: 1}
notifiers:
  - type: nope
scorer:
  type: magic
announcer:
  type: exec
`)
	_, err := Build(cfg, Options{})
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{
		"sources[0] (test-source): config: ",
		`notifiers[0] (nope): unknown notifier type "nope"`,
		`scorer[0] (magic): unknown scorer type "magic"`,
		`announcer[0] (exec): unknown announcer type "exec"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func TestStorageStartsFirstStopsLast(t *testing.T) {
	events = nil
	dir := t.TempDir()
	cfg := load(t, "sources:\n  - type: test-source\n    name: s1\nstorage:\n  type: sqlite\n  config: {path: "+dir+"/p.db}\n")
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(s.Summary(), ";"); !strings.HasPrefix(got, "storage sqlite;source s1") {
		t.Errorf("Summary = %s", got)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Storage.Plugin.Write(context.Background(), plugin.HistoryBatch{}); err != nil {
		t.Fatalf("storage not started: %v", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.Storage.Plugin.Write(context.Background(), plugin.HistoryBatch{}); err == nil {
		t.Fatal("storage still open after Stop")
	}
	bad := load(t, "storage:\n  type: nope\n")
	if _, err := Build(bad, Options{}); err == nil || !strings.Contains(err.Error(), `storage[0] (nope): unknown storage type "nope"`) {
		t.Fatalf("unknown storage: %v", err)
	}
	badCfg := load(t, "storage:\n  type: sqlite\n  config: {path: relative.db}\n")
	if _, err := Build(badCfg, Options{}); err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("bad storage config: %v", err)
	}
}

func TestElectorBuildAndOrder(t *testing.T) {
	dir := t.TempDir()
	nb := "bgp:\n  neighbors:\n    - address: 192.0.2.254\n"
	cfg := load(t, nb+"announcer:\n  type: gobgp\nha:\n  type: lease\n  config: {path: "+dir+"/lease.json, id: pk-a}\n")
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Elector == nil || s.Elector.Type != "lease" || s.Elector.Plugin.Active() {
		t.Fatalf("elector = %+v", s.Elector)
	}
	// The elector starts before, and so stops after, the announcer.
	if got := strings.Join(s.Summary(), ";"); !strings.Contains(got, "elector lease;announcer gobgp") {
		t.Errorf("Summary = %s", got)
	}
	bad := load(t, nb+"ha:\n  type: vrrp\n")
	if _, err := Build(bad, Options{}); err == nil || !strings.Contains(err.Error(), `ha[0] (vrrp): unknown elector type "vrrp" (available: lease)`) {
		t.Fatalf("unknown elector: %v", err)
	}
	badCfg := load(t, nb+"ha:\n  type: lease\n  config: {id: pk-a}\n")
	if _, err := Build(badCfg, Options{}); err == nil || !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("bad elector config: %v", err)
	}
	if _, err := config.Parse([]byte("mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: a\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\nha:\n  type: lease\n")); err == nil || !strings.Contains(err.Error(), "ha requires bgp.neighbors") {
		t.Fatalf("ha without neighbors: %v", err)
	}
}

func TestSSOBuild(t *testing.T) {
	dir := t.TempDir()
	st := "storage:\n  type: sqlite\n  config: {path: " + dir + "/p.db}\n"
	sso := "  sso:\n    type: oidc\n    config: {issuer: 'https://idp.example.net', client_id: packeteer, client_secret_env: OIDC_SECRET, redirect_url: 'https://packeteer.example.net/auth/callback', default_role: viewer}\n"
	env := func(k string) string {
		if k == "OIDC_SECRET" {
			return "s"
		}
		return ""
	}
	s, err := Build(load(t, st+"auth:\n  enabled: true\n"+sso), Options{Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	if s.SSO == nil || s.SSO.Type != "oidc" {
		t.Fatalf("sso = %+v", s.SSO)
	}
	if got := strings.Join(s.Summary(), ";"); !strings.HasPrefix(got, "storage sqlite;sso oidc") {
		t.Errorf("Summary = %s", got)
	}
	if _, err := Build(load(t, st+"auth:\n  enabled: true\n"+sso), Options{}); err == nil || !strings.Contains(err.Error(), "OIDC_SECRET") {
		t.Fatalf("missing secret: %v", err)
	}
	bad := load(t, st+"auth:\n  enabled: true\n  sso:\n    type: saml\n")
	if _, err := Build(bad, Options{}); err == nil || !strings.Contains(err.Error(), `auth.sso[0] (saml): unknown sso type "saml" (available: oidc)`) {
		t.Fatalf("unknown sso: %v", err)
	}
}

func TestDetectorBuild(t *testing.T) {
	src := "sources:\n  - type: flow\n    config: {listen: '127.0.0.1:0'}\n"
	cfg := load(t, src+"anomaly:\n  detector:\n    type: baseline\n    config: {sensitivity: 4}\n")
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Detector == nil || s.Detector.Type != "baseline" {
		t.Fatalf("detector = %+v", s.Detector)
	}
	if got := strings.Join(s.Summary(), ";"); !strings.Contains(got, "source flow;detector baseline") {
		t.Errorf("Summary = %s", got)
	}
	bad := load(t, src+"anomaly:\n  detector:\n    type: nope\n")
	if _, err := Build(bad, Options{}); err == nil || !strings.Contains(err.Error(), `anomaly.detector[0] (nope): unknown detector type "nope" (available: baseline)`) {
		t.Fatalf("unknown detector: %v", err)
	}
	badCfg := load(t, src+"anomaly:\n  detector:\n    type: baseline\n    config: {sensitivity: -1}\n")
	if _, err := Build(badCfg, Options{}); err == nil || !strings.Contains(err.Error(), "sensitivity") {
		t.Fatalf("bad detector config: %v", err)
	}
}

func TestSampleStoreAttached(t *testing.T) {
	s, err := Build(load(t, "storage:\n  type: test-sample-storage\ntelemetry:\n  - type: test-sample-telemetry\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	k := s.Telemetry[0].Plugin.(*telKeep)
	if k.store == nil || k.store != s.Storage.Plugin.(plugin.SampleStore) {
		t.Fatal("sample store was not attached")
	}
	plain, err := Build(load(t, "storage:\n  type: test-plain-storage\ntelemetry:\n  - type: test-sample-telemetry\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Telemetry[0].Plugin.(*telKeep).store != nil {
		t.Fatal("storage without a sample store was attached")
	}
}

type orderLC struct {
	plugin.Base
	name string
	log  *[]string
}

func (o orderLC) Stop(context.Context) error {
	*o.log = append(*o.log, o.name)
	return nil
}

// A plugin an online reload starts is stopped before the elector and the
// announcers, so the announcers still stop first.
func TestTrackStartKeepsAnnouncersStoppingFirst(t *testing.T) {
	var stopped []string
	lc := func(n string) plugin.Lifecycle { return orderLC{name: n, log: &stopped} }
	s := &Set{}
	s.track(namedLifecycle{plugin.KindStorage, "storage", lc("storage")})
	s.track(namedLifecycle{plugin.KindSource, "source old", lc("source old")})
	s.track(namedLifecycle{plugin.KindElector, "elector", lc("elector")})
	s.track(namedLifecycle{plugin.KindAnnouncer, "announcer", lc("announcer")})
	s.TrackStart(plugin.KindSource, "new", lc("source new"))
	s.TrackStart(plugin.KindPolicy, "new", lc("policy new"))
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"announcer", "elector", "policy new", "source new", "source old", "storage"}
	if !slices.Equal(stopped, want) {
		t.Fatalf("stop order = %v, want %v", stopped, want)
	}
}

func TestLeakSourcesBuiltOnlyWhenEnabled(t *testing.T) {
	// rislive refuses to build without the local ASN, so this also shows
	// that the host passes config asn to plugins.
	set, err := Build(load(t, "packeteer_community: \"64512:666\"\nleak_watch:\n  enabled: true\n  sources: [{type: rislive}]\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.LeakSources) != 1 || set.LeakSources[0].Type != "rislive" {
		t.Fatalf("leak sources %+v", set.LeakSources)
	}
	set, err = Build(load(t, "packeteer_community: \"64512:666\"\nleak_watch:\n  enabled: false\n  sources: [{type: nope}]\n"), Options{})
	if err != nil || len(set.LeakSources) != 0 {
		t.Fatalf("a disabled leak_watch built sources: %v %+v", err, set)
	}
	_, err = Build(load(t, "packeteer_community: \"64512:666\"\nleak_watch:\n  enabled: true\n  sources: [{type: nope}]\n"), Options{})
	if err == nil || !strings.Contains(err.Error(), `leak_watch.sources[0] (nope): unknown leak_source type "nope" (available: bmp, rislive)`) {
		t.Fatalf("err %v", err)
	}
}

func TestRPKISourcesBuiltOnlyWhenEnabled(t *testing.T) {
	set, err := Build(load(t, "rpki:\n  enabled: true\n  sources:\n    - type: rtr\n      config: {address: 192.0.2.20:3323}\n"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.RPKISources) != 1 || set.RPKISources[0].Type != "rtr" {
		t.Fatalf("rpki sources %+v", set.RPKISources)
	}
	set, err = Build(load(t, "rpki:\n  enabled: false\n"), Options{})
	if err != nil || len(set.RPKISources) != 0 {
		t.Fatalf("a disabled rpki built sources: %v %+v", err, set)
	}
	_, err = Build(load(t, "rpki:\n  enabled: true\n  sources: [{type: nope}]\n"), Options{})
	if err == nil || !strings.Contains(err.Error(), `rpki.sources[0] (nope): unknown rpki type "nope" (available: rtr)`) {
		t.Fatalf("err %v", err)
	}
}

func TestLookupIsNotARIBSource(t *testing.T) {
	cfg := load(t, `
lookup:
  type: peeringdb
  config:
    exchanges:
      - {name: example-ix, ix_id: 1}
`)
	s, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.Lookup == nil || s.Lookup.Type != "peeringdb" {
		t.Fatalf("%+v", s.Lookup)
	}
	if len(s.RIBSources) != 0 || s.Announcer != nil {
		t.Fatalf("rib %d announcer %v", len(s.RIBSources), s.Announcer)
	}
	if !slices.Contains(s.Summary(), "lookup peeringdb") {
		t.Fatalf("summary %v", s.Summary())
	}
	if v := s.Lookup.Plugin.View(); !v.Configured || v.NetworkCount != 0 || len(v.Memberships) != 0 {
		t.Fatalf("%+v", v)
	}
}

func TestLookupConfigErrorNamesTheBlock(t *testing.T) {
	cfg := load(t, `
lookup:
  type: peeringdb
  config:
    exchanges: []
`)
	if _, err := Build(cfg, Options{}); err == nil || !strings.Contains(err.Error(), "lookup[0] (peeringdb)") || !strings.Contains(err.Error(), "exchanges is required") {
		t.Fatalf("err %v", err)
	}
	cfg = load(t, "lookup:\n  type: nosuch\n")
	if _, err := Build(cfg, Options{}); err == nil || !strings.Contains(err.Error(), `unknown lookup type "nosuch"`) {
		t.Fatalf("err %v", err)
	}
}

const portExchange = `
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
%s    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
telemetry:
  - type: fixed
    config:
      providers:
        - {name: ix-lab, commit_mbps: 1, usage_mbps: 5}
`

func TestTelemetryBindsToAnExchangePort(t *testing.T) {
	with := load(t, fmt.Sprintf(portExchange, "    port: {capacity_mbps: 1000}\n"))
	s, err := Build(with, Options{})
	if err != nil {
		t.Fatalf("a binding named like an exchange with a port block was refused: %v", err)
	}
	if len(s.Telemetry) != 1 {
		t.Fatalf("telemetry = %d", len(s.Telemetry))
	}
	without := load(t, fmt.Sprintf(portExchange, ""))
	if _, err := Build(without, Options{}); err == nil || !strings.Contains(err.Error(), `provider "ix-lab" is not configured`) {
		t.Fatalf("a binding with no port block: err = %v", err)
	}
}

func TestIXPCorrelateDoesNotAnnounce(t *testing.T) {
	const block = `
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
      rounds: 3
`
	s, err := Build(load(t, block), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s.IXPCorrelate == nil || s.IXPCorrelate.Type != "topology" {
		t.Fatalf("%+v", s.IXPCorrelate)
	}
	if s.Announcer != nil || len(s.RIBSources) != 0 || s.Inbound != nil || s.Mitigation != nil {
		t.Fatalf("announce path built: %v rib %d", s.Announcer, len(s.RIBSources))
	}
	sum := s.Summary()
	iFab, iCor := slices.Index(sum, "ixp_fabric icmp"), slices.Index(sum, "ixp_correlate topology")
	if iFab < 0 || iCor < iFab {
		t.Fatalf("the correlator must start after the fabric prober: %v", sum)
	}
	v := s.IXPCorrelate.Plugin.View()
	if !v.Configured || len(v.Groups) != 0 || len(v.Members) != 0 {
		t.Fatalf("%+v", v)
	}
	bad := strings.Replace(block, "rounds: 3", "rounds: 99", 1)
	if _, err := Build(load(t, bad), Options{}); err == nil || !strings.Contains(err.Error(), "ixp.correlate") {
		t.Fatalf("bad rounds: %v", err)
	}
}
