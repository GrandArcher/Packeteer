package pluginhost

import (
	"context"
	"errors"
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
