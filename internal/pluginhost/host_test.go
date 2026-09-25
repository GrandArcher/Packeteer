package pluginhost

import (
	"context"
	"errors"
	"strings"
	"testing"

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
}

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
