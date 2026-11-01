package agent

import (
	"context"
	"net/netip"
	"testing"
	"time"

	engine "github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type staticTargets struct {
	plugin.Base
	targets []plugin.Target
}

func (s staticTargets) Targets(context.Context) ([]plugin.Target, error) { return s.targets, nil }

// The lab from the issue: a controller and two agents at different sites,
// driven by the real probe engine.
func TestEngineSplitsProvidersAcrossSitesAndStopsUsingADeadAgent(t *testing.T) {
	l := newLab(t, 0, "agent-a", "agent-b")
	l.startAgent("agent-a", "site-a", &fakeProber{rtt: 10 * time.Millisecond}, map[string]string{"carrier-a": "192.0.2.11"})
	stopB := l.startAgent("agent-b", "site-b", &fakeProber{rtt: 30 * time.Millisecond}, map[string]string{"carrier-b": "192.0.2.12"})
	waitFor(t, "both agents online", func() bool {
		l.hub.mu.Lock()
		defer l.hub.mu.Unlock()
		return l.hub.agents["agent-a"].up && l.hub.agents["agent-b"].up
	})

	pfx := netip.MustParsePrefix("198.51.100.0/24")
	e, err := engine.New(
		[]engine.Provider{{Name: "carrier-a", Site: "site-a"}, {Name: "carrier-b", Site: "site-b"}},
		[]engine.NamedProber{{Name: "agents", Prober: l.hub}},
		[]engine.NamedSource{{Name: "static", Source: staticTargets{targets: []plugin.Target{{Prefix: pfx}}}}},
		engine.Options{Interval: time.Second, Timeout: 100 * time.Millisecond, Packets: 3, Workers: 4, PerTargetConcurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	got := map[string]engine.Result{}
	for _, r := range e.Results() {
		got[r.Provider] = r
	}
	a, b := got["carrier-a"], got["carrier-b"]
	if !a.OK() || a.Site != "site-a" || a.Agent != "agent-a" || a.Stats.RTTAvg != 10*time.Millisecond {
		t.Fatalf("carrier-a = %+v", a)
	}
	if !b.OK() || b.Site != "site-b" || b.Agent != "agent-b" || b.Stats.RTTAvg != 30*time.Millisecond {
		t.Fatalf("carrier-b = %+v", b)
	}

	stopB()
	waitFor(t, "carrier-b down", func() bool {
		e.RunOnce(context.Background())
		for _, st := range e.Providers() {
			if st.Name == "carrier-b" {
				return !st.Up
			}
		}
		return false
	})
	for _, st := range e.Providers() {
		if st.Name == "carrier-a" && !st.Up {
			t.Fatal("carrier-a must keep working")
		}
	}
}
