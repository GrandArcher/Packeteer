package span

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/source/static"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type nopProber struct{ plugin.Base }

func (nopProber) Probe(context.Context, plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return plugin.ProbeResult{}, nil
}

// TestProbeEngineQueuesProblems checks that problem prefixes reach the probe
// engine's target list next to a static source, urgent on the first read.
func TestProbeEngineQueuesProblems(t *testing.T) {
	sp := mustSource(t, baseYAML)
	start := time.Unix(1_800_000_000, 0)
	replayFixture(t, sp, start)
	pin(sp, start.Add(10*time.Second))
	c, err := plugin.ConfigFromYAML("targets: [{prefix: 198.51.100.0/24, host: 198.51.100.9}]")
	if err != nil {
		t.Fatal(err)
	}
	st, err := static.New(c, quiet())
	if err != nil {
		t.Fatal(err)
	}
	e, err := probe.New(
		[]probe.Provider{{Name: "a", Source: netip.MustParseAddr("192.0.2.11")}},
		[]probe.NamedProber{{Name: "nop", Prober: nopProber{}}},
		[]probe.NamedSource{{Name: "static", Source: st}, {Name: "span", Source: sp}},
		probe.Options{Interval: time.Second, Timeout: time.Second, Packets: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	ts := e.Targets(context.Background())
	got := map[string]plugin.Target{}
	for _, tg := range ts {
		got[tg.Prefix.String()] = tg
	}
	if len(ts) != 3 {
		t.Fatalf("targets = %+v", ts)
	}
	// static listed 198.51.100.0/24 first: its host wins, span marks it urgent.
	if g := got["198.51.100.0/24"]; g.Host.String() != "198.51.100.9" || !g.Urgent {
		t.Fatalf("shared prefix = %+v", g)
	}
	if g := got["203.0.113.0/24"]; g.Host != failV4 || !g.Urgent {
		t.Fatalf("span prefix = %+v", g)
	}
	if g := got["2001:db8:eeee::/48"]; g.Host != inboundV6 || !g.Urgent {
		t.Fatalf("span v6 prefix = %+v", g)
	}
}
