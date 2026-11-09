package probe_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/prober/fixed"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// countingLimit records how many packets waited on the global limiter.
type countingLimit struct{ total int }

func (c *countingLimit) WaitN(ctx context.Context, n int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.total += n
	return nil
}

type listSource struct {
	plugin.Base
	targets []plugin.Target
}

func (s *listSource) Targets(context.Context) ([]plugin.Target, error) {
	return s.targets, nil
}

func fixedProber(t *testing.T, yaml string) plugin.Prober {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := fixed.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func qualEngine(t *testing.T, o probe.Options, prober plugin.Prober, targets ...plugin.Target) *probe.Engine {
	t.Helper()
	if o.Interval == 0 {
		o.Interval = time.Second
	}
	if o.Timeout == 0 {
		o.Timeout = 100 * time.Millisecond
	}
	if o.Packets == 0 {
		o.Packets = 3
	}
	e, err := probe.New(
		[]probe.Provider{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), NextHop: netip.MustParseAddr("192.0.2.21")}},
		[]probe.NamedProber{{Name: "fixed", Prober: prober}},
		[]probe.NamedSource{{Name: "static", Source: &listSource{targets: targets}}},
		o,
	)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func oneResult(t *testing.T, e *probe.Engine) probe.Result {
	t.Helper()
	e.RunOnce(context.Background())
	rs := e.Results()
	if len(rs) != 1 {
		t.Fatalf("results = %+v", rs)
	}
	return rs[0]
}

// A consistent host, enough replies and a tight spread, defines the score.
func TestFixedConsistentHostScores(t *testing.T) {
	lim := &countingLimit{}
	p := fixedProber(t, `
paths:
  - provider: transit-a
    target: 198.51.100.9
    sent: 3
    rtts_ms: [15, 15, 16]
`)
	o := probe.Options{
		Packets: 3, MinReplies: 2, Dispersion: 20 * time.Millisecond,
		RetryPackets: 9, Limiter: lim,
	}
	host := netip.MustParseAddr("198.51.100.9")
	e := qualEngine(t, o, p, plugin.Target{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: host})
	r := oneResult(t, e)
	if !r.OK() || r.Target != host || r.Stats.LossPct != 0 || r.Stats.Received != 3 ||
		r.Stats.RTTMin != 15*time.Millisecond || r.Stats.RTTMax != 16*time.Millisecond || r.Stats.Sent != 3 {
		t.Fatalf("score = %+v", r)
	}
	if len(r.Targets) != 1 || r.Targets[0] != host {
		t.Fatalf("pin was not the only target: %v", r.Targets)
	}
	// Spread is inside the limit, so the full probe does not run.
	if lim.total != 3 {
		t.Fatalf("limiter tokens = %d, want 3", lim.total)
	}
}

// A noisy host is left out when another host inside the prefix qualifies.
// The noisy sample still escalates, and every packet waits on the limiter.
func TestFixedNoisyHostExcludedWhenAnotherQualifies(t *testing.T) {
	lim := &countingLimit{}
	p := fixedProber(t, `
paths:
  - provider: transit-a
    loss_pct: 100
  - provider: transit-a
    target: 198.51.100.50
    sent: 3
    rtts_ms: [5, 80, 5]
  - provider: transit-a
    target: 198.51.100.1
    sent: 3
    rtts_ms: [20, 21, 20]
`)
	o := probe.Options{
		Packets: 3, MinReplies: 2, Dispersion: 20 * time.Millisecond,
		RetryPackets: 9, Limiter: lim,
	}
	busy := netip.MustParseAddr("198.51.100.50")
	e := qualEngine(t, o, p, plugin.Target{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: busy, Candidate: true,
	})
	r := oneResult(t, e)
	if !r.OK() || r.Target.String() != "198.51.100.1" || r.Stats.LossPct != 0 || r.Stats.Received != 3 ||
		r.Stats.RTTMin != 20*time.Millisecond || r.Stats.RTTMax != 21*time.Millisecond {
		t.Fatalf("score = %+v", r)
	}
	// Four addresses on the fast probe, then the consistent host and the
	// noisy host again on the full probe. Silent addresses are not retried.
	if lim.total != 4*3+2*9 {
		t.Fatalf("limiter tokens = %d, want %d", lim.total, 4*3+2*9)
	}
}

// A prefix whose only sample is inconsistent is stored from the retry.
func TestFixedNoisyOnlyEscalatesToRetry(t *testing.T) {
	lim := &countingLimit{}
	p := fixedProber(t, `
paths:
  - provider: transit-a
    count: 2
    sent: 2
    rtts_ms: [5, 50]
  - provider: transit-a
    count: 6
    sent: 6
    rtts_ms: [10, 10, 10, 10, 10, 10]
`)
	o := probe.Options{
		Packets: 2, MinReplies: 2, Dispersion: 20 * time.Millisecond,
		RetryPackets: 6, Limiter: lim,
	}
	host := netip.MustParseAddr("198.51.100.9")
	e := qualEngine(t, o, p, plugin.Target{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: host})
	r := oneResult(t, e)
	if !r.OK() || r.Target != host || r.Stats.Sent != 6 || r.Stats.Received != 6 || r.Stats.LossPct != 0 ||
		r.Stats.RTTMin != 10*time.Millisecond || r.Stats.RTTMax != 10*time.Millisecond {
		t.Fatalf("retry sample = %+v", r)
	}
	if lim.total != 2+6 {
		t.Fatalf("limiter tokens = %d, want 8", lim.total)
	}
}

// Too few replies drop out of the score and do not escalate. Dispersion
// is what starts the full probe.
func TestFixedShortSampleDoesNotEscalate(t *testing.T) {
	lim := &countingLimit{}
	p := fixedProber(t, `
paths:
  - provider: transit-a
    target: 198.51.100.9
    sent: 4
    rtts_ms: [10]
  - provider: transit-a
    target: 198.51.100.1
    sent: 4
    rtts_ms: [12, 12, 12, 12]
`)
	o := probe.Options{
		Packets: 4, MinReplies: 3, Dispersion: 20 * time.Millisecond,
		RetryPackets: 12, Limiter: lim,
	}
	// Not a pin: .9 is a candidate and .1 is the automatic first host.
	e := qualEngine(t, o, p, plugin.Target{
		Prefix: netip.MustParsePrefix("198.51.100.0/24"),
		Host:   netip.MustParseAddr("198.51.100.9"), Candidate: true,
	})
	r := oneResult(t, e)
	if !r.OK() || r.Target.String() != "198.51.100.1" || r.Stats.Received != 4 || r.Stats.RTTAvg != 12*time.Millisecond {
		t.Fatalf("short sample was not dropped: %+v", r)
	}
	// .9 has one reply, under min_replies, and no spread to judge.
	// No retry. The other automatic hosts error (no path) after waiting.
	if lim.total != 4*4 {
		t.Fatalf("limiter tokens = %d, want %d", lim.total, 4*4)
	}
}
