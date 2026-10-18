package icmp

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

type fakeSender struct {
	fn   func(plugin.ProbeRequest) (plugin.ProbeResult, error)
	reqs []plugin.ProbeRequest
}

func (f *fakeSender) Start(context.Context) error { return nil }
func (f *fakeSender) Stop(context.Context) error  { return nil }
func (f *fakeSender) Probe(_ context.Context, r plugin.ProbeRequest) (plugin.ProbeResult, error) {
	f.reqs = append(f.reqs, r)
	return f.fn(r)
}

func newProber(t *testing.T, cfg string, fn func(plugin.ProbeRequest) (plugin.ProbeResult, error)) (*Prober, *fakeSender) {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
		t.Fatal(err)
	}
	c, err := New(plugin.NewConfig(&node), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	p := c.(*Prober)
	f := &fakeSender{fn: fn}
	p.sender = f
	p.now = func() time.Time { return t0 }
	return p, f
}

func replies(n int, rtt time.Duration) func(plugin.ProbeRequest) (plugin.ProbeResult, error) {
	return func(r plugin.ProbeRequest) (plugin.ProbeResult, error) {
		res := plugin.ProbeResult{Sent: r.Count}
		for i := 0; i < n; i++ {
			res.RTTs = append(res.RTTs, rtt)
		}
		return res, nil
	}
}

func link(name, peer, addr string, loss float64, rtt time.Duration) plugin.CoreLink {
	return plugin.CoreLink{Name: name, Peer: peer, Source: netip.MustParseAddr("192.0.2.30"),
		Address: netip.MustParseAddr(addr), MaxLossPct: loss, MaxRTT: rtt}
}

func TestConfigBounds(t *testing.T) {
	for cfg, want := range map[string]string{
		"interval: 1s":   "interval",
		"interval: 2h":   "interval",
		"timeout: 1ms":   "timeout",
		"timeout: 1h":    "timeout",
		"packets: 99":    "packets",
		"packets: -1":    "packets",
		"unknown_key: 1": "unknown_key",
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(cfg), &node); err != nil {
			t.Fatal(err)
		}
		_, err := New(plugin.NewConfig(&node), plugin.Env{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", cfg, err, want)
		}
	}
	if _, err := New(plugin.NewConfig(nil), plugin.Env{}); err != nil {
		t.Fatalf("defaults: %v", err)
	}
}

func TestRoundMeasuresEachLink(t *testing.T) {
	p, f := newProber(t, "packets: 4", replies(4, 12*time.Millisecond))
	p.SetLinks([]plugin.CoreLink{link("a-to-b", "site-b", "192.0.2.40", 10, 50*time.Millisecond)})
	p.round(context.Background())
	v := p.View()
	if !v.Configured || !v.Round.Equal(t0) || len(v.Links) != 1 {
		t.Fatalf("view = %+v", v)
	}
	l := v.Links[0]
	if l.Name != "a-to-b" || l.Peer != "site-b" || l.Address != "192.0.2.40" || l.Sent != 4 || l.LossPct != 0 || l.RTTMs != 12 || !l.Up || l.Degraded {
		t.Fatalf("link = %+v", l)
	}
	r := f.reqs[0]
	if r.Target.String() != "192.0.2.40" || r.Source.String() != "192.0.2.30" || r.Count != 4 || r.Provider != "a-to-b" {
		t.Fatalf("request = %+v", r)
	}
}

func TestDegradedByLossRTTAndSilence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		replies  int
		rtt      time.Duration
		degraded bool
		up       bool
	}{
		{"healthy", 5, 10 * time.Millisecond, false, true},
		{"loss over limit", 4, 10 * time.Millisecond, true, true}, // 20% > 10%
		{"rtt over limit", 5, 80 * time.Millisecond, true, true},
		{"no reply", 0, 0, true, false},
	} {
		p, _ := newProber(t, "packets: 5", replies(tc.replies, tc.rtt))
		p.SetLinks([]plugin.CoreLink{link("l", "site-b", "192.0.2.40", 10, 50*time.Millisecond)})
		p.round(context.Background())
		l := p.View().Links[0]
		if l.Degraded != tc.degraded || l.Up != tc.up {
			t.Errorf("%s: degraded=%v up=%v, link = %+v", tc.name, l.Degraded, l.Up, l)
		}
	}
}

func TestNoRTTLimitMeansLossOnly(t *testing.T) {
	p, _ := newProber(t, "", replies(5, 900*time.Millisecond))
	p.SetLinks([]plugin.CoreLink{link("l", "site-b", "192.0.2.40", 10, 0)})
	p.round(context.Background())
	if l := p.View().Links[0]; l.Degraded {
		t.Fatalf("max_rtt unset must not degrade on RTT: %+v", l)
	}
}

func TestProbeErrorIsDegradedAndNotAMeasurement(t *testing.T) {
	p, _ := newProber(t, "", func(plugin.ProbeRequest) (plugin.ProbeResult, error) {
		return plugin.ProbeResult{}, errors.New("source address unavailable")
	})
	p.SetLinks([]plugin.CoreLink{link("l", "site-b", "192.0.2.40", 10, 0)})
	p.round(context.Background())
	l := p.View().Links[0]
	if !l.Degraded || l.Up || l.Error != "source address unavailable" || l.RTTMs != 0 || l.LossPct != 0 {
		t.Fatalf("link = %+v", l)
	}
}

func TestCancelledRoundKeepsPreviousView(t *testing.T) {
	p, _ := newProber(t, "", replies(5, time.Millisecond))
	p.SetLinks([]plugin.CoreLink{link("l", "site-b", "192.0.2.40", 10, 0)})
	p.round(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.SetLinks(nil)
	p.round(ctx)
	if v := p.View(); len(v.Links) != 1 {
		t.Fatalf("view after cancelled round = %+v", v)
	}
}

func TestStartStop(t *testing.T) {
	p, _ := newProber(t, "", replies(5, time.Millisecond))
	p.SetLinks([]plugin.CoreLink{link("l", "site-b", "192.0.2.40", 10, 0)})
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(p.View().Links) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(p.View().Links) != 1 {
		t.Fatal("first round did not run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}
