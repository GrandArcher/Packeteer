package probe

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func testJob(provider string, n int) job {
	return job{provider: Provider{Name: provider}, target: plugin.Target{
		Prefix: netip.MustParsePrefix(fmt.Sprintf("198.51.%d.0/24", n)),
	}}
}

func TestDispatcherSharesWorkersAcrossProviders(t *testing.T) {
	var jobs []job
	for i := 0; i < 4; i++ {
		jobs = append(jobs, testJob("dead", i), testJob("live", i))
	}
	d := newDispatcher(jobs)
	// Four workers take a job each and none returns, as when the dead
	// provider's probes hang.
	var got []string
	for i := 0; i < 4; i++ {
		j, ok := d.next()
		if !ok {
			t.Fatalf("job %d: queue empty", i)
		}
		got = append(got, j.provider.Name)
	}
	counts := map[string]int{}
	for _, n := range got {
		counts[n]++
	}
	if counts["dead"] != 2 || counts["live"] != 2 {
		t.Fatalf("four workers split %v, want two each", got)
	}
	if got[0] != "dead" || got[1] != "live" {
		t.Fatalf("a tie must go to the job that ranks first: %v", got)
	}
}

func TestDispatcherPrefersFreeProviderOverRank(t *testing.T) {
	d := newDispatcher([]job{testJob("dead", 1), testJob("dead", 2), testJob("live", 3)})
	first, _ := d.next() // dead
	second, _ := d.next()
	if first.provider.Name != "dead" || second.provider.Name != "live" {
		t.Fatalf("got %s then %s, want dead then live: the second dead job ranks first but dead is busy",
			first.provider.Name, second.provider.Name)
	}
}

func TestDispatcherLetsLastProviderTakeEveryWorker(t *testing.T) {
	d := newDispatcher([]job{testJob("a", 1), testJob("a", 2), testJob("a", 3)})
	for i := 0; i < 3; i++ {
		if _, ok := d.next(); !ok {
			t.Fatalf("worker %d got no job while one provider had work left", i)
		}
	}
	if _, ok := d.next(); ok {
		t.Fatal("queue should be empty")
	}
}

func TestDispatcherDoneFreesTheShare(t *testing.T) {
	d := newDispatcher([]job{testJob("a", 1), testJob("b", 2), testJob("a", 3), testJob("b", 4)})
	a1, _ := d.next()
	b2, _ := d.next()
	d.done(b2)
	j, _ := d.next()
	if j.provider.Name != "b" {
		t.Fatalf("after b finished, next = %s, want b (a still has a job in flight)", j.provider.Name)
	}
	d.done(a1)
}

// With four workers and a provider whose probes never return, the other
// provider still gets a result for every prefix (#381). With the workers
// handed out in job order, the dead provider's first four probes would
// hold all of them.
func TestDeadProviderDoesNotStarveHealthyProvider(t *testing.T) {
	var targets []plugin.Target
	for i := 0; i < 12; i++ {
		pfx := netip.MustParsePrefix(fmt.Sprintf("198.51.%d.0/24", i))
		targets = append(targets, plugin.Target{Prefix: pfx, Host: pfx.Addr().Next()})
	}
	p := &fakeProber{fn: func(ctx context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
		if req.Provider != provB.Name {
			return plugin.ProbeResult{Sent: req.Count, RTTs: ms(5)}, nil
		}
		<-ctx.Done()
		return plugin.ProbeResult{}, ctx.Err()
	}}
	o := opts()
	o.Workers = 4
	o.RoundTimeout = 300 * time.Millisecond
	e, err := New([]Provider{provB, provA}, []NamedProber{{"p", p}}, src(targets...), o)
	if err != nil {
		t.Fatal(err)
	}
	e.RunOnce(context.Background())
	live := 0
	for _, r := range e.Results() {
		switch r.Provider {
		case provA.Name:
			live++
			if !r.OK() {
				t.Errorf("healthy result not ok: %+v", r)
			}
		case provB.Name:
			t.Errorf("dead provider stored a result: %+v", r)
		}
	}
	if live != len(targets) {
		t.Fatalf("healthy provider stored %d of %d prefixes", live, len(targets))
	}
}

// silentProber records the hosts it was asked for and answers only the
// ones in reply.
type silentProber struct {
	plugin.Base
	mu    sync.Mutex
	asked []netip.Addr
	reply map[netip.Addr]bool
}

func (s *silentProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	s.mu.Lock()
	s.asked = append(s.asked, req.Target)
	s.mu.Unlock()
	if s.reply[req.Target] {
		return plugin.ProbeResult{Sent: req.Count, RTTs: ms(7, 7, 7)}, nil
	}
	return plugin.ProbeResult{Sent: req.Count}, nil
}

func TestJobStopsAfterSilentHosts(t *testing.T) {
	gw := netip.MustParseAddr("192.0.2.21")
	hosts := ProbeHosts(pfx1, netip.Addr{}, nil, gw, provA.Source)
	if len(hosts) != 4 || hosts[3] != gw {
		t.Fatalf("test needs three in-prefix hosts and the gateway: %v", hosts)
	}
	tests := []struct {
		name      string
		reply     map[netip.Addr]bool
		wantAsked []netip.Addr
		wantLoss  float64
	}{
		{"all silent: skip the third host, try the gateway", nil,
			[]netip.Addr{hosts[0], hosts[1], gw}, 100},
		{"first host answers: the third host is still probed", map[netip.Addr]bool{hosts[0]: true},
			hosts, 0},
		{"gateway answers after two silent hosts", map[netip.Addr]bool{gw: true},
			[]netip.Addr{hosts[0], hosts[1], gw}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &silentProber{reply: tt.reply}
			e, err := New([]Provider{{Name: provA.Name, Source: provA.Source, NextHop: gw}},
				[]NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), opts())
			if err != nil {
				t.Fatal(err)
			}
			e.RunOnce(context.Background())
			if fmt.Sprint(p.asked) != fmt.Sprint(tt.wantAsked) {
				t.Errorf("asked %v, want %v", p.asked, tt.wantAsked)
			}
			r := e.Results()[0]
			if fmt.Sprint(r.Targets) != fmt.Sprint(tt.wantAsked) {
				t.Errorf("targets %v, want the hosts probed %v", r.Targets, tt.wantAsked)
			}
			if r.Stats.LossPct < tt.wantLoss-0.1 || r.Stats.LossPct > tt.wantLoss+0.1 {
				t.Errorf("loss %.1f, want %.1f: %+v", r.Stats.LossPct, tt.wantLoss, r)
			}
		})
	}
}
