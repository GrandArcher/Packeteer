package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/source/traceroute"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func testJob(provider string, n int) job {
	return job{provider: Provider{Name: provider}, target: plugin.Target{
		Prefix: netip.MustParsePrefix(fmt.Sprintf("203.0.113.%d/28", n*16)),
	}}
}

func TestDispatcherSharesWorkersAcrossProviders(t *testing.T) {
	var jobs []job
	for i := 0; i < 4; i++ {
		jobs = append(jobs, testJob("dead", i), testJob("live", i))
	}
	d := newDispatcher(jobs, nil)
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
	d := newDispatcher([]job{testJob("dead", 1), testJob("dead", 2), testJob("live", 3)}, nil)
	first, _ := d.next() // dead
	second, _ := d.next()
	if first.provider.Name != "dead" || second.provider.Name != "live" {
		t.Fatalf("got %s then %s, want dead then live: the second dead job ranks first but dead is busy",
			first.provider.Name, second.provider.Name)
	}
}

func TestDispatcherLetsLastProviderTakeEveryWorker(t *testing.T) {
	d := newDispatcher([]job{testJob("a", 1), testJob("a", 2), testJob("a", 3)}, nil)
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
	d := newDispatcher([]job{testJob("a", 1), testJob("b", 2), testJob("a", 3), testJob("b", 4)}, nil)
	a1, _ := d.next()
	b2, _ := d.next()
	d.done(b2, true)
	b4, _ := d.next()
	if b4.provider.Name != "b" {
		t.Fatalf("after b finished, next = %s, want b (a still has a job in flight)", b4.provider.Name)
	}
	d.done(a1, true)
	if j, _ := d.next(); j.provider.Name != "a" {
		t.Fatalf("after a finished, next = %s, want a (b still has a job in flight)", j.provider.Name)
	}
}

func TestDispatcherLooksDown(t *testing.T) {
	jobs := []job{testJob("a", 1), testJob("a", 2), testJob("b", 3), testJob("b", 4), testJob("c", 5)}
	d := newDispatcher(jobs, map[string]bool{"a": true, "b": true, "c": false})
	if d.looksDown("a") {
		t.Fatal("a provider with no finished job this round looks down")
	}
	d.done(testJob("a", 1), false)
	d.done(testJob("b", 3), false)
	d.done(testJob("b", 4), true)
	d.done(testJob("c", 5), false)
	if !d.looksDown("a") {
		t.Fatal("a was silent last round and its only finished job got no reply, but a does not look down")
	}
	if d.looksDown("b") {
		t.Fatal("b got a reply this round but looks down")
	}
	if d.looksDown("c") {
		t.Fatal("c got a reply last round but looks down")
	}
	want := map[string]bool{"a": true, "b": false, "c": true}
	if got := d.silentProviders(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("silentProviders = %v, want %v", got, want)
	}
}

// With four workers and a provider whose probes never return, the other
// provider still gets a result for every prefix (#381). With the workers
// handed out in job order, the dead provider's first four probes would
// hold all of them.
func TestDeadProviderDoesNotStarveHealthyProvider(t *testing.T) {
	var targets []plugin.Target
	for i := 0; i < 12; i++ {
		pfx := netip.MustParsePrefix(fmt.Sprintf("203.0.113.%d/28", i*16))
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

// silentProber records the hosts it was asked for, fails the ones in fail,
// and answers only the ones in reply.
type silentProber struct {
	plugin.Base
	mu    sync.Mutex
	asked []netip.Addr
	reply map[netip.Addr]bool
	fail  map[netip.Addr]error
}

func (s *silentProber) Probe(_ context.Context, req plugin.ProbeRequest) (plugin.ProbeResult, error) {
	s.mu.Lock()
	s.asked = append(s.asked, req.Target)
	s.mu.Unlock()
	if err := s.fail[req.Target]; err != nil {
		return plugin.ProbeResult{}, err
	}
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
		down      bool // the provider looks down in this round
		reply     map[netip.Addr]bool
		fail      map[netip.Addr]error
		wantAsked []netip.Addr
		wantLoss  float64 // negative: the result carries an error instead
		wantTrace bool    // an indirect trace is queued for the prefix
	}{
		{"down, all silent: skip the third host, try the gateway", true, nil, nil,
			[]netip.Addr{hosts[0], hosts[1], gw}, 100, false},
		{"down, first host answers: the third host is still probed", true, map[netip.Addr]bool{hosts[0]: true}, nil,
			hosts, 0, false},
		{"down, gateway answers after two silent hosts", true, map[netip.Addr]bool{gw: true}, nil,
			[]netip.Addr{hosts[0], hosts[1], gw}, 0, false},
		{"down, two hosts that error count as silent", true, nil,
			map[netip.Addr]error{hosts[0]: errors.New("send failed"), hosts[1]: errors.New("send failed")},
			[]netip.Addr{hosts[0], hosts[1], gw}, 100, false},
		{"down, source down on the second host: targets stop there", true, nil,
			map[netip.Addr]error{hosts[1]: plugin.ErrSourceUnavailable},
			[]netip.Addr{hosts[0], hosts[1]}, -1, false},
		{"healthy, third host answers: it is probed and scores the prefix", false, map[netip.Addr]bool{hosts[2]: true}, nil,
			hosts, 0, false},
		{"healthy, all silent: every host is probed and a trace queued", false, nil, nil,
			hosts, 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &silentProber{reply: tt.reply, fail: tt.fail}
			prov := Provider{Name: provA.Name, Source: provA.Source, NextHop: gw}
			o := opts()
			o.Indirect = &Indirect{
				Tracer:   traceroute.Tracer{MaxHops: 8, Probes: 2, MinReplies: 2, Port: 33434, Timeout: 50 * time.Millisecond, Hop: (&fakeHopper{}).hop},
				Budget:   time.Second,
				CacheTTL: time.Minute,
			}
			e, err := New([]Provider{prov}, []NamedProber{{"p", p}}, src(plugin.Target{Prefix: pfx1}), o)
			if err != nil {
				t.Fatal(err)
			}
			r, _ := e.probe(context.Background(), job{provider: prov, target: plugin.Target{Prefix: pfx1}, hosts: hosts},
				func(name string) bool { return tt.down && name == prov.Name })
			if fmt.Sprint(p.asked) != fmt.Sprint(tt.wantAsked) {
				t.Errorf("asked %v, want %v", p.asked, tt.wantAsked)
			}
			if fmt.Sprint(r.Targets) != fmt.Sprint(tt.wantAsked) {
				t.Errorf("targets %v, want the hosts probed %v", r.Targets, tt.wantAsked)
			}
			if _, queued := e.indQueued[key{prov.Name, pfx1}]; queued != tt.wantTrace {
				t.Errorf("trace queued = %v, want %v", queued, tt.wantTrace)
			}
			if tt.wantLoss < 0 {
				if r.Err == "" {
					t.Errorf("want an error result: %+v", r)
				}
				return
			}
			if r.Stats.LossPct < tt.wantLoss-0.1 || r.Stats.LossPct > tt.wantLoss+0.1 {
				t.Errorf("loss %.1f, want %.1f: %+v", r.Stats.LossPct, tt.wantLoss, r)
			}
		})
	}
}

// The limit applies only to a provider that got no reply in its last
// round and none yet in this one. With one worker the jobs run in target
// order. No usable gateway: the three hosts are all inside the prefix, so
// a skipped third host would leave the prefix with no reply.
func TestSilentHostLimitOnlyForDownProvider(t *testing.T) {
	inPrefix := func(p netip.Prefix) []netip.Addr {
		hs := ProbeHosts(p, netip.Addr{}, nil, netip.Addr{}, provA.Source)
		if len(hs) != 3 {
			t.Fatalf("test needs three in-prefix hosts: %v", hs)
		}
		return hs
	}
	h1, h2 := inPrefix(pfx1), inPrefix(pfx2)
	newEngine := func(t *testing.T, p *silentProber) *Engine {
		t.Helper()
		o := opts()
		o.Workers = 1
		e, err := New([]Provider{provA}, []NamedProber{{"p", p}},
			src(plugin.Target{Prefix: pfx2}, plugin.Target{Prefix: pfx1}), o)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	// round runs one round and returns the hosts asked in each prefix.
	round := func(e *Engine, p *silentProber, reply map[netip.Addr]bool) map[netip.Prefix][]netip.Addr {
		p.asked, p.reply = nil, reply
		e.RunOnce(context.Background())
		out := map[netip.Prefix][]netip.Addr{}
		for _, a := range p.asked {
			for _, pfx := range []netip.Prefix{pfx1, pfx2} {
				if pfx.Contains(a) {
					out[pfx] = append(out[pfx], a)
				}
			}
		}
		return out
	}
	result := func(e *Engine, pfx netip.Prefix) Result {
		for _, r := range e.Results() {
			if r.Prefix == pfx {
				return r
			}
		}
		return Result{}
	}

	t.Run("healthy provider, earlier prefix silent, third host answers", func(t *testing.T) {
		p := &silentProber{}
		e := newEngine(t, p)
		round(e, p, map[netip.Addr]bool{h2[0]: true})
		for i := 0; i < 2; i++ {
			asked := round(e, p, map[netip.Addr]bool{h1[2]: true})
			if fmt.Sprint(asked[pfx1]) != fmt.Sprint(h1) {
				t.Fatalf("round %d: asked %v in %s, want every host %v", i+2, asked[pfx1], pfx1, h1)
			}
			if r := result(e, pfx1); r.Stats.LossPct != 0 || r.Target != h1[2] {
				t.Fatalf("round %d: third host did not score the prefix: %+v", i+2, r)
			}
		}
	})
	t.Run("down provider", func(t *testing.T) {
		p := &silentProber{}
		e := newEngine(t, p)
		asked := round(e, p, nil)
		if fmt.Sprint(asked[pfx2]) != fmt.Sprint(h2) || fmt.Sprint(asked[pfx1]) != fmt.Sprint(h1) {
			t.Fatalf("first round asked %v, want every host: no earlier round was silent", asked)
		}
		asked = round(e, p, nil)
		if fmt.Sprint(asked[pfx2]) != fmt.Sprint(h2) {
			t.Fatalf("first job asked %v, want every host %v: nothing had finished yet", asked[pfx2], h2)
		}
		if fmt.Sprint(asked[pfx1]) != fmt.Sprint(h1[:2]) {
			t.Fatalf("after a silent round and a silent job, asked %v, want %v", asked[pfx1], h1[:2])
		}
		if r := result(e, pfx1); r.Stats.LossPct != 100 {
			t.Fatalf("skipped job result = %+v", r)
		}
		asked = round(e, p, map[netip.Addr]bool{h2[0]: true})
		if fmt.Sprint(asked[pfx1]) != fmt.Sprint(h1) {
			t.Fatalf("after a reply this round, asked %v, want every host %v", asked[pfx1], h1)
		}
	})
}
