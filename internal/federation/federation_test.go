package federation

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Documentation prefixes only.
var (
	pfx   = netip.MustParsePrefix("198.51.100.0/24")
	other = netip.MustParsePrefix("203.0.113.0/24")
	t0    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
)

// popA has x-a and y-a locally and sees x-b in pop-b over a 10ms backbone.
func popA() Config {
	return Config{
		Instance: "pop-a", Domain: "pop-a",
		InterDCRTT: map[string]time.Duration{"pop-b": 10 * time.Millisecond},
		Remote:     map[string]string{"x-b": "pop-b"},
		Local:      []string{"x-a", "y-a"},
		GlobalCommits: []GlobalCommit{{
			Name: "carrier-x", CommitMbps: 100, Providers: []string{"x-a", "x-b"},
		}},
	}
}

func res(provider string, p netip.Prefix, rtt time.Duration, loss float64, at time.Time) probe.Result {
	recv := 10 - int(loss/10)
	return probe.Result{Provider: provider, Prefix: p, Time: at,
		Stats: probe.Stats{Sent: 10, Received: recv, LossPct: loss, RTTMin: rtt, RTTAvg: rtt, RTTMax: rtt}}
}

// peerB is a fresh pop-b snapshot: x-b up, its traffic for pfx leaves via
// x-b, and it measured 20ms through x-b.
func peerB(at time.Time) plugin.PeerState {
	return plugin.PeerState{
		Name: "pop-b", URL: "https://192.0.2.20:9443/v1/snapshot", Fresh: true, LastSeen: at,
		Snapshot: plugin.InstanceSnapshot{
			Instance: "pop-b", Domain: "pop-b", Mode: "inject", Time: at, RIBReady: true, MaxImprovements: 50,
			Providers: []plugin.FederatedProvider{
				{Name: "x-b", Domain: "pop-b", Up: true, Usage: &plugin.Usage{Provider: "x-b", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 60}},
				// A peer never reports another domain's provider as its own.
				{Name: "x-a", Domain: "pop-a", Up: true},
			},
			Paths: []plugin.FederatedPath{
				{Prefix: pfx, Provider: "x-b", Sent: 10, RTT: 20 * time.Millisecond, Time: at},
				{Prefix: other, Provider: "x-b", Sent: 10, RTT: 20 * time.Millisecond, Time: at},
			},
			Routes: []plugin.FederatedRoute{{Prefix: pfx, Native: "x-b", Exit: "x-b"}},
		},
	}
}

func baseInput(at time.Time) policy.Input {
	return policy.Input{
		Results: []probe.Result{
			res("x-a", pfx, 80*time.Millisecond, 0, at),
			res("y-a", pfx, 80*time.Millisecond, 0, at),
		},
		ProviderUp: map[string]bool{"x-a": true, "y-a": true},
		RIBEnabled: true, RIBReady: true,
		Native: map[netip.Prefix]string{pfx: "x-a"},
	}
}

func TestMergeAddsInterDCRTT(t *testing.T) {
	in := baseInput(t0)
	Merge(&in, popA(), []plugin.PeerState{peerB(t0)})
	if !in.ProviderUp["x-b"] {
		t.Fatal("x-b not up with a fresh peer")
	}
	var got *probe.Result
	for i, r := range in.Results {
		if r.Provider == "x-b" {
			if r.Prefix != pfx {
				t.Fatalf("merged a path for %s, which this POP does not probe", r.Prefix)
			}
			got = &in.Results[i]
		}
	}
	if got == nil {
		t.Fatalf("no x-b path merged: %+v", in.Results)
	}
	if got.Stats.RTTAvg != 30*time.Millisecond || got.Stats.Sent != 10 || got.Stats.Received != 10 {
		t.Fatalf("x-b path = %+v, want 20ms + 10ms inter-DC", got.Stats)
	}
	if got.Prober != "federation:pop-b" {
		t.Errorf("prober = %q", got.Prober)
	}
	if in.NoRoute[pfx]["x-b"] {
		t.Error("x-b marked no-route although pop-b exits there")
	}
}

func TestMergeStalePeerIsStandalone(t *testing.T) {
	cases := map[string]func(*plugin.PeerState){
		"stale":            func(p *plugin.PeerState) { p.Fresh = false },
		"rib not ready":    func(p *plugin.PeerState) { p.Snapshot.RIBReady = false },
		"provider down":    func(p *plugin.PeerState) { p.Snapshot.Providers[0].Up = false },
		"own domain":       func(p *plugin.PeerState) { p.Snapshot.Domain = "pop-a" },
		"provider missing": func(p *plugin.PeerState) { p.Snapshot.Providers = p.Snapshot.Providers[1:] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			peer := peerB(t0)
			mutate(&peer)
			in := baseInput(t0)
			Merge(&in, popA(), []plugin.PeerState{peer})
			if in.ProviderUp["x-b"] {
				t.Fatal("x-b up")
			}
		})
	}
	in := baseInput(t0)
	Merge(&in, popA(), nil)
	if in.ProviderUp["x-b"] || !in.NoRoute[pfx]["x-b"] || len(in.Results) != 2 {
		t.Fatalf("no peers: up=%v noroute=%v results=%d", in.ProviderUp["x-b"], in.NoRoute[pfx], len(in.Results))
	}
}

func TestMergeRequiresPeerExit(t *testing.T) {
	// pop-b does not route pfx at all: steering there could loop.
	peer := peerB(t0)
	peer.Snapshot.Routes = nil
	in := baseInput(t0)
	Merge(&in, popA(), []plugin.PeerState{peer})
	if !in.NoRoute[pfx]["x-b"] {
		t.Fatal("x-b usable for a prefix pop-b has no route for")
	}
	// pop-b exits via a third domain's provider: not a destination.
	peer.Snapshot.Routes = []plugin.FederatedRoute{{Prefix: pfx, Native: "x-b", Exit: "z-c"}}
	in = baseInput(t0)
	Merge(&in, popA(), []plugin.PeerState{peer})
	if !in.NoRoute[pfx]["x-b"] {
		t.Fatal("x-b usable although pop-b's traffic leaves through z-c")
	}
}

func TestMergeTieBreak(t *testing.T) {
	// Both POPs steered pfx at each other in one interval: pop-b's
	// snapshot shows its exit is x-a (ours), native x-b.
	peer := peerB(t0)
	peer.Snapshot.Routes = []plugin.FederatedRoute{{Prefix: pfx, Native: "x-b", Exit: "x-a"}}
	in := baseInput(t0)
	Merge(&in, popA(), []plugin.PeerState{peer})
	if in.NoRoute[pfx]["x-b"] {
		t.Fatal("pop-a sorts first and must keep its steer")
	}
	// The same from pop-b's side: pop-a steered to x-b, native x-a.
	cfgB := Config{Instance: "pop-b", Domain: "pop-b",
		InterDCRTT: map[string]time.Duration{"pop-a": 10 * time.Millisecond},
		Remote:     map[string]string{"x-a": "pop-a"}, Local: []string{"x-b"}}
	peerA := plugin.PeerState{Name: "pop-a", Fresh: true, Snapshot: plugin.InstanceSnapshot{
		Instance: "pop-a", Domain: "pop-a", RIBReady: true,
		Providers: []plugin.FederatedProvider{{Name: "x-a", Domain: "pop-a", Up: true}},
		Routes:    []plugin.FederatedRoute{{Prefix: pfx, Native: "x-a", Exit: "x-b"}},
	}}
	inB := policy.Input{Results: []probe.Result{res("x-b", pfx, 20*time.Millisecond, 0, t0)},
		ProviderUp: map[string]bool{"x-b": true}, RIBEnabled: true, RIBReady: true,
		Native: map[netip.Prefix]string{pfx: "x-b"}}
	Merge(&inB, cfgB, []plugin.PeerState{peerA})
	if !inB.NoRoute[pfx]["x-a"] {
		t.Fatal("pop-b sorts second and must retire its steer to x-a")
	}
}

// TestDecideThroughRemotePOP runs Merge into the real decision engine:
// the remote path wins on RTT (with the inter-DC RTT added), then the
// peer goes stale and the improvement is retired: no stale intent.
func TestDecideThroughRemotePOP(t *testing.T) {
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	e := policy.NewEngine(policy.Config{
		Mode: "inject", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
		HoldTime: time.Minute, MaxImprovements: 50, MaxResultAge: 10 * time.Second,
		Allowlist: []netip.Prefix{pfx},
	}, scorer)
	in := baseInput(t0)
	Merge(&in, popA(), []plugin.PeerState{peerB(t0)})
	e.Evaluate(in, t0)
	imps := e.Improvements()
	if len(imps) != 1 || imps[0].Provider != "x-b" || imps[0].Native != "x-a" {
		t.Fatalf("improvements = %+v, want pfx via x-b", imps)
	}

	// The remote path is within the threshold once the inter-DC RTT is
	// large: 20ms + 55ms is not 15ms better than 80ms.
	cfg := popA()
	cfg.InterDCRTT["pop-b"] = 55 * time.Millisecond
	e2 := policy.NewEngine(policy.Config{Mode: "inject", MinRTTDelta: 15 * time.Millisecond, MaxImprovements: 50, Allowlist: []netip.Prefix{pfx}}, scorer)
	in2 := baseInput(t0)
	Merge(&in2, cfg, []plugin.PeerState{peerB(t0)})
	e2.Evaluate(in2, t0)
	if n := len(e2.Improvements()); n != 0 {
		t.Fatalf("inter-DC RTT not counted: %+v", e2.Improvements())
	}

	// The peer goes stale inside the hold time: the steer is retired.
	at := t0.Add(5 * time.Second)
	stale := peerB(t0)
	stale.Fresh = false
	in = baseInput(at)
	Merge(&in, popA(), []plugin.PeerState{stale})
	e.Evaluate(in, at)
	if imps := e.Improvements(); len(imps) != 0 {
		t.Fatalf("improvement onto a stale peer's provider kept: %+v", imps)
	}
}

func TestApplyGlobalCommit(t *testing.T) {
	local := []plugin.Usage{
		{Provider: "x-a", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 60},
		{Provider: "y-a", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 10},
	}
	out, st := ApplyGlobalCommit(local, popA(), []plugin.PeerState{peerB(t0)})
	if len(st) != 1 || !st[0].Complete || !st[0].Over || st[0].TotalMbps != 120 {
		t.Fatalf("status = %+v", st)
	}
	by := map[string]plugin.Usage{}
	for _, u := range out {
		by[u.Provider] = u
	}
	if by["x-a"].CommitMbps != 40 {
		t.Errorf("x-a effective commit = %v, want 100 - 60", by["x-a"].CommitMbps)
	}
	if by["y-a"].CommitMbps != 100 {
		t.Errorf("y-a (not a member) commit changed: %v", by["y-a"].CommitMbps)
	}
	if u, ok := by["x-b"]; !ok || u.UsageMbps != 60 {
		t.Errorf("peer usage row for x-b missing: %+v", out)
	}
	if local[0].CommitMbps != 100 {
		t.Error("ApplyGlobalCommit changed the caller's usage")
	}

	// The peer is stale: incomplete, own commits stand (standalone).
	stale := peerB(t0)
	stale.Fresh = false
	out, st = ApplyGlobalCommit(local, popA(), []plugin.PeerState{stale})
	if st[0].Complete || st[0].Over {
		t.Fatalf("stale peer: %+v", st[0])
	}
	for _, u := range out {
		if u.Provider == "x-a" && u.CommitMbps != 100 {
			t.Fatalf("x-a commit %v with an incomplete global commit", u.CommitMbps)
		}
		if u.Provider == "x-b" {
			t.Fatal("stale peer's usage used")
		}
	}

	// An exhausted global commit stays billable, never zero.
	peer := peerB(t0)
	peer.Snapshot.Providers[0].Usage.UsageMbps = 150
	out, _ = ApplyGlobalCommit(local, popA(), []plugin.PeerState{peer})
	for _, u := range out {
		if u.Provider == "x-a" && (u.CommitMbps <= 0 || u.CommitMbps > 0.01) {
			t.Fatalf("exhausted x-a commit = %v", u.CommitMbps)
		}
	}
	// The own commit caps the effective commit.
	peer.Snapshot.Providers[0].Usage.UsageMbps = 0
	small := []plugin.Usage{{Provider: "x-a", CommitMbps: 30, Samples: 1, Single: true, UsageMbps: 10}}
	out, _ = ApplyGlobalCommit(small, popA(), []plugin.PeerState{peer})
	if out[0].CommitMbps != 30 {
		t.Fatalf("x-a commit %v above its own 30", out[0].CommitMbps)
	}
}

func TestSnapshotOwnDataOnly(t *testing.T) {
	in := baseInput(t0)
	Merge(&in, popA(), []plugin.PeerState{peerB(t0)})
	in.Results = append(in.Results, res("x-a", other, 10*time.Millisecond, 0, t0.Add(-time.Hour)))
	imps := []policy.Improvement{{Prefix: pfx, Provider: "y-a", Native: "x-a", Since: t0}}
	usage := []plugin.Usage{{Provider: "x-a", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 60}}
	for _, mode := range []string{"observe", "inject"} {
		s := Snapshot(popA(), SnapshotInput{Mode: mode, Now: t0, RIBReady: true, MaxImprovements: 50,
			MaxResultAge: time.Minute, Input: in, Improvements: imps, Usage: usage})
		for _, p := range s.Paths {
			if p.Provider == "x-b" {
				t.Fatal("published a peer's merged path as our own")
			}
			if p.Prefix == other {
				t.Fatal("published a stale measurement")
			}
		}
		if len(s.Paths) != 2 || len(s.Providers) != 2 || s.Providers[0].Usage == nil || s.Providers[0].Usage.UsageMbps != 60 {
			t.Fatalf("%s snapshot = %+v", mode, s)
		}
		// Only in inject does the improvement change the exit.
		want := "x-a"
		if mode == "inject" {
			want = "y-a"
		}
		var exits []plugin.FederatedRoute
		for _, r := range s.Routes {
			if r.Prefix == pfx {
				exits = append(exits, r)
			}
		}
		if len(exits) != 1 || exits[0].Exit != want || exits[0].Native != "x-a" {
			t.Fatalf("%s routes = %+v, want exit %s", mode, s.Routes, want)
		}
	}
	// RIB not ready: no routes, so no peer steers here.
	s := Snapshot(popA(), SnapshotInput{Mode: "inject", Now: t0, Input: in})
	if len(s.Routes) != 0 || s.RIBReady {
		t.Fatalf("routes published without a ready RIB: %+v", s.Routes)
	}
}

func TestShiftSnapshotClockSkew(t *testing.T) {
	// The peer's clock is an hour ahead. A path it measured 4s before it
	// served the snapshot is 4s old here, not an hour in the future.
	peerNow := t0.Add(time.Hour)
	s := plugin.InstanceSnapshot{Time: peerNow, Paths: []plugin.FederatedPath{{Prefix: pfx, Time: peerNow.Add(-4 * time.Second)}}}
	got := plugin.ShiftSnapshot(s, t0)
	if got.Paths[0].Time != t0.Add(-4*time.Second) || got.Time != t0 {
		t.Fatalf("shifted = %v (snapshot %v)", got.Paths[0].Time, got.Time)
	}
}

func TestView(t *testing.T) {
	local := Snapshot(popA(), SnapshotInput{Mode: "observe", Now: t0})
	_, commits := ApplyGlobalCommit(nil, popA(), nil)
	st := View(popA(), &local, []plugin.PeerState{peerB(t0), {Name: "pop-c", URL: "https://192.0.2.30:9443/v1/snapshot", Error: "refused"}}, commits)
	if !st.Enabled || st.Instance != "pop-a" || len(st.Peers) != 2 || len(st.GlobalCommit) != 1 {
		t.Fatalf("view = %+v", st)
	}
	if st.Peers[0].InterDCRTTMs != 10 || st.Peers[0].Snapshot == nil {
		t.Fatalf("pop-b view = %+v", st.Peers[0])
	}
	if st.Peers[1].Snapshot != nil || st.Peers[1].Fresh || st.Peers[1].Error != "refused" {
		t.Fatalf("never-seen peer view = %+v", st.Peers[1])
	}
}
