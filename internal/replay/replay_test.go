package replay

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	sqlitestore "github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	pA = netip.MustParsePrefix("198.51.100.0/24")
	pB = netip.MustParsePrefix("203.0.113.0/24")
	pC = netip.MustParsePrefix("192.0.2.0/24")
	t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
)

func scorer(t testing.TB) plugin.Scorer {
	t.Helper()
	s, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cfg() policy.Config {
	return policy.Config{Mode: "observe", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond,
		HoldTime: 2 * time.Minute, MaxImprovements: 50, MaxResultAge: 2 * time.Minute}
}

// meas is one provider's loss (%) and RTT (ms) toward a prefix.
type meas struct {
	prov      string
	loss, rtt float64
}

func results(at time.Time, p netip.Prefix, ms ...meas) []probe.Result {
	var out []probe.Result
	for _, x := range ms {
		out = append(out, probe.Result{Provider: x.prov, Prefix: p, Time: at, Round: at,
			Stats: probe.Stats{Sent: 10, Received: 10 - int(x.loss/10), LossPct: x.loss,
				RTTAvg: time.Duration(x.rtt * float64(time.Millisecond))}})
	}
	return out
}

// round is a decision input at the round time. pA is lossy on its native
// provider a in rounds 0-9 and from 20, and lossy on b in rounds 14-19, so
// it is moved to b, flips back, and is moved again. pB is 20 ms slower on a
// than on b all the time, pC is fine.
func round(i int) policy.Input {
	at := t0.Add(time.Duration(i) * 30 * time.Second)
	aLoss, bLoss := 0.0, 0.0
	if i < 10 || i >= 20 {
		aLoss = 20
	}
	if i >= 14 && i < 20 {
		bLoss = 20
	}
	var res []probe.Result
	res = append(res, results(at, pA, meas{"a", aLoss, 40}, meas{"b", bLoss, 45})...)
	res = append(res, results(at, pB, meas{"a", 0, 80}, meas{"b", 0, 60})...)
	res = append(res, results(at, pC, meas{"a", 0, 30}, meas{"b", 0, 30})...)
	return policy.Input{Results: res, ProviderUp: map[string]bool{"a": true, "b": true}, RIBEnabled: true, RIBReady: true,
		Native:     map[netip.Prefix]string{pA: "a", pB: "a", pC: "a"},
		VolumeMbps: map[netip.Prefix]float64{pA: 100, pB: 20}}
}

func openStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	c, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "r.db") + "\nround_retention: 720h")
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlitestore.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	s.SetClock(func() time.Time { return t0.Add(time.Hour) })
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	return s
}

// record decides n rounds on a live engine, stores each round's input like
// the recorder does, and returns the changes the live engine made.
func record(t *testing.T, s plugin.RoundStore, c policy.Config, n int) []policy.Change {
	t.Helper()
	e := policy.NewEngine(c, scorer(t))
	var live []policy.Change
	var recs []plugin.RoundRecord
	for i := 0; i < n; i++ {
		now, in := t0.Add(time.Duration(i)*30*time.Second), round(i)
		live = append(live, e.Evaluate(in, now)...)
		data, err := Encode(now, in)
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, plugin.RoundRecord{At: now, Input: data})
	}
	if err := s.PutRounds(context.Background(), recs); err != nil {
		t.Fatal(err)
	}
	return live
}

func TestEncodeDecodeKeepsTheDecision(t *testing.T) {
	c := cfg()
	in := round(0)
	in.Held = func(p netip.Prefix) bool { return p == pA }
	in.Synthesize = map[netip.Prefix]netip.Prefix{netip.MustParsePrefix("198.51.100.0/25"): pA}
	in.Usage = []plugin.Usage{{Provider: "a", CommitMbps: 50, OutMbps: 70}}
	in.Policies = map[netip.Prefix]plugin.PolicyVerdict{pC: {Action: plugin.PolicyIgnore, Rule: "lab"}}
	data, err := Encode(t0, in)
	if err != nil {
		t.Fatal(err)
	}
	at, got, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !at.Equal(t0) {
		t.Fatalf("time = %s", at)
	}
	if got.Synthesize != nil {
		t.Fatal("synthesized sub-ranges were stored")
	}
	if !got.Held(pA) || got.Held(pB) {
		t.Fatal("held prefixes lost")
	}
	in.Synthesize = nil
	_, want := policy.Decide(policy.NewState(), in, c, scorer(t), t0)
	_, have := policy.Decide(policy.NewState(), got, c, scorer(t), t0)
	if !reflect.DeepEqual(want.Decisions, have.Decisions) || !reflect.DeepEqual(want.Changes, have.Changes) {
		t.Fatalf("decoded input decides differently:\nwant %+v\nhave %+v", want.Changes, have.Changes)
	}
	if _, _, err := Decode([]byte("not gzip")); err == nil {
		t.Fatal("garbage decoded")
	}
}

// The same config over the stored rounds makes the decisions the live
// engine made, in order (acceptance: a recorded run is reproduced).
func TestSameConfigReproducesTheLiveDecisions(t *testing.T) {
	s := openStore(t)
	live := record(t, s, cfg(), 24)
	if len(live) == 0 {
		t.Fatal("the scenario made no decision")
	}
	res, err := Run(context.Background(), s, t0.Add(-time.Hour), t0.Add(time.Hour), []Side{{Name: "running", Cfg: cfg(), Scorer: scorer(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rounds != 24 || !res.From.Equal(t0) || !res.To.Equal(t0.Add(23*30*time.Second)) {
		t.Fatalf("window = %d rounds %s..%s", res.Rounds, res.From, res.To)
	}
	var want, have []string
	for _, c := range live {
		p, to := c.New.Prefix, c.New.Provider
		if c.Action == policy.ActionRetire {
			p, to = c.Old.Prefix, ""
		}
		want = append(want, c.Action+" "+p.String()+" "+to)
	}
	for _, m := range res.Sides[0].Moves {
		have = append(have, m.Action+" "+m.Prefix.String()+" "+m.To)
	}
	if !reflect.DeepEqual(want, have) {
		t.Fatalf("replay differs from the live run:\nlive   %v\nreplay %v", want, have)
	}
	if len(res.Diff) != 0 {
		t.Fatalf("one side has a diff: %+v", res.Diff)
	}
}

// Observe-mode history is enough, and a stricter threshold shows up as a
// diff against the running config.
func TestChangedThresholdsProduceADiff(t *testing.T) {
	s := openStore(t)
	record(t, s, cfg(), 24)
	strict := cfg()
	strict.MinRTTDelta = 30 * time.Millisecond
	res, err := Run(context.Background(), s, t0, t0.Add(time.Hour), []Side{
		{Name: "running", Cfg: cfg(), Scorer: scorer(t)},
		{Name: "candidate", Cfg: strict, Scorer: scorer(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	base, next := res.Sides[0].Summary, res.Sides[1].Summary
	if base.Prefixes != 2 || next.Prefixes != 1 {
		t.Fatalf("steered prefixes base=%d candidate=%d, want 2 and 1 (pB gains 20 ms)", base.Prefixes, next.Prefixes)
	}
	if len(res.Diff) != 1 || res.Diff[0].Prefix != pB || !reflect.DeepEqual(res.Diff[0].Base, []string{"b"}) || len(res.Diff[0].New) != 0 {
		t.Fatalf("diff = %+v", res.Diff)
	}
}

func TestSummaryWeightsByVolumeAndCountsCommitAndCap(t *testing.T) {
	s := openStore(t)
	record(t, s, cfg(), 12)
	capped := cfg()
	capped.MaxImprovements = 1
	res, err := Run(context.Background(), s, t0, t0.Add(time.Hour), []Side{
		{Name: "running", Cfg: cfg(), Scorer: scorer(t)},
		{Name: "cap1", Cfg: capped, Scorer: scorer(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := res.Sides[0].Summary
	// pA (100 Mbps) gains 20 points of loss and pB (20 Mbps) 20 ms of RTT,
	// so the weighted means are 100*20/120 and (100*-5+20*20)/120.
	if !b.Weighted || b.UnknownVolume != 0 || b.MovedMbps != 120 {
		t.Fatalf("summary = %+v", b)
	}
	if got, want := b.LossDeltaPct, 100.0*20/120; got < want-0.01 || got > want+0.01 {
		t.Fatalf("loss delta = %v, want %v", got, want)
	}
	if got, want := b.RTTDeltaMs, (100.0*-5+20*20)/120; got < want-0.01 || got > want+0.01 {
		t.Fatalf("rtt delta = %v, want %v", got, want)
	}
	if b.CappedRounds != 0 || b.PeakActive != 2 {
		t.Fatalf("uncapped side: %+v", b)
	}
	c := res.Sides[1].Summary
	if c.PeakActive != 1 || c.CappedRounds == 0 || c.CappedPrefixes != 1 || c.MaxImprovements != 1 {
		t.Fatalf("cap pressure not reported: %+v", c)
	}
}

func TestFlapsAndRetires(t *testing.T) {
	s := openStore(t)
	record(t, s, cfg(), 24)
	res, err := Run(context.Background(), s, t0, t0.Add(time.Hour), []Side{{Name: "running", Cfg: cfg(), Scorer: scorer(t)}})
	if err != nil {
		t.Fatal(err)
	}
	sum := res.Sides[0].Summary
	if sum.Improves != 3 || sum.Retires != 1 || sum.Flaps != 1 || sum.Active != 2 {
		t.Fatalf("summary = %+v", sum)
	}
	var seq []string
	for _, m := range res.Sides[0].Moves {
		if m.Prefix == pA {
			seq = append(seq, m.Action)
		}
	}
	if !reflect.DeepEqual(seq, []string{"improve", "retire", "improve"}) {
		t.Fatalf("pA moves = %v", seq)
	}
}

func TestRunErrors(t *testing.T) {
	s := openStore(t)
	sides := []Side{{Name: "running", Cfg: cfg(), Scorer: scorer(t)}}
	if _, err := Run(context.Background(), s, t0, t0.Add(time.Hour), sides); !errors.Is(err, ErrNoRounds) {
		t.Fatalf("empty window: %v", err)
	}
	if _, err := Run(context.Background(), s, t0, t0.Add(time.Hour), nil); err == nil {
		t.Fatal("no sides accepted")
	}
	if err := s.PutRounds(context.Background(), []plugin.RoundRecord{{At: t0, Input: []byte("junk")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), s, t0, t0.Add(time.Hour), sides); err == nil || !strings.Contains(err.Error(), "2026-10-01T12:00:00Z") {
		t.Fatalf("damaged round: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, s, t0, t0.Add(time.Hour), sides); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

// More rounds than one page are all replayed.
func TestRunPages(t *testing.T) {
	s := openStore(t)
	record(t, s, cfg(), 2*pageSize+7)
	res, err := Run(context.Background(), s, t0, t0.Add(48*time.Hour), []Side{{Name: "running", Cfg: cfg(), Scorer: scorer(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rounds != 2*pageSize+7 {
		t.Fatalf("replayed %d rounds", res.Rounds)
	}
}

func TestMovesAreBounded(t *testing.T) {
	tr := newTracker(Side{Name: "x", Cfg: cfg(), Scorer: scorer(t)})
	for i := 0; i < MaxListed+5; i++ {
		tr.add(Move{Action: policy.ActionImprove})
	}
	r := tr.report()
	if len(r.Moves) != MaxListed || r.MovesOmitted != 5 {
		t.Fatalf("listed %d, omitted %d", len(r.Moves), r.MovesOmitted)
	}
}

func TestFormat(t *testing.T) {
	s := openStore(t)
	record(t, s, cfg(), 24)
	strict := cfg()
	strict.MinRTTDelta = 30 * time.Millisecond
	res, err := Run(context.Background(), s, t0, t0.Add(time.Hour), []Side{
		{Name: "running", Cfg: cfg(), Scorer: scorer(t)},
		{Name: "candidate", Cfg: strict, Scorer: scorer(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	Format(&b, res)
	out := b.String()
	for _, want := range []string{"24 rounds", "running", "candidate", "203.0.113.0/24", "base: b", "new: (no move)", "nothing was announced"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// The size the docs give for round_retention: about 60 KB for 1000
// prefixes measured through three providers.
func TestEncodedRoundSize(t *testing.T) {
	in := policy.Input{ProviderUp: map[string]bool{"a": true, "b": true, "c": true}, Native: map[netip.Prefix]string{}, RIBEnabled: true, RIBReady: true}
	for i := 0; i < 1000; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24)
		in.Native[p] = "a"
		for j, prov := range []string{"a", "b", "c"} {
			in.Results = append(in.Results, probe.Result{Provider: prov, Prefix: p, Target: netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), Prober: "icmp",
				Time: t0.Add(time.Duration(i*j) * time.Millisecond), Round: t0,
				Stats: probe.Stats{Sent: 10, Received: 10, LossPct: float64(i % 7), RTTMin: 20*time.Millisecond + time.Duration(i*1234),
					RTTAvg: 25*time.Millisecond + time.Duration(i*4321+j*777), RTTMax: 40 * time.Millisecond, Jitter: 2*time.Millisecond + time.Duration(i*91)}})
		}
	}
	data, err := Encode(t0, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 60<<10 {
		t.Fatalf("a round of 1000 prefixes and 3 providers is %d bytes; docs/CONFIG.md says about 60 KB", len(data))
	}
}

func TestParseWindow(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	f, to, err := ParseWindow("", "", now)
	if err != nil || !to.Equal(now) || !f.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("defaults: %v %v %v", f, to, err)
	}
	f, to, err = ParseWindow("6h", "1h", now)
	if err != nil || !f.Equal(now.Add(-6*time.Hour)) || !to.Equal(now.Add(-time.Hour)) {
		t.Fatalf("durations: %v %v %v", f, to, err)
	}
	f, to, err = ParseWindow("2026-10-01T00:00:00Z", "2026-10-01T06:00:00Z", now)
	if err != nil || !f.Equal(t0.Add(-12*time.Hour)) || !to.Equal(t0.Add(-6*time.Hour)) {
		t.Fatalf("times: %v %v %v", f, to, err)
	}
	for _, bad := range [][2]string{{"yesterday", ""}, {"-1h", ""}, {"", "soon"}, {"1h", "2h"}, {"2026-10-03T00:00:00Z", ""}} {
		if _, _, err := ParseWindow(bad[0], bad[1], now); err == nil {
			t.Errorf("ParseWindow(%q, %q) accepted", bad[0], bad[1])
		}
	}
}
