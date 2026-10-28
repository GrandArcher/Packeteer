package history

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// roundStore is a memStore that also keeps decision rounds.
type roundStore struct {
	*memStore
	retention time.Duration
	rounds    []plugin.RoundRecord
	failPut   error
}

func (s *roundStore) RoundRetention() time.Duration { return s.retention }

func (s *roundStore) PutRounds(_ context.Context, rs []plugin.RoundRecord) error {
	if s.failPut != nil {
		return s.failPut
	}
	s.rounds = append(s.rounds, rs...)
	return nil
}

func (s *roundStore) Rounds(context.Context, time.Time, time.Time, int) ([]plugin.RoundRecord, error) {
	return s.rounds, nil
}

func roundInput() policy.Input {
	return policy.Input{
		Results:    []probe.Result{{Provider: "a", Prefix: pfxA, Time: time.Now(), Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 10 * time.Millisecond}}},
		ProviderUp: map[string]bool{"a": true}, RIBEnabled: true, RIBReady: true,
		Native: map[netip.Prefix]string{pfxA: "a"},
	}
}

func TestRoundsAreKeptOnlyWhenTheStoreKeepsThem(t *testing.T) {
	ctx := context.Background()
	off := &roundStore{memStore: &memStore{}}
	r := New(Options{Store: off})
	r.Round(time.Now(), roundInput(), false)
	if r.keepsRounds() || len(r.rounds) != 0 {
		t.Fatal("a store with round retention 0 queued a round")
	}
	plain := New(Options{Store: &memStore{}})
	plain.Round(time.Now(), roundInput(), false)
	if plain.keepsRounds() || len(plain.rounds) != 0 {
		t.Fatal("a store without rounds queued one")
	}

	on := &roundStore{memStore: &memStore{}, retention: time.Hour}
	r = New(Options{Store: on})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	r.Round(now, roundInput(), false)
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(on.rounds) != 1 || !on.rounds[0].At.Equal(now) {
		t.Fatalf("stored rounds = %+v", on.rounds)
	}
	at, in, err := replay.Decode(on.rounds[0].Input)
	if err != nil || !at.Equal(now) || len(in.Results) != 1 {
		t.Fatalf("stored round: %v %v %+v", at, err, in)
	}
}

// RIB changes trigger evaluations between probe rounds. Those are kept at
// most once per RoundEvery, unless they changed something; a new probe
// round is always kept.
func TestRoundsAreSpacedByRoundEvery(t *testing.T) {
	st := &roundStore{memStore: &memStore{}, retention: time.Hour}
	r := New(Options{Store: st, RoundEvery: 15 * time.Second})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	sec := func(n int) time.Duration { return time.Duration(n) * time.Second }
	for _, c := range []struct {
		at, probeRound time.Duration
		changed        bool
		kept           bool
	}{
		{sec(0), sec(0), false, true},
		{sec(1), sec(0), false, false},
		{sec(5), sec(0), false, false},
		{sec(6), sec(0), true, true},
		{sec(7), sec(0), false, false},
		{sec(8), sec(8), false, true},
		{sec(24), sec(8), false, true},
		{sec(25), sec(25), false, true},
	} {
		in := roundInput()
		in.Results[0].Round = now.Add(c.probeRound)
		before := len(r.rounds)
		r.Round(now.Add(c.at), in, c.changed)
		if kept := len(r.rounds) > before; kept != c.kept {
			t.Errorf("round at +%s (probe round +%s, changed %v): kept %v, want %v", c.at, c.probeRound, c.changed, kept, c.kept)
		}
	}
}

// The recorder keeps what a replay needs to make the live decisions: with
// confirm_rounds 3 and a prefix probed early every 7s, a time-only gap of
// RoundEvery would drop probe rounds and confirm the move later.
func TestRecordedRoundsReplayTheLiveDecisions(t *testing.T) {
	ctx := context.Background()
	c, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "h.db") + "\nround_retention: 24h")
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer st.Stop(ctx)
	sc, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := policy.Config{Mode: "observe", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: time.Minute,
		MaxImprovements: 50, MaxResultAge: 2 * time.Minute, ConfirmRounds: 3}
	eng := policy.NewEngine(cfg, sc)
	rec := New(Options{Store: st, RoundEvery: 15 * time.Second})

	start := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Minute)
	var live []string
	evals, probeRounds := 0, 0
	for i := 0; i < 60; i++ {
		now := start.Add(time.Duration(i) * 3500 * time.Millisecond)
		in := roundInput()
		// A probe round ends every other evaluation; the ones between are
		// RIB-change evaluations on the same results.
		pr := start.Add(time.Duration(i/2) * 7 * time.Second)
		if i%2 == 0 {
			probeRounds++
		}
		in.Results = []probe.Result{
			{Provider: "a", Prefix: pfxA, Time: pr, Round: pr, Stats: probe.Stats{Sent: 10, Received: 7, LossPct: 30, RTTAvg: 40 * time.Millisecond}},
			{Provider: "b", Prefix: pfxA, Time: pr, Round: pr, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 40 * time.Millisecond}},
		}
		in.ProviderUp = map[string]bool{"a": true, "b": true}
		changes := eng.Evaluate(in, now)
		for _, ch := range changes {
			live = append(live, ch.Action+" "+ch.New.Prefix.String()+" "+ch.New.Provider+" "+now.Format(time.RFC3339Nano))
		}
		rec.Round(now, in, len(changes) > 0)
		evals++
	}
	if len(live) == 0 {
		t.Fatal("the scenario made no decision")
	}
	if err := rec.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	stored, err := st.Rounds(ctx, start.Add(-time.Minute), start.Add(time.Hour), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != probeRounds || len(stored) >= evals {
		t.Fatalf("stored %d rounds of %d evaluations and %d probe rounds, want one per probe round", len(stored), evals, probeRounds)
	}
	res, err := replay.Run(ctx, st, start.Add(-time.Minute), start.Add(time.Hour), []replay.Side{{Name: "running", Cfg: cfg, Scorer: sc}})
	if err != nil {
		t.Fatal(err)
	}
	var have []string
	for _, m := range res.Sides[0].Moves {
		have = append(have, m.Action+" "+m.Prefix.String()+" "+m.To+" "+m.At.Format(time.RFC3339Nano))
	}
	if len(have) != len(live) {
		t.Fatalf("live %v\nreplay %v", live, have)
	}
	for i := range live {
		if live[i] != have[i] {
			t.Fatalf("live %v\nreplay %v", live, have)
		}
	}
}

func TestFailedRoundWriteIsRetriedAndBounded(t *testing.T) {
	ctx := context.Background()
	st := &roundStore{memStore: &memStore{}, retention: time.Hour, failPut: errors.New("disk full")}
	r := New(Options{Store: st})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < maxPendingRounds+3; i++ {
		r.Round(now.Add(time.Duration(i)*time.Second), roundInput(), false)
	}
	if len(r.rounds) != maxPendingRounds || r.roundsDropped != 3 {
		t.Fatalf("pending %d dropped %d", len(r.rounds), r.roundsDropped)
	}
	if err := r.Flush(ctx); err == nil {
		t.Fatal("a failed round write was not reported")
	}
	if len(r.rounds) != maxPendingRounds {
		t.Fatalf("rounds after a failed flush = %d, want them kept", len(r.rounds))
	}
	st.failPut = nil
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(st.rounds) != maxPendingRounds || len(r.rounds) != 0 {
		t.Fatalf("stored %d, pending %d", len(st.rounds), len(r.rounds))
	}
}

// The byte cap binds before the count cap on a large table, and the
// oldest rounds go first.
func TestPendingRoundsAreBoundedByBytes(t *testing.T) {
	st := &roundStore{memStore: &memStore{}, retention: time.Hour, failPut: errors.New("disk full")}
	r := New(Options{Store: st})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	r.Round(now, roundInput(), false)
	size := len(r.rounds[0].Input)
	defer func(old int) { maxPendingRoundBytes = old }(maxPendingRoundBytes)
	maxPendingRoundBytes = 3*size + size/2
	for i := 1; i < 5; i++ {
		r.Round(now.Add(time.Duration(i)*time.Second), roundInput(), false)
	}
	pending := func() int {
		n := 0
		for _, rd := range r.rounds {
			n += len(rd.Input)
		}
		return n
	}
	if len(r.rounds) != 3 || r.roundsDropped != 2 || r.roundBytes != pending() || r.roundBytes > maxPendingRoundBytes {
		t.Fatalf("pending %d (%d bytes, counted %d) dropped %d, want 3 rounds of about %d bytes and 2 dropped", len(r.rounds), pending(), r.roundBytes, r.roundsDropped, size)
	}
	if !r.rounds[0].At.Equal(now.Add(2 * time.Second)) {
		t.Fatalf("oldest pending round is %v, want the oldest dropped", r.rounds[0].At)
	}
	if err := r.Flush(context.Background()); err == nil {
		t.Fatal("a failed round write was not reported")
	}
	if len(r.rounds) != 3 || r.roundBytes != pending() {
		t.Fatalf("after a failed flush: pending %d (%d bytes, counted %d)", len(r.rounds), pending(), r.roundBytes)
	}
}

// A failing round write reaches the storage health even when the history
// write succeeds, and a later good flush clears it.
func TestRoundWriteFailureReachesOnWrite(t *testing.T) {
	ctx := context.Background()
	st := &roundStore{memStore: &memStore{}, retention: time.Hour, failPut: errors.New("disk full")}
	var results []error
	r := New(Options{Store: st, OnWrite: func(err error) { results = append(results, err) }})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	r.Round(now, roundInput(), false)
	if err := r.Flush(ctx); err == nil {
		t.Fatal("rounds only: a failed round write was not reported")
	}
	r.Probe(result(pfxA, "lab-a", 0, 5*time.Millisecond, now))
	if err := r.Flush(ctx); err == nil {
		t.Fatal("rounds and history: a failed round write was not reported")
	}
	st.failPut = nil
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || results[0] == nil || results[1] == nil || results[1].Error() != "disk full" || results[2] != nil {
		t.Fatalf("OnWrite results = %v, want two failures then one success", results)
	}
	if len(st.rounds) != 1 || len(st.h.Buckets) == 0 {
		t.Fatalf("stored %d rounds, %d buckets", len(st.rounds), len(st.h.Buckets))
	}
}

// The recorder writes the rounds a replay reads back from sqlite.
func TestRoundsReachSQLite(t *testing.T) {
	ctx := context.Background()
	c, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "h.db") + "\nround_retention: 24h")
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer st.Stop(ctx)
	r := New(Options{Store: st})
	now := time.Now().UTC().Truncate(time.Millisecond)
	r.Round(now, roundInput(), false)
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := st.Rounds(ctx, now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("rounds = %+v %v", got, err)
	}
}
