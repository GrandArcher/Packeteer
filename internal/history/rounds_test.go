package history

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

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
	r.Round(time.Now(), roundInput())
	if r.KeepsRounds() || len(r.rounds) != 0 {
		t.Fatal("a store with round retention 0 queued a round")
	}
	plain := New(Options{Store: &memStore{}})
	plain.Round(time.Now(), roundInput())
	if plain.KeepsRounds() || len(plain.rounds) != 0 {
		t.Fatal("a store without rounds queued one")
	}

	on := &roundStore{memStore: &memStore{}, retention: time.Hour}
	r = New(Options{Store: on})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	r.Round(now, roundInput())
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

// RIB changes trigger evaluations between probe rounds; only one round per
// RoundEvery is kept.
func TestRoundsAreSpacedByRoundEvery(t *testing.T) {
	st := &roundStore{memStore: &memStore{}, retention: time.Hour}
	r := New(Options{Store: st, RoundEvery: 15 * time.Second})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, off := range []time.Duration{0, time.Second, 5 * time.Second, 14 * time.Second, 15 * time.Second, 16 * time.Second, 31 * time.Second} {
		r.Round(now.Add(off), roundInput())
	}
	var at []time.Duration
	for _, rr := range r.rounds {
		at = append(at, rr.At.Sub(now))
	}
	want := []time.Duration{0, 15 * time.Second, 31 * time.Second}
	if len(at) != len(want) {
		t.Fatalf("kept rounds at %v, want %v", at, want)
	}
	for i := range want {
		if at[i] != want[i] {
			t.Fatalf("kept rounds at %v, want %v", at, want)
		}
	}
}

func TestFailedRoundWriteIsRetriedAndBounded(t *testing.T) {
	ctx := context.Background()
	st := &roundStore{memStore: &memStore{}, retention: time.Hour, failPut: errors.New("disk full")}
	r := New(Options{Store: st})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < maxPendingRounds+3; i++ {
		r.Round(now.Add(time.Duration(i)*time.Second), roundInput())
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
	r.Round(now, roundInput())
	if err := r.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := st.Rounds(ctx, now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("rounds = %+v %v", got, err)
	}
}
