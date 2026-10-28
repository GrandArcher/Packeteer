package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestRoundsOffByDefault(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "r.db"))
	if s.RoundRetention() != 0 {
		t.Fatalf("round retention = %s, want off", s.RoundRetention())
	}
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if err := s.PutRounds(ctx, []plugin.RoundRecord{{At: time.Now(), Input: []byte("x")}}); err == nil {
		t.Fatal("a store with round_retention 0 accepted a round")
	}
}

func TestRoundsRoundTripPageReplacePrune(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "r.db")+"\nround_retention: 2h")
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)

	var rs []plugin.RoundRecord
	for i := 0; i < 5; i++ {
		rs = append(rs, plugin.RoundRecord{At: now.Add(-time.Duration(i) * time.Minute), Input: []byte{byte('a' + i)}})
	}
	rs = append(rs, plugin.RoundRecord{At: now.Add(-3 * time.Hour), Input: []byte("old")})
	if err := s.PutRounds(ctx, rs); err != nil {
		t.Fatal(err)
	}
	// A write prunes what is past round_retention.
	got, err := s.Rounds(ctx, now.Add(-4*time.Hour), now.Add(time.Minute), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || string(got[0].Input) != "e" || string(got[4].Input) != "a" {
		t.Fatalf("rounds = %+v", got)
	}
	// Pages: the next page starts after the last round of the previous one.
	first, err := s.Rounds(ctx, now.Add(-time.Hour), now.Add(time.Minute), 2)
	if err != nil || len(first) != 2 {
		t.Fatalf("first page: %+v %v", first, err)
	}
	next, err := s.Rounds(ctx, first[1].At.Add(time.Millisecond), now.Add(time.Minute), 2)
	if err != nil || len(next) != 2 || string(next[0].Input) != "c" {
		t.Fatalf("second page: %+v %v", next, err)
	}
	// [from, to) excludes a round at to.
	got, err = s.Rounds(ctx, now.Add(-time.Hour), now, 100)
	if err != nil || len(got) != 4 {
		t.Fatalf("round at the end bound: %+v %v", got, err)
	}
	// The same time replaces.
	if err := s.PutRounds(ctx, []plugin.RoundRecord{{At: now, Input: []byte("z")}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Rounds(ctx, now, now.Add(time.Minute), 10)
	if len(got) != 1 || string(got[0].Input) != "z" {
		t.Fatalf("replaced round = %+v", got)
	}
	if _, err := s.Rounds(ctx, now, now, 0); err == nil {
		t.Fatal("limit 0 accepted")
	}
	if err := s.PutRounds(ctx, []plugin.RoundRecord{{At: now}}); err == nil {
		t.Fatal("a round without input accepted")
	}
}

func TestOpenReadOnlyReadsAndCannotWrite(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r.db")
	w := newStore(t, "path: "+path+"\nround_retention: 2h")
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := w.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.PutRounds(ctx, []plugin.RoundRecord{{At: now, Input: []byte("a")}}); err != nil {
		t.Fatal(err)
	}

	// A second handle while the writer is still open, as a CLI beside a
	// running controller.
	r := newStore(t, "path: "+path+"\nround_retention: 2h")
	if err := r.OpenReadOnly(ctx); err != nil {
		t.Fatal(err)
	}
	defer r.Stop(ctx)
	got, err := r.Rounds(ctx, now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(got) != 1 || string(got[0].Input) != "a" {
		t.Fatalf("read-only rounds = %+v %v", got, err)
	}
	if err := r.PutRounds(ctx, []plugin.RoundRecord{{At: now.Add(time.Second), Input: []byte("b")}}); err == nil {
		t.Fatal("a read-only handle wrote a round")
	}
	_ = w.Stop(ctx)

	missing := newStore(t, "path: "+filepath.Join(t.TempDir(), "none.db"))
	if err := missing.OpenReadOnly(ctx); err == nil {
		t.Fatal("opened a database that does not exist")
	}
}

// A database from before round storage has no table; a read finds no rounds.
func TestRoundsWithoutTable(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "r.db"))
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	if _, err := s.db.ExecContext(ctx, `DROP TABLE decision_rounds`); err != nil {
		t.Fatal(err)
	}
	got, err := s.Rounds(ctx, time.Time{}, time.Now(), 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("rounds = %+v %v", got, err)
	}
}
