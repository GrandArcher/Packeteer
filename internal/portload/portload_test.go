package portload

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var now = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func TestFresh(t *testing.T) {
	for _, tc := range []struct {
		name    string
		updated time.Time
		maxAge  time.Duration
		want    bool
	}{
		{"just now", now, time.Minute, true},
		{"at the limit", now.Add(-time.Minute), time.Minute, true},
		{"past the limit", now.Add(-time.Minute - time.Second), time.Minute, false},
		{"a little ahead", now.Add(MaxFutureSkew), time.Minute, true},
		{"too far ahead", now.Add(MaxFutureSkew + time.Second), time.Minute, false},
		{"no stamp", time.Time{}, time.Minute, true},
		{"no limit", now.Add(-24 * time.Hour), 0, true},
	} {
		if got := Fresh(tc.updated, now, tc.maxAge); got != tc.want {
			t.Errorf("%s: Fresh = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRead(t *testing.T) {
	row := func(p95, out float64, at time.Time) plugin.Usage {
		return plugin.Usage{Provider: "ix", CommitMbps: 1, Samples: 5, Single: true, UsageMbps: p95, OutMbps: out, Updated: at}
	}
	if load, p95, ok := Read(row(300, 350, now), now, time.Minute); !ok || load != 350 || p95 != 300 {
		t.Fatalf("outbound above the 95th: load %v p95 %v ok %v", load, p95, ok)
	}
	if load, p95, ok := Read(row(300, 100, now), now, time.Minute); !ok || load != 300 || p95 != 300 {
		t.Fatalf("95th above outbound: load %v p95 %v ok %v", load, p95, ok)
	}
	if _, _, ok := Read(row(300, 350, now.Add(-time.Hour)), now, time.Minute); ok {
		t.Fatal("a stale row was read")
	}
	if _, _, ok := Read(plugin.Usage{Updated: now}, now, time.Minute); ok {
		t.Fatal("a row with no samples was read")
	}
}

func TestRoom(t *testing.T) {
	if got := Room(1000, 0, 300, 100); got != 700 {
		t.Fatalf("no commit: %v", got)
	}
	if got := Room(1000, 400, 300, 350); got != 50 {
		t.Fatalf("commit tighter than capacity: %v", got)
	}
	if got := Room(1000, 400, 900, 100); got != 100 {
		t.Fatalf("capacity tighter than commit: %v", got)
	}
}
