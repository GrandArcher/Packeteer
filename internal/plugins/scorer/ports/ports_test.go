package ports

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/portload"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

func row(p95, out float64, updated time.Time) plugin.Usage {
	return plugin.Usage{Provider: "ix", CommitMbps: 1, Samples: 5, Single: true, UsageMbps: p95, OutMbps: out, Updated: updated}
}

func input(capacity, commit float64, u plugin.Usage, have bool) plugin.PlanInput {
	return plugin.PlanInput{
		Now: t0,
		Providers: []plugin.PlanProvider{
			{Name: "transit"}, {Name: "peer-a", Port: "ix"}, {Name: "peer-b", Port: "ix"},
		},
		Ports: []plugin.PlanPort{{Name: "ix", CapacityMbps: capacity, CommitMbps: commit, Usage: u, HaveRow: have}},
	}
}

func TestAllowsCapacityAndCommit(t *testing.T) {
	l := New(input(1000, 600, row(500, 550, t0), true), portload.DefaultMaxAge)
	for _, tc := range []struct {
		name     string
		from, to string
		vol      float64
		want     bool
	}{
		{"inside both", "transit", "peer-a", 40, true},
		{"over commit, inside capacity", "transit", "peer-a", 150, false},
		{"exactly at commit", "transit", "peer-a", 100, true},
		{"sibling peers share the port", "peer-a", "peer-b", 900, true},
		{"not a port destination", "peer-a", "transit", 5000, true},
		{"unknown volume is not checkable", "transit", "peer-a", 0, false},
	} {
		if got := l.Allows(tc.from, tc.to, tc.vol); got != tc.want {
			t.Errorf("%s: Allows = %v, want %v", tc.name, got, tc.want)
		}
	}

	// No commit: only capacity limits. Load is the larger of out and p95.
	l = New(input(1000, 0, row(100, 900, t0), true), portload.DefaultMaxAge)
	if l.Allows("transit", "peer-a", 150) || !l.Allows("transit", "peer-a", 100) {
		t.Fatal("capacity must be judged on the larger of the outbound rate and the 95th")
	}
}

func TestFailsClosedWithoutAFreshRow(t *testing.T) {
	for name, in := range map[string]plugin.PlanInput{
		"no row":       input(1000, 0, plugin.Usage{}, false),
		"stale row":    input(1000, 0, row(1, 1, t0.Add(-time.Hour)), true),
		"future row":   input(1000, 0, row(1, 1, t0.Add(time.Hour)), true),
		"no samples":   input(1000, 0, plugin.Usage{CommitMbps: 1, Updated: t0}, true),
		"no billable":  input(1000, 0, plugin.Usage{Samples: 3, Updated: t0}, true),
		"zero commit":  input(1000, 0, plugin.Usage{Samples: 3, Single: true, UsageMbps: 1, Updated: t0}, true),
		"stale+commit": input(1000, 500, row(1, 1, t0.Add(-time.Hour)), true),
	} {
		l := New(in, portload.DefaultMaxAge)
		if l.Allows("transit", "peer-a", 1) {
			t.Errorf("%s: a port with no usable reading accepted a move", name)
		}
		if _, ok := l.Headroom("peer-a"); ok {
			t.Errorf("%s: headroom reported without a reading", name)
		}
		if !l.Allows("peer-a", "transit", 1) {
			t.Errorf("%s: a move off the port must not be refused", name)
		}
	}
}

func TestMoveBooksBothEnds(t *testing.T) {
	l := New(input(1000, 600, row(500, 500, t0), true), portload.DefaultMaxAge)
	if room, ok := l.Headroom("peer-a"); !ok || room != 100 {
		t.Fatalf("headroom = %v %v, want 100", room, ok)
	}
	l.Move("transit", "peer-a", 80)
	if l.Allows("transit", "peer-b", 30) {
		t.Fatal("the booked 80 Mbps must count against the shared commit")
	}
	if !l.Allows("transit", "peer-b", 20) {
		t.Fatal("20 Mbps still fits")
	}
	l.Move("peer-b", "transit", 80)
	if room, _ := l.Headroom("peer-a"); room != 100 {
		t.Fatalf("headroom after moving off = %v, want 100", room)
	}
	l.Move("peer-a", "peer-b", 50)
	if room, _ := l.Headroom("peer-a"); room != 100 {
		t.Fatalf("a move between peers of one port changed the load: %v", room)
	}
	l.Move("peer-a", "transit", 5000)
	if room, _ := l.Headroom("peer-a"); room != 600 {
		t.Fatalf("load must not go negative: headroom %v, want 600", room)
	}
}
