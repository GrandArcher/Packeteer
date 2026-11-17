package portload

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func row(p95, out float64, updated time.Time) plugin.Usage {
	return plugin.Usage{Provider: "ix", CommitMbps: 1, Samples: 5, Single: true, UsageMbps: p95, OutMbps: out, Updated: updated}
}

func input(capacity, commit float64, u plugin.Usage, have bool) plugin.PlanInput {
	return plugin.PlanInput{
		Now: now,
		Providers: []plugin.PlanProvider{
			{Name: "transit"}, {Name: "peer-a", Port: "ix"}, {Name: "peer-b", Port: "ix"},
		},
		Ports: []plugin.PlanPort{{Name: "ix", CapacityMbps: capacity, CommitMbps: commit, Usage: u, HaveRow: have}},
	}
}

func TestAllowsCapacityAndCommit(t *testing.T) {
	l := NewLedger(input(1000, 600, row(500, 550, now), true), DefaultMaxAge)
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
	l = NewLedger(input(1000, 0, row(100, 900, now), true), DefaultMaxAge)
	if l.Allows("transit", "peer-a", 150) || !l.Allows("transit", "peer-a", 100) {
		t.Fatal("capacity must be judged on the larger of the outbound rate and the 95th")
	}
}

func TestRefusalNamesThePortAndTheLimit(t *testing.T) {
	l := NewLedger(input(1000, 600, row(500, 550, now), true), DefaultMaxAge)
	for _, tc := range []struct {
		to   string
		vol  float64
		want string
	}{
		{"peer-a", 40, ""},
		{"peer-a", 150, "ix 95th would reach 650 of its 600 Mbps commit with this 150 Mbps steer onto peer-a"},
		{"peer-b", 500, "ix would carry 1050 of its 1000 Mbps capacity with this 500 Mbps steer onto peer-b"},
		{"peer-a", 0, "ix: the prefix has no known volume, so the port's headroom cannot be checked for a steer onto peer-a"},
	} {
		if got := l.Refusal("transit", tc.to, tc.vol); got != tc.want {
			t.Errorf("%v Mbps onto %s: %q, want %q", tc.vol, tc.to, got, tc.want)
		}
	}
	for name, in := range map[string]plugin.PlanInput{
		"ix: no port telemetry":                               input(1000, 0, plugin.Usage{}, false),
		"ix: port reading is stale or has no billable figure": input(1000, 0, row(1, 1, now.Add(-time.Hour)), true),
	} {
		if got := NewLedger(in, DefaultMaxAge).Refusal("transit", "peer-a", 10); got != name+", so no new steer goes onto peer-a" {
			t.Errorf("%s: %q", name, got)
		}
	}
	// A one-sided move books only the side that is named.
	l.Move("", "peer-a", 60)
	if h, _ := l.Headroom("peer-b"); h != 40 {
		t.Fatalf("headroom after 60 Mbps onto the port = %v, want 40", h)
	}
	l.Move("peer-b", "", 100)
	if h, _ := l.Headroom("peer-a"); h != 140 {
		t.Fatalf("headroom after 100 Mbps off the port = %v, want 140", h)
	}
}

func TestFailsClosedWithoutAFreshRow(t *testing.T) {
	for name, in := range map[string]plugin.PlanInput{
		"no row":       input(1000, 0, plugin.Usage{}, false),
		"stale row":    input(1000, 0, row(1, 1, now.Add(-time.Hour)), true),
		"future row":   input(1000, 0, row(1, 1, now.Add(time.Hour)), true),
		"no samples":   input(1000, 0, plugin.Usage{CommitMbps: 1, Updated: now}, true),
		"no billable":  input(1000, 0, plugin.Usage{Samples: 3, Updated: now}, true),
		"zero commit":  input(1000, 0, plugin.Usage{Samples: 3, Single: true, UsageMbps: 1, Updated: now}, true),
		"stale+commit": input(1000, 500, row(1, 1, now.Add(-time.Hour)), true),
	} {
		l := NewLedger(in, DefaultMaxAge)
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
	l := NewLedger(input(1000, 600, row(500, 500, now), true), DefaultMaxAge)
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
