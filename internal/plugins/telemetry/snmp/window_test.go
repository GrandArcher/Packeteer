package snmp

import (
	"math"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestBillingPeriod(t *testing.T) {
	day := 15
	start, end := billingPeriod(time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC), day)
	if !start.Equal(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)) || !end.Equal(time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("mid period = %s .. %s", start, end)
	}
	start, end = billingPeriod(time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC), day)
	if !start.Equal(time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)) || !end.Equal(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("before day = %s .. %s", start, end)
	}
	start, end = billingPeriod(time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC), day)
	if !start.Equal(time.Date(2025, 12, 15, 0, 0, 0, 0, time.UTC)) || !end.Equal(time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("year boundary = %s .. %s", start, end)
	}
	// The billing instant itself opens the new period.
	start, _ = billingPeriod(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC), day)
	if !start.Equal(time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("boundary start = %s", start)
	}
}

func TestWindowRollsOnBillingDay(t *testing.T) {
	w := window{billingDay: 15, mode: plugin.PercentileGreaterSeparate, maxSamples: 10}
	march := time.Date(2026, 3, 14, 23, 0, 0, 0, time.UTC)
	w.add(march, 5e6, 1e6) // 5 Mbps in, 1 Mbps out
	sum, _, _ := w.summary(march)
	if sum.Samples != 1 || sum.In95 != 5 || sum.Usage != 5 {
		t.Fatalf("march = %+v", sum)
	}
	april := time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	sum, start, _ := w.summary(april)
	if sum.Samples != 0 || sum.Single || !start.Equal(april) {
		t.Fatalf("rolled = %+v start %s", sum, start)
	}
	w.add(april, 2e6, 8e6)
	sum, _, _ = w.summary(april)
	if sum.Samples != 1 || sum.Out95 != 8 || sum.Usage != 8 || len(w.samples) != 1 {
		t.Fatalf("new period = %+v samples %d", sum, len(w.samples))
	}
}

func TestCounterDeltaAndRate(t *testing.T) {
	// 7_500_000 octets in 60s is exactly 1 Mbps.
	dt := 60 * time.Second
	if got := rateBps(7_500_000, dt); math.Abs(got-1e6) > 1 {
		t.Fatalf("rate = %v", got)
	}
	const max32 = uint64(1<<32 - 1)
	delta := counterDelta(max32-999, 6500, 32)
	if delta != 7500 {
		t.Fatalf("32-bit wrap delta = %d, want 7500", delta)
	}
	if got := rateBps(delta, dt); math.Abs(got-1000) > 0.01 {
		t.Fatalf("wrap rate = %v, want 1000 bps", got)
	}
	// 64-bit subtraction wraps in unsigned arithmetic.
	if counterDelta(math.MaxUint64-5, 4, 64) != 10 {
		t.Fatalf("64-bit wrap = %d", counterDelta(math.MaxUint64-5, 4, 64))
	}
	if saneRate(math.Inf(1), 0) || saneRate(-1, 0) || saneRate(maxSaneBps+1, 0) {
		t.Fatal("insane rate accepted")
	}
	// Twice the reported link speed is the limit.
	if saneRate(2001e6, 1000) || !saneRate(2000e6, 1000) {
		t.Fatal("speed cap")
	}
}

func TestIfIndexForm(t *testing.T) {
	if n, ok := ifIndex("12"); !ok || n != 12 {
		t.Fatalf("12 = %d %v", n, ok)
	}
	for _, s := range []string{"ether1", "01", "0", "-1", "1.2"} {
		if _, ok := ifIndex(s); ok {
			t.Fatalf("%q parsed as an ifIndex", s)
		}
	}
}
