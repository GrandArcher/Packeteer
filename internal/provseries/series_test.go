package provseries

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 3, 17, 12, 7, 0, 0, time.UTC)

func result(provider string, at time.Time, loss float64, rtt time.Duration) probe.Result {
	return probe.Result{Provider: provider, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Time: at,
		Stats: probe.Stats{Sent: 10, Received: 10 - int(loss/10), LossPct: loss, RTTAvg: rtt, Jitter: rtt / 10}}
}

func find(t *testing.T, stats []Stat, name string) Stat {
	t.Helper()
	for _, s := range stats {
		if s.Provider == name {
			return s
		}
	}
	t.Fatalf("no stat for %s in %+v", name, stats)
	return Stat{}
}

func TestWindowsAreMediansOfSlots(t *testing.T) {
	s := New(func() time.Time { return t0 })
	// 12:05 slot 40 ms, 12:00 slot 20 ms, 11:55 slot 30 ms (in 15 m),
	// 11:30 slot 500 ms (24 h only). The outlier must not move the 15 m
	// median, and the 24 h median of 4 slots is the mean of the middle two.
	for _, c := range []struct {
		at  time.Duration
		rtt time.Duration
	}{{-2 * time.Minute, 40 * time.Millisecond}, {-7 * time.Minute, 20 * time.Millisecond}, {-12 * time.Minute, 30 * time.Millisecond}, {-37 * time.Minute, 500 * time.Millisecond}} {
		s.Add(result("lab-a", t0.Add(c.at), 0, c.rtt))
	}
	st := find(t, s.Stats(), "lab-a")
	if st.Last15m.Slots != 3 || !st.Last15m.HasRTT || st.Last15m.RTTMs != 30 || st.Last15m.JitterMs != 3 {
		t.Fatalf("15m = %+v", st.Last15m)
	}
	if st.Last24h.Slots != 4 || st.Last24h.RTTMs != 35 {
		t.Fatalf("24h = %+v", st.Last24h)
	}
}

func TestFailedAndSilentProbesAreFullLossAndNoRTT(t *testing.T) {
	s := New(func() time.Time { return t0 })
	s.Add(result("lab-a", t0, 0, 10*time.Millisecond))
	s.Add(probe.Result{Provider: "lab-a", Time: t0, Err: "no route"})
	// 100% loss: nothing came back, so Stats carries a zero RTT.
	s.Add(probe.Result{Provider: "lab-a", Time: t0, Stats: probe.Stats{Sent: 10, LossPct: 100}})
	s.Add(probe.Result{Provider: "lab-b", Time: t0, Stats: probe.Stats{Sent: 10, LossPct: 100}})
	stats := s.Stats()
	a := find(t, stats, "lab-a")
	if a.Last15m.RTTMs != 10 {
		t.Fatalf("a silent probe moved the RTT: %+v", a.Last15m)
	}
	// 1 good probe at 0% and 2 failed at 100%.
	if got := a.Last15m.LossPct; got < 66.6 || got > 66.7 {
		t.Fatalf("loss = %v, want 66.67", got)
	}
	b := find(t, stats, "lab-b")
	if b.Last15m.HasRTT || b.Last15m.RTTMs != 0 || b.Last15m.LossPct != 100 || b.Points[0].HasRTT {
		t.Fatalf("lab-b answers nothing: %+v %+v", b.Last15m, b.Points)
	}
}

func TestPointsAreHourlyAndOldDataIsDropped(t *testing.T) {
	now := t0
	s := New(func() time.Time { return now })
	s.Add(result("lab-a", t0.Add(-90*time.Minute), 0, 20*time.Millisecond))
	s.Add(result("lab-a", t0.Add(-80*time.Minute), 0, 40*time.Millisecond))
	s.Add(result("lab-a", t0, 10, 100*time.Millisecond))
	s.Add(result("lab-a", t0.Add(-25*time.Hour), 0, 1*time.Millisecond)) // older than Keep: ignored
	st := find(t, s.Stats(), "lab-a")
	if len(st.Points) != 2 {
		t.Fatalf("points = %+v", st.Points)
	}
	if p := st.Points[0]; !p.At.Equal(time.Date(2026, 3, 17, 10, 0, 0, 0, time.UTC)) || p.RTTMs != 30 {
		t.Fatalf("first hour = %+v", p)
	}
	if p := st.Points[1]; !p.At.Equal(time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)) || p.RTTMs != 100 || p.LossPct != 10 {
		t.Fatalf("second hour = %+v", p)
	}

	// A day later everything has expired and the provider is forgotten.
	now = t0.Add(25 * time.Hour)
	if got := s.Stats(); len(got) != 0 {
		t.Fatalf("stats after expiry = %+v", got)
	}
	if len(s.cells) != 0 {
		t.Fatalf("expired provider still held: %v", s.cells)
	}
}

func TestMemoryIsBoundedPerProvider(t *testing.T) {
	now := t0
	s := New(func() time.Time { return now })
	for i := 0; i < 3*288; i++ {
		now = t0.Add(time.Duration(i) * Slot)
		s.Add(result("lab-a", now, 0, time.Millisecond))
	}
	if n := len(s.cells["lab-a"]); n > 289 {
		t.Fatalf("%d slots held, want at most 289", n)
	}
}

type fakeStore struct {
	rows []plugin.ProviderSample
	fail error
}

func (f *fakeStore) PutProviderSamples(_ context.Context, in []plugin.ProviderSample) error {
	if f.fail != nil {
		return f.fail
	}
	for _, sm := range in {
		replaced := false
		for i := range f.rows {
			if f.rows[i].Provider == sm.Provider && f.rows[i].Slot.Equal(sm.Slot) {
				f.rows[i], replaced = sm, true
			}
		}
		if !replaced {
			f.rows = append(f.rows, sm)
		}
	}
	return nil
}

func (f *fakeStore) ProviderSamples(_ context.Context, from, to time.Time) ([]plugin.ProviderSample, error) {
	var out []plugin.ProviderSample
	for _, r := range f.rows {
		if !r.Slot.Before(from) && r.Slot.Before(to) {
			out = append(out, r)
		}
	}
	return out, nil
}

func TestFlushRestoreAndRetryAfterFailure(t *testing.T) {
	ctx := context.Background()
	store := &fakeStore{}
	s := New(func() time.Time { return t0 })
	s.Add(result("lab-a", t0, 0, 20*time.Millisecond))
	s.Add(result("lab-a", t0, 0, 40*time.Millisecond))

	store.fail = errors.New("disk full")
	if err := s.Flush(ctx, store); err == nil {
		t.Fatal("Flush hid the write error")
	}
	store.fail = nil
	if err := s.Flush(ctx, store); err != nil || len(store.rows) != 1 || store.rows[0].Probes != 2 || store.rows[0].RTTSumMs != 60 {
		t.Fatalf("retry wrote %+v, err %v", store.rows, err)
	}
	if err := s.Flush(ctx, store); err != nil || len(store.rows) != 1 {
		t.Fatalf("an unchanged slot was written again: %+v %v", store.rows, err)
	}

	// A restart inside the same slot keeps counting from the stored values.
	again := New(func() time.Time { return t0 })
	if err := again.Restore(ctx, store); err != nil {
		t.Fatal(err)
	}
	again.Add(result("lab-a", t0, 0, 60*time.Millisecond))
	if err := again.Flush(ctx, store); err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 1 || store.rows[0].Probes != 3 || store.rows[0].RTTSumMs != 120 {
		t.Fatalf("slot after restart = %+v", store.rows)
	}
	if st := find(t, again.Stats(), "lab-a"); st.Last24h.RTTMs != 40 {
		t.Fatalf("restored window = %+v", st.Last24h)
	}
}

func TestIgnoresResultsWithoutProvider(t *testing.T) {
	s := New(func() time.Time { return t0 })
	s.Add(result("", t0, 0, time.Millisecond))
	if got := s.Stats(); len(got) != 0 {
		t.Fatalf("stats = %+v", got)
	}
}
