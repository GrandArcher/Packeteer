// Package provseries keeps the last day of each provider's probe results
// in five-minute slots, for the Providers page and the Overview latency
// chart. It is display only: nothing here feeds a decision or announces a
// route. The Recorder persists the slots through plugin.ProviderSampleStore
// when a storage plugin has one.
package provseries

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Slot is the width of one stored sample; Keep is how far back they are kept.
const (
	Slot = 5 * time.Minute
	Keep = 24 * time.Hour
)

// Short is the "last 15 minutes" window of the Providers table.
const Short = 15 * time.Minute

type cell struct {
	probes, failed, measured int
	loss, rtt, jitter        float64
}

type key struct {
	provider string
	slot     int64
}

// Series is safe for concurrent use. Memory is bounded by the number of
// providers times Keep/Slot slots: a slot older than Keep is dropped when
// its provider gets a new slot.
type Series struct {
	mu    sync.Mutex
	now   func() time.Time
	cells map[string]map[int64]*cell
	dirty map[key]bool
}

// New returns an empty series. A nil now uses the wall clock.
func New(now func() time.Time) *Series {
	if now == nil {
		now = time.Now
	}
	return &Series{now: now, cells: map[string]map[int64]*cell{}, dirty: map[key]bool{}}
}

func slotOf(t time.Time) int64 { return t.UTC().Truncate(Slot).Unix() }

// Add counts one probe result. A result with no provider, or older than
// Keep, is ignored. A result that errored or got no reply counts as a
// failed probe, which is full loss and has no RTT: a path with no answer
// must not drag the median latency toward zero.
func (s *Series) Add(res probe.Result) {
	if res.Provider == "" {
		return
	}
	now := s.now()
	t := res.Time
	if t.IsZero() {
		t = now
	}
	if t.Before(now.Add(-Keep)) {
		return
	}
	sl := slotOf(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.cells[res.Provider]
	if row == nil {
		row = map[int64]*cell{}
		s.cells[res.Provider] = row
	}
	c := row[sl]
	if c == nil {
		s.expire(res.Provider, row, now)
		c = &cell{}
		row[sl] = c
	}
	c.probes++
	if !res.OK() || res.Stats.Received == 0 {
		c.failed++
	} else {
		c.measured++
		c.loss += res.Stats.LossPct
		c.rtt += float64(res.Stats.RTTAvg) / float64(time.Millisecond)
		c.jitter += float64(res.Stats.Jitter) / float64(time.Millisecond)
	}
	s.dirty[key{res.Provider, sl}] = true
}

// expire drops the provider's slots that ended more than Keep ago.
func (s *Series) expire(provider string, row map[int64]*cell, now time.Time) {
	cutoff := slotOf(now.Add(-Keep))
	for sl := range row {
		if sl < cutoff {
			delete(row, sl)
			delete(s.dirty, key{provider, sl})
		}
	}
}

// Window is a provider's figures over a window: the median of the
// five-minute slot values. Slots is how many slots had probes; with none,
// every figure is zero and the page says there is no data.
type Window struct {
	Slots    int
	LossPct  float64
	RTTMs    float64
	JitterMs float64
	// HasRTT is false when no probe in the window returned a measurement.
	HasRTT bool
}

// Point is one hour of a provider's results: the mean over its probes.
type Point struct {
	At      time.Time
	LossPct float64
	RTTMs   float64
	// HasRTT is false when no probe that hour returned a measurement.
	HasRTT bool
}

// Stat is one provider's windows and hourly points, oldest first.
type Stat struct {
	Provider string
	Last15m  Window
	Last24h  Window
	Points   []Point
}

// slotLoss is a slot's loss: a failed probe counts as 100%, as the
// provider health does.
func (c *cell) slotLoss() float64 {
	return (c.loss + 100*float64(c.failed)) / float64(c.probes)
}

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	slices.Sort(v)
	if n := len(v); n%2 == 0 {
		return (v[n/2-1] + v[n/2]) / 2
	}
	return v[len(v)/2]
}

// window summarizes the slots that overlap the last d.
func window(row map[int64]*cell, now time.Time, d time.Duration) Window {
	from := slotOf(now.Add(-d))
	var loss, rtt, jit []float64
	var w Window
	for sl, c := range row {
		if sl < from || c.probes == 0 {
			continue
		}
		w.Slots++
		loss = append(loss, c.slotLoss())
		if c.measured > 0 {
			rtt = append(rtt, c.rtt/float64(c.measured))
			jit = append(jit, c.jitter/float64(c.measured))
		}
	}
	w.LossPct, w.RTTMs, w.JitterMs, w.HasRTT = median(loss), median(rtt), median(jit), len(rtt) > 0
	return w
}

func points(row map[int64]*cell, now time.Time) []Point {
	from := slotOf(now.Add(-Keep))
	type acc struct {
		probes, failed, measured int
		loss, rtt                float64
	}
	hours := map[int64]*acc{}
	for sl, c := range row {
		if sl < from || c.probes == 0 {
			continue
		}
		h := time.Unix(sl, 0).UTC().Truncate(time.Hour).Unix()
		a := hours[h]
		if a == nil {
			a = &acc{}
			hours[h] = a
		}
		a.probes += c.probes
		a.failed += c.failed
		a.measured += c.measured
		a.loss += c.loss
		a.rtt += c.rtt
	}
	keys := make([]int64, 0, len(hours))
	for h := range hours {
		keys = append(keys, h)
	}
	slices.Sort(keys)
	out := make([]Point, 0, len(keys))
	for _, h := range keys {
		a := hours[h]
		p := Point{At: time.Unix(h, 0).UTC(), LossPct: (a.loss + 100*float64(a.failed)) / float64(a.probes)}
		if a.measured > 0 {
			p.RTTMs, p.HasRTT = a.rtt/float64(a.measured), true
		}
		out = append(out, p)
	}
	return out
}

// Stats returns one Stat per provider that has a slot inside Keep, sorted
// by name. A provider whose slots have all expired is forgotten.
func (s *Series) Stats() []Stat {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Stat, 0, len(s.cells))
	for name, row := range s.cells {
		s.expire(name, row, now)
		if len(row) == 0 {
			delete(s.cells, name)
			continue
		}
		out = append(out, Stat{Provider: name, Last15m: window(row, now, Short), Last24h: window(row, now, Keep), Points: points(row, now)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out
}

// Take returns the slots changed since the last Take, as absolute values,
// and clears the changed marks.
func (s *Series) Take() []plugin.ProviderSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]plugin.ProviderSample, 0, len(s.dirty))
	for k := range s.dirty {
		if c := s.cells[k.provider][k.slot]; c != nil {
			out = append(out, plugin.ProviderSample{Provider: k.provider, Slot: time.Unix(k.slot, 0).UTC(),
				Probes: c.probes, Failed: c.failed, Measured: c.measured, LossSum: c.loss, RTTSumMs: c.rtt, JitterSum: c.jitter})
		}
	}
	clear(s.dirty)
	return out
}

// Requeue marks samples a failed write did not store as changed again.
func (s *Series) Requeue(samples []plugin.ProviderSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sm := range samples {
		k := key{sm.Provider, slotOf(sm.Slot)}
		if s.cells[k.provider][k.slot] != nil {
			s.dirty[k] = true
		}
	}
}

// load adds stored samples to the series. It runs before the first probe,
// so the slot a restart interrupts continues from its stored values.
func (s *Series) load(samples []plugin.ProviderSample) {
	now := s.now()
	cutoff := slotOf(now.Add(-Keep))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sm := range samples {
		sl := slotOf(sm.Slot)
		if sm.Provider == "" || sl < cutoff {
			continue
		}
		row := s.cells[sm.Provider]
		if row == nil {
			row = map[int64]*cell{}
			s.cells[sm.Provider] = row
		}
		c := row[sl]
		if c == nil {
			c = &cell{}
			row[sl] = c
		}
		c.probes += sm.Probes
		c.failed += sm.Failed
		c.measured += sm.Measured
		c.loss += sm.LossSum
		c.rtt += sm.RTTSumMs
		c.jitter += sm.JitterSum
	}
}

// Flush writes the changed slots to store. A failed write keeps them for
// the next flush.
func (s *Series) Flush(ctx context.Context, store plugin.ProviderSampleStore) error {
	batch := s.Take()
	if len(batch) == 0 {
		return nil
	}
	if err := store.PutProviderSamples(ctx, batch); err != nil {
		s.Requeue(batch)
		return err
	}
	return nil
}

// Restore reads the slots still inside Keep from store into the series.
func (s *Series) Restore(ctx context.Context, store plugin.ProviderSampleStore) error {
	now := s.now()
	rows, err := store.ProviderSamples(ctx, time.Unix(slotOf(now.Add(-Keep)), 0).UTC(), now.Add(Slot))
	if err != nil {
		return err
	}
	s.load(rows)
	return nil
}
