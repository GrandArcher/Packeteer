package snmp

import (
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// sample is one accepted counter delta. Rates are bits per second.
type sample struct {
	at  time.Time
	in  float64
	out float64
}

// window keeps the open billing period. The period is [start, end) in UTC,
// beginning at 00:00 UTC on billingDay. Days 29–31 are rejected at config
// time so February always contains the day.
type window struct {
	billingDay int
	mode       plugin.PercentileMode
	maxSamples int
	samples    []sample
}

func billingPeriod(t time.Time, day int) (start, end time.Time) {
	t = t.UTC()
	y, m, d := t.Date()
	if d >= day {
		start = time.Date(y, m, day, 0, 0, 0, 0, time.UTC)
		end = time.Date(y, m+1, day, 0, 0, 0, 0, time.UTC)
	} else {
		start = time.Date(y, m-1, day, 0, 0, 0, 0, time.UTC)
		end = time.Date(y, m, day, 0, 0, 0, 0, time.UTC)
	}
	return start, end
}

func (w *window) add(t time.Time, inBps, outBps float64) {
	t = t.UTC()
	start, end := billingPeriod(t, w.billingDay)
	w.retain(start, end)
	w.samples = append(w.samples, sample{at: t, in: inBps, out: outBps})
	if w.maxSamples > 0 && len(w.samples) > w.maxSamples {
		w.samples = append([]sample(nil), w.samples[len(w.samples)-w.maxSamples:]...)
	}
}

func (w *window) retain(start, end time.Time) {
	kept := w.samples[:0]
	for _, s := range w.samples {
		if !s.at.Before(start) && s.at.Before(end) {
			kept = append(kept, s)
		}
	}
	w.samples = kept
}

func (w *window) summary(now time.Time) (plugin.PercentileSummary, time.Time, time.Time) {
	start, end := billingPeriod(now, w.billingDay)
	rates := make([]plugin.RateSample, 0, len(w.samples))
	for _, s := range w.samples {
		if s.at.Before(start) || !s.at.Before(end) {
			continue
		}
		rates = append(rates, plugin.RateSample{In: s.in, Out: s.out})
	}
	sum := plugin.Summarize(w.mode, rates)
	// Summarize works in the stored unit (bits per second). The API is Mbps.
	const mega = 1e6
	sum.In95 /= mega
	sum.Out95 /= mega
	sum.Usage /= mega
	return sum, start, end
}
