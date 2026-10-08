package snmp

import (
	"context"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// How long a sample write may wait on the storage plugin. The poll does
// not start the next host until this returns. A failure leaves the sample
// in memory and logs; the next accepted sample tries again for itself.
const sampleStoreTimeout = 5 * time.Second

var _ plugin.SampleKeeper = (*Collector)(nil)

// persistedSample is one accepted rate and the oldest sample the open
// window still keeps, so the store can drop what memory already dropped.
type persistedSample struct {
	store  plugin.SampleStore
	sample plugin.UsageSample
	oldest time.Time
}

// UseSampleStore keeps samples in store. The host calls it before Start.
// A nil store leaves the window in memory only.
func (c *Collector) UseSampleStore(store plugin.SampleStore) {
	c.mu.Lock()
	c.store = store
	c.mu.Unlock()
}

func (c *Collector) clock() time.Time {
	c.mu.Lock()
	now := c.now
	c.mu.Unlock()
	if now != nil {
		return now()
	}
	return time.Now()
}

// loadSamples fills each open billing window from store. A read error
// leaves that binding empty for this process and does not fail Start:
// collection still runs, and the next sample is stored.
func (c *Collector) loadSamples(ctx context.Context) {
	c.mu.Lock()
	store := c.store
	c.mu.Unlock()
	if store == nil {
		return
	}
	now := c.clock().UTC()
	for _, name := range c.order {
		c.mu.Lock()
		st := c.states[name]
		spec := st.spec
		limit := st.win.maxSamples
		c.mu.Unlock()
		start, end := billingPeriod(now, spec.billingDay)
		rows, err := store.UsageSamples(ctx, plugin.UsageSampleQuery{
			Provider: spec.name, Host: spec.host, Interface: spec.iface,
			From: start, To: end, Limit: limit,
		})
		if err != nil {
			c.log.Warn("snmp sample load", "provider", spec.name, "err", err)
			continue
		}
		c.mu.Lock()
		st.win.samples = st.win.samples[:0]
		for _, r := range rows {
			st.win.samples = append(st.win.samples, sample{at: r.At.UTC(), in: r.InBps, out: r.OutBps})
		}
		if len(rows) > 0 {
			last := rows[len(rows)-1]
			st.lastIn = last.InBps / 1e6
			st.lastOut = last.OutBps / 1e6
			st.updated = last.At.UTC()
		}
		c.mu.Unlock()
		if len(rows) == 0 {
			continue
		}
		// Disk may still hold samples the cap dropped the last time a
		// write failed. Forget those so the file matches memory.
		if err := store.TrimUsageSamples(ctx, spec.name, spec.host, spec.iface, start, end, rows[0].At); err != nil {
			c.log.Warn("snmp sample trim", "provider", spec.name, "err", err)
		}
	}
}

// sampleRecord is called with c.mu held.
func (c *Collector) sampleRecord(st *provState, at time.Time, inBps, outBps float64) persistedSample {
	start, end := billingPeriod(at, st.win.billingDay)
	rec := persistedSample{store: c.store}
	if c.store == nil || len(st.win.samples) == 0 {
		return rec
	}
	rec.oldest = st.win.samples[0].at
	rec.sample = plugin.UsageSample{
		Provider:    st.spec.name,
		Host:        st.spec.host,
		Interface:   st.spec.iface,
		PeriodStart: start,
		PeriodEnd:   end,
		At:          at.UTC(),
		InBps:       inBps,
		OutBps:      outBps,
	}
	return rec
}

func (c *Collector) persist(rec persistedSample) {
	if rec.store == nil || rec.sample.Provider == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sampleStoreTimeout)
	defer cancel()
	if err := rec.store.PutUsageSamples(ctx, []plugin.UsageSample{rec.sample}); err != nil {
		c.log.Warn("snmp sample persist", "provider", rec.sample.Provider, "err", err)
		return
	}
	// A sample taken earlier than the oldest one memory kept is a clock
	// step backwards. Leave the file alone; the next forward sample trims.
	if rec.oldest.IsZero() || rec.sample.At.Before(rec.oldest) {
		return
	}
	if err := rec.store.TrimUsageSamples(ctx, rec.sample.Provider, rec.sample.Host, rec.sample.Interface, rec.sample.PeriodStart, rec.sample.PeriodEnd, rec.oldest); err != nil {
		c.log.Warn("snmp sample trim", "provider", rec.sample.Provider, "err", err)
	}
}

// addSample records one rate the way a successful poll does, including
// the store. Tests use it so they do not open a socket.
func (c *Collector) addSample(provider string, at time.Time, inBps, outBps float64) {
	at = at.UTC()
	c.mu.Lock()
	st := c.states[provider]
	st.win.add(at, inBps, outBps)
	st.lastIn = inBps / 1e6
	st.lastOut = outBps / 1e6
	st.updated = at
	st.err = ""
	rec := c.sampleRecord(st, at, inBps, outBps)
	c.mu.Unlock()
	c.persist(rec)
}
