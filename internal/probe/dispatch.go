package probe

import "sync"

// dispatcher hands jobs to workers so one provider cannot hold every
// worker (#381). A provider whose hosts time out keeps its workers for the
// whole timeout; handing the next job to the provider with the fewest jobs
// in flight leaves the other workers to the other providers. When only one
// provider has work left it may take them all, so the split never idles a
// worker.
type dispatcher struct {
	mu       sync.Mutex
	queued   map[string][]queuedJob // per provider, in priority order
	inflight map[string]int
	names    []string
	// replied and silent count, per provider, this round's finished jobs
	// that got a reply and those that got none (#381).
	replied map[string]int
	silent  map[string]int
	// silentBefore marks providers whose last round with a finished job
	// got no reply on any job.
	silentBefore map[string]bool
}

type queuedJob struct {
	seq int // position in the priority order of the whole round
	job job
}

func newDispatcher(jobs []job, silentBefore map[string]bool) *dispatcher {
	d := &dispatcher{queued: map[string][]queuedJob{}, inflight: map[string]int{},
		replied: map[string]int{}, silent: map[string]int{}, silentBefore: silentBefore}
	for i, j := range jobs {
		n := j.provider.Name
		if _, ok := d.queued[n]; !ok {
			d.names = append(d.names, n)
		}
		d.queued[n] = append(d.queued[n], queuedJob{seq: i, job: j})
	}
	return d
}

// next returns the next job and counts it in flight; the caller passes it
// to done when it finishes. The provider with the fewest jobs in flight
// goes first. On a tie, the provider whose next job ranks first does.
func (d *dispatcher) next() (job, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	best := ""
	for _, n := range d.names {
		q := d.queued[n]
		if len(q) == 0 {
			continue
		}
		if best == "" || d.inflight[n] < d.inflight[best] ||
			(d.inflight[n] == d.inflight[best] && q[0].seq < d.queued[best][0].seq) {
			best = n
		}
	}
	if best == "" {
		return job{}, false
	}
	q := d.queued[best]
	d.queued[best] = q[1:]
	d.inflight[best]++
	return q[0].job, true
}

// done records that j finished; replied is whether any of its hosts
// answered.
func (d *dispatcher) done(j job, replied bool) {
	d.mu.Lock()
	n := j.provider.Name
	d.inflight[n]--
	if replied {
		d.replied[n]++
	} else {
		d.silent[n]++
	}
	d.mu.Unlock()
}

// looksDown reports whether provider got no reply in its last round, and
// has finished a job this round with none of its finished jobs getting a
// reply. A healthy provider whose first jobs in a round hit silent
// prefixes got a reply in the round before, so it does not look down.
func (d *dispatcher) looksDown(provider string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.silentBefore[provider] && d.silent[provider] > 0 && d.replied[provider] == 0
}

// silentProviders returns, for each provider that finished a job this
// round, whether none of its finished jobs got a reply.
func (d *dispatcher) silentProviders() map[string]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]bool{}
	for n := range d.silent {
		out[n] = true
	}
	for n := range d.replied {
		out[n] = false
	}
	return out
}
