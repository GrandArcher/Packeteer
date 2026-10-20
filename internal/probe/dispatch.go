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
}

type queuedJob struct {
	seq int // position in the priority order of the whole round
	job job
}

func newDispatcher(jobs []job) *dispatcher {
	d := &dispatcher{queued: map[string][]queuedJob{}, inflight: map[string]int{}}
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

func (d *dispatcher) done(j job) {
	d.mu.Lock()
	d.inflight[j.provider.Name]--
	d.mu.Unlock()
}
