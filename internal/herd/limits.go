package herd

import (
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Trips counts every limit that fired, by limit name and peer key id (empty
// when the peer is not known yet), for metrics and the status API. The set
// is bounded by the limit names and the pinned peers.
type Trips struct {
	mu sync.Mutex
	m  map[Trip]uint64
}

// Trip is one limit and the peer it fired for.
type Trip struct {
	Limit string `json:"limit"`
	Peer  string `json:"peer,omitempty"`
}

// TripCount is a Trip with its count.
type TripCount struct {
	Trip
	Count uint64 `json:"count"`
}

// Add counts one trip.
func (t *Trips) Add(limit, peer string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[Trip]uint64{}
	}
	t.m[Trip{limit, peer}]++
}

// Snapshot returns the counts, sorted.
func (t *Trips) Snapshot() []TripCount {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TripCount, 0, len(t.m))
	for k, n := range t.m {
		out = append(out, TripCount{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Limit != out[j].Limit {
			return out[i].Limit < out[j].Limit
		}
		return out[i].Peer < out[j].Peer
	})
	return out
}

// maxCost is the most one request costs: covering and covered prefix
// queries cost this many exact ones.
const maxCost = 4

const maxLimiterKeys = 4096

// limiterSet is a token bucket per key, refilled over a minute. A bucket
// holds one minute of budget, so a client may spend it at once and then waits.
type limiterSet struct {
	mu     sync.Mutex
	perMin int
	m      map[string]*limiterEntry
}

type limiterEntry struct {
	lim  *rate.Limiter
	seen time.Time
	// pinned is set once a connection from this key completed a pinned
	// handshake; churn from unknown keys evicts the entry last.
	pinned bool
}

func newLimiterSet(perMin int) *limiterSet {
	return &limiterSet{perMin: perMin, m: map[string]*limiterEntry{}}
}

// reserve takes n tokens for key at now. When the key is over budget it
// takes nothing and returns how long to wait.
func (l *limiterSet) reserve(key string, n int, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil {
		if len(l.m) >= maxLimiterKeys {
			l.evict(now)
		}
		e = &limiterEntry{lim: rate.NewLimiter(rate.Limit(float64(l.perMin)/60), max(l.perMin, maxCost))}
		l.m[key] = e
	}
	e.seen = now
	r := e.lim.ReserveN(now, n)
	if !r.OK() {
		return false, time.Minute
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// markPinned records that key completed a pinned handshake.
func (l *limiterSet) markPinned(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e := l.m[key]; e != nil {
		e.pinned = true
	}
}

// evict makes room for one key. Entries idle past the time a bucket takes
// to refill (max(perMin, maxCost) / perMin minutes) hold a full bucket, so
// dropping them changes nothing. Otherwise the least recently
// seen entry goes, preferring one without a pinned handshake. A new key is
// never refused for want of room: many source addresses must not lock out
// a pinned peer that connects from a new one (#506).
func (l *limiterSet) evict(now time.Time) {
	refill := time.Duration(float64(max(l.perMin, maxCost)) / float64(l.perMin) * float64(time.Minute))
	for k, e := range l.m {
		if now.Sub(e.seen) > refill {
			delete(l.m, k)
		}
	}
	if len(l.m) < maxLimiterKeys {
		return
	}
	var victim string
	var v *limiterEntry
	for k, e := range l.m {
		if v == nil || (v.pinned && !e.pinned) || (v.pinned == e.pinned && e.seen.Before(v.seen)) {
			victim, v = k, e
		}
	}
	delete(l.m, victim)
}

// retryAfter is the Retry-After header value for a wait.
func retryAfter(d time.Duration) int {
	return max(1, int((d+time.Second-1)/time.Second))
}
