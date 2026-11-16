package span

import (
	"context"
	"errors"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath"
	"github.com/GrandArcher/Packeteer/internal/passive"
)

// kernelTracker is the eBPF connection tracker (#631): the kernel follows
// the TCP connections and reports count deltas per remote address. What it
// cannot do without a timer (SYN timeouts, expiry of idle connections) the
// source does by reading the connection table.
type kernelTracker interface {
	next() (ebpfpath.Summary, error)
	flows() ([]ebpfpath.TrackState, error)
	forget(ebpfpath.TrackKey) error
	drops() (ring, flows uint64)
	close() error
}

type ebpfTracker struct{ t *ebpfpath.Tracker }

func (e ebpfTracker) next() (ebpfpath.Summary, error) {
	s, err := e.t.Next()
	if errors.Is(err, ebpfpath.ErrTimeout) {
		return s, errReadTimeout
	}
	return s, err
}

func (e ebpfTracker) flows() ([]ebpfpath.TrackState, error) { return e.t.Flows() }
func (e ebpfTracker) forget(k ebpfpath.TrackKey) error      { return e.t.Forget(k) }
func (e ebpfTracker) close() error                          { return e.t.Close() }

func (e ebpfTracker) drops() (ring, flows uint64) {
	ring, flows, _ = e.t.Drops()
	return ring, flows
}

func openKernelTracker(o ebpfpath.TrackOptions) (kernelTracker, error) {
	t, err := ebpfpath.OpenTracker(o)
	if err != nil {
		return nil, err
	}
	return ebpfTracker{t}, nil
}

// connState is what userspace remembers of a connection the kernel tracks:
// the counters already scored, and the handshake timeouts already counted
// (by the kernel timestamp of the SYN or SYN-ACK). A final connection, one
// the kernel or the sweep forgot, is kept as a tombstone for finalHold: a
// table read taken before it was forgotten can still arrive, and must not
// score it again.
type connState struct {
	ebpfpath.Counters
	synAt, synAckAt uint64
	touched         time.Time
	final           bool
}

const finalHold = 10 * time.Second

// kernelRun reads summaries until the source stops, and reads the
// connection table every sweepEvery, as the userspace tracker sweeps while
// packets arrive.
func (s *Source) kernelRun(ctx context.Context, kt kernelTracker) {
	defer s.wg.Done()
	defer func() {
		s.capMu.Lock()
		s.kt = nil
		s.capMu.Unlock()
		_ = kt.close()
	}()
	lastSweep := s.now()
	for !s.stopped(ctx) {
		sum, err := kt.next()
		switch {
		case errors.Is(err, errReadTimeout):
		case err != nil:
			s.log.Warn("span eBPF tracker stopped", "interface", s.iface, "err", err)
			return
		default:
			s.kmu.Lock()
			s.account(s.now(), sum.Key, sum.Counters, sum.Final)
			s.kmu.Unlock()
		}
		if now := s.now(); now.Sub(lastSweep) >= sweepEvery {
			lastSweep = now
			s.kernelSweep(now, kt)
		}
	}
}

// account scores what a connection's counters gained since the last time
// they were seen, with the same remote filter, prefix, and counters as the
// userspace tracker. A summary and a table read can arrive in either order:
// a counter that did not grow adds nothing. kmu is held.
func (s *Source) account(at time.Time, key ebpfpath.TrackKey, c ebpfpath.Counters, final bool) {
	remote := key.Remote.Addr()
	if !s.keep(remote) {
		return
	}
	p := s.prefixFor(remote)
	if !p.IsValid() || !p.Contains(remote) {
		return
	}
	cs := s.conns[key]
	if cs != nil && cs.final && cs.Created == c.Created {
		return
	}
	var d passive.Counts
	if cs == nil || cs.Created != c.Created {
		cs = &connState{Counters: ebpfpath.Counters{Created: c.Created}}
		s.conns[key] = cs
		d.Flows = 1
	}
	cs.touched = at
	grow := func(now uint64, seen *uint64) uint64 {
		if now <= *seen {
			return 0
		}
		g := now - *seen
		*seen = now
		return g
	}
	d.Segments = grow(c.Segments, &cs.Segments)
	d.Retrans = grow(c.Retrans, &cs.Retrans)
	d.Resets = grow(c.Resets, &cs.Resets)
	d.RTTSamples = grow(c.RTTSamples, &cs.RTTSamples)
	sum := uint64(cs.RTTSum)
	d.RTTSum = time.Duration(grow(uint64(c.RTTSum), &sum))
	cs.RTTSum = time.Duration(sum)
	if d != (passive.Counts{}) {
		s.win.Add(at, p, remote, d)
	}
	cs.final = final
}

// kernelSweep reads the connection table. It scores the counts no summary
// has carried yet, counts handshakes that timed out once each (the kernel
// has no timer), and removes connections that went idle. A handshake
// answered after syn_timeout and before the read is counted as neither a
// timeout nor an RTT, as in the userspace tracker between its sweeps.
func (s *Source) kernelSweep(now time.Time, kt kernelTracker) {
	states, err := kt.flows()
	if err != nil {
		s.log.Warn("span eBPF connection table unreadable", "err", err)
		return
	}
	s.kmu.Lock()
	defer s.kmu.Unlock()
	for _, st := range states {
		s.account(now, st.Key, st.Counters, false)
		if cs := s.conns[st.Key]; cs != nil && !cs.final {
			s.timeouts(now, st, cs)
		}
		if st.Idle >= s.trk.idle {
			_ = kt.forget(st.Key)
			// Two sweeps can hold the same table read; the second must
			// not score the forgotten connection again.
			if cs := s.conns[st.Key]; cs != nil {
				cs.final, cs.touched = true, now
			}
		}
	}
	// Entries of connections that left the table without a summary, and
	// tombstones, expire here.
	for k, cs := range s.conns {
		ttl := s.trk.idle
		if cs.final {
			ttl = finalHold
		}
		if now.Sub(cs.touched) >= ttl {
			delete(s.conns, k)
		}
	}
}

// timeouts counts the handshakes of st that outlived syn_timeout and were
// not counted yet. kmu is held.
func (s *Source) timeouts(now time.Time, st ebpfpath.TrackState, cs *connState) {
	var n uint64
	if st.SynAt != 0 && st.SynAge >= s.trk.synTimeout && cs.synAt != st.SynAt {
		cs.synAt = st.SynAt
		n++
	}
	if st.SynAckAt != 0 && st.SynAckAge >= s.trk.synTimeout && cs.synAckAt != st.SynAckAt {
		cs.synAckAt = st.SynAckAt
		n++
	}
	if n == 0 {
		return
	}
	remote := st.Key.Remote.Addr()
	if p := s.prefixFor(remote); p.IsValid() && p.Contains(remote) {
		s.win.Add(now, p, remote, passive.Counts{Timeouts: n})
	}
}

func (s *Source) trackOptions() ebpfpath.TrackOptions {
	return ebpfpath.TrackOptions{
		Interface:  s.iface,
		Promisc:    s.promisc,
		Local:      s.trk.local,
		SYNTimeout: s.trk.synTimeout,
		MaxFlows:   s.trk.maxFlows,
		Timeout:    readTimeout,
	}
}
