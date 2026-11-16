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
// (by the kernel timestamp of the SYN or SYN-ACK).
type connState struct {
	ebpfpath.Counters
	synAt, synAckAt uint64
	touched         time.Time
}

// kernelRun reads summaries until the source stops.
func (s *Source) kernelRun(ctx context.Context, kt kernelTracker) {
	defer s.wg.Done()
	defer kt.close()
	for !s.stopped(ctx) {
		sum, err := kt.next()
		if err != nil {
			if errors.Is(err, errReadTimeout) {
				continue
			}
			s.log.Warn("span eBPF tracker stopped", "interface", s.iface, "err", err)
			return
		}
		s.kmu.Lock()
		s.account(s.now(), sum.Key, sum.Counters, sum.Final)
		s.kmu.Unlock()
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
	if final {
		delete(s.conns, key)
	}
}

// kernelSweep reads the connection table. It scores the counts no summary
// has carried yet, counts handshakes that timed out once each (the kernel
// has no timer), and removes connections that went idle.
func (s *Source) kernelSweep(now time.Time, kt kernelTracker) {
	states, err := kt.flows()
	if err != nil {
		s.log.Warn("span eBPF connection table unreadable", "err", err)
		return
	}
	s.kmu.Lock()
	defer s.kmu.Unlock()
	for _, st := range states {
		if st.Idle >= s.trk.idle {
			s.account(now, st.Key, st.Counters, false)
			_ = kt.forget(st.Key)
			delete(s.conns, st.Key)
			continue
		}
		s.account(now, st.Key, st.Counters, false)
		cs := s.conns[st.Key]
		if cs == nil {
			continue
		}
		var timeouts uint64
		if st.SynAt != 0 && st.SynAge >= s.trk.synTimeout && cs.synAt != st.SynAt {
			cs.synAt = st.SynAt
			timeouts++
		}
		if st.SynAckAt != 0 && st.SynAckAge >= s.trk.synTimeout && cs.synAckAt != st.SynAckAt {
			cs.synAckAt = st.SynAckAt
			timeouts++
		}
		if timeouts > 0 {
			remote := st.Key.Remote.Addr()
			if p := s.prefixFor(remote); p.IsValid() && p.Contains(remote) {
				s.win.Add(now, p, remote, passive.Counts{Timeouts: timeouts})
			}
		}
	}
	// A connection the kernel forgot with a RST keeps no entry; one that
	// never reports again and left the table without a summary expires here.
	for k, cs := range s.conns {
		if now.Sub(cs.touched) >= s.trk.idle {
			delete(s.conns, k)
		}
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
