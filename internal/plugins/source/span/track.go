package span

import (
	"net/netip"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/passive"
)

// flowKey is one TCP connection, oriented local to remote.
type flowKey struct {
	local, remote netip.AddrPort
}

// flowState is what the tracker remembers about one connection: handshake
// timestamps, the next outbound sequence number, and whether the remote
// already reset it. No payload is kept.
type flowState struct {
	prefix netip.Prefix
	last   time.Time

	// A local SYN waiting for the remote SYN-ACK (outbound connection).
	synAt      time.Time
	synPending bool
	synRetx    bool

	// A local SYN-ACK waiting for the remote ACK (inbound connection).
	synAckAt      time.Time
	synAckPending bool
	synAckRetx    bool

	haveSeq bool
	nextSeq uint32
}

// tracker follows TCP connections between local and remote addresses and
// adds problem deltas to a passive.Window. It holds at most maxFlows
// connections; a new connection beyond that is not tracked.
type tracker struct {
	mu         sync.Mutex
	local      []netip.Prefix
	keep       func(netip.Addr) bool
	prefixFor  func(netip.Addr) netip.Prefix
	win        *passive.Window
	synTimeout time.Duration
	idle       time.Duration
	maxFlows   int

	flows     map[flowKey]*flowState
	lastSweep time.Time
	dropped   uint64
}

// sweepEvery bounds how often packet processing expires flows.
const sweepEvery = time.Second

// seqLT is sequence-space a < b (RFC 1982 style, 32-bit wrap).
func seqLT(a, b uint32) bool { return int32(a-b) < 0 }

// seqLE is sequence-space a <= b.
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }

// observe processes one segment captured at time at.
func (t *tracker) observe(at time.Time, s segment) {
	src, dst := s.src.Unmap(), s.dst.Unmap()
	srcLocal, dstLocal := passive.Contains(t.local, src), passive.Contains(t.local, dst)
	var key flowKey
	var out bool
	switch {
	case srcLocal && !dstLocal:
		key = flowKey{netip.AddrPortFrom(src, s.sport), netip.AddrPortFrom(dst, s.dport)}
		out = true
	case dstLocal && !srcLocal:
		key = flowKey{netip.AddrPortFrom(dst, s.dport), netip.AddrPortFrom(src, s.sport)}
	default:
		return
	}
	remote := key.remote.Addr()
	if !t.keep(remote) {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if at.Sub(t.lastSweep) >= sweepEvery {
		t.sweepLocked(at)
	}

	var d passive.Counts
	st := t.flows[key]
	if st == nil {
		// A stray RST or ACK for a connection we never saw is not a new
		// connection worth tracking.
		if s.flags&flagRST != 0 {
			return
		}
		if len(t.flows) >= t.maxFlows {
			t.dropped++
			return
		}
		p := t.prefixFor(remote)
		if !p.IsValid() || !p.Contains(remote) {
			return
		}
		st = &flowState{prefix: p}
		t.flows[key] = st
		d.Flows = 1
	}
	st.last = at
	syn, ack, rst := s.flags&flagSYN != 0, s.flags&flagACK != 0, s.flags&flagRST != 0

	if out {
		switch {
		case rst:
			// The local side aborted. That is not a path problem.
			delete(t.flows, key)
		case syn && !ack:
			if st.synPending || st.synRetx {
				st.synRetx = true
			} else {
				st.synAt, st.synPending = at, true
			}
			st.haveSeq, st.nextSeq = true, s.seq+1
		case syn && ack:
			if st.synAckPending || st.synAckRetx {
				st.synAckRetx = true
			} else {
				st.synAckAt, st.synAckPending = at, true
			}
			st.haveSeq, st.nextSeq = true, s.seq+1
		case s.payload > 0:
			d.Segments = 1
			end := s.seq + s.payload
			switch {
			case !st.haveSeq:
				st.haveSeq, st.nextSeq = true, end
			case seqLE(end, st.nextSeq):
				// A one-byte keepalive probe repeats the last byte on
				// purpose; do not call it a retransmission.
				if !(s.payload == 1 && end == st.nextSeq) {
					d.Retrans = 1
				}
			default:
				if seqLT(s.seq, st.nextSeq) {
					d.Retrans = 1
				}
				st.nextSeq = end
			}
		}
	} else {
		switch {
		case rst:
			d.Resets = 1
			delete(t.flows, key)
		case syn && ack:
			if st.synPending {
				if !st.synRetx {
					d.RTTSamples, d.RTTSum = 1, at.Sub(st.synAt)
				}
				st.synPending = false
			}
		case ack && st.synAckPending:
			if !st.synAckRetx {
				d.RTTSamples, d.RTTSum = 1, at.Sub(st.synAckAt)
			}
			st.synAckPending = false
		}
	}
	if d != (passive.Counts{}) {
		t.win.Add(at, st.prefix, remote, d)
	}
}

// sweep counts handshakes that timed out and forgets idle connections.
func (t *tracker) sweep(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now)
}

func (t *tracker) sweepLocked(now time.Time) {
	t.lastSweep = now
	for k, st := range t.flows {
		var d passive.Counts
		// A timed-out handshake is marked retransmitted so a late SYN or
		// SYN-ACK neither counts a second timeout nor yields an RTT.
		if st.synPending && now.Sub(st.synAt) >= t.synTimeout {
			st.synPending, st.synRetx = false, true
			d.Timeouts++
		}
		if st.synAckPending && now.Sub(st.synAckAt) >= t.synTimeout {
			st.synAckPending, st.synAckRetx = false, true
			d.Timeouts++
		}
		if d.Timeouts > 0 {
			t.win.Add(now, st.prefix, k.remote.Addr(), d)
		}
		if now.Sub(st.last) >= t.idle {
			delete(t.flows, k)
		}
	}
}

// size is the number of tracked connections.
func (t *tracker) size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}
