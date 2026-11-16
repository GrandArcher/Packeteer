package span

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath"
	"github.com/GrandArcher/Packeteer/internal/passive"
)

// fakeKernel stands in for the eBPF tracker: it hands out queued summaries
// and serves a fixed connection table.
type fakeKernel struct {
	mu     sync.Mutex
	sums   []ebpfpath.Summary
	states []ebpfpath.TrackState
	forgot []ebpfpath.TrackKey
	ring   uint64
	full   uint64
	closed bool
	err    error // returned by next, like a ring buffer that went away
}

func (f *fakeKernel) next() (ebpfpath.Summary, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return ebpfpath.Summary{}, f.err
	}
	if len(f.sums) == 0 {
		f.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		f.mu.Lock()
		return ebpfpath.Summary{}, errReadTimeout
	}
	s := f.sums[0]
	f.sums = f.sums[1:]
	return s, nil
}

func (f *fakeKernel) flows() ([]ebpfpath.TrackState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ebpfpath.TrackState(nil), f.states...), nil
}

func (f *fakeKernel) forget(k ebpfpath.TrackKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forgot = append(f.forgot, k)
	for i, st := range f.states {
		if st.Key == k {
			f.states = append(f.states[:i], f.states[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeKernel) drops() (uint64, uint64) { return f.ring, f.full }

func (f *fakeKernel) close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeKernel) queue(s ...ebpfpath.Summary) {
	f.mu.Lock()
	f.sums = append(f.sums, s...)
	f.mu.Unlock()
}

func (f *fakeKernel) drained() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sums) == 0
}

func tkey(lport uint16, remote string) ebpfpath.TrackKey {
	return ebpfpath.TrackKey{
		Local:  netip.AddrPortFrom(localV4, lport),
		Remote: netip.AddrPortFrom(netip.MustParseAddr(remote), 443),
	}
}

func startKernelSource(t *testing.T, fk *fakeKernel, extra string) *Source {
	t.Helper()
	s := mustSource(t, baseYAML+"ebpf: true\nebpf_track: true\n"+extra)
	s.openKernel = func(o ebpfpath.TrackOptions) (kernelTracker, error) {
		if o.Interface != "eth1" || !o.Promisc || len(o.Local) != 2 || o.SYNTimeout != DefaultSYNTimeout || o.MaxFlows != DefaultMaxFlows {
			t.Errorf("tracker options = %+v", o)
		}
		return fk, nil
	}
	s.openEBPF = func(string, bool, time.Duration) (capture, error) {
		t.Error("the capture path opened although the kernel tracker loaded")
		return nil, errors.New("unexpected")
	}
	s.openRaw = s.openEBPF
	return startSource(t, s)
}

func waitDrained(t *testing.T, fk *fakeKernel) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !fk.drained() {
		if time.Now().After(deadline) {
			t.Fatal("summaries were not read")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// next returns a summary before it is scored; a window total read now
	// could miss the last one.
	time.Sleep(20 * time.Millisecond)
}

func prefixTotals(s *Source, p string) passive.Counts {
	return s.win.Totals(s.now())[netip.MustParsePrefix(p)].Counts
}

func TestKernelTrackerSummariesAreScored(t *testing.T) {
	fk := &fakeKernel{}
	s := startKernelSource(t, fk, "")
	a := tkey(40000, "198.51.100.10")
	cA := ebpfpath.Counters{Created: 7, Segments: 10, Retrans: 2, RTTSamples: 1, RTTSum: 40 * time.Millisecond}
	fk.queue(
		ebpfpath.Summary{Key: a, Counters: ebpfpath.Counters{Created: 7}},
		ebpfpath.Summary{Key: a, Counters: ebpfpath.Counters{Created: 7, Segments: 4, Retrans: 1}},
		ebpfpath.Summary{Key: a, Counters: cA},
		// The same counters again, as a table read after a summary gives
		// them, add nothing.
		ebpfpath.Summary{Key: a, Counters: cA},
		// Another connection to the same prefix, reset.
		ebpfpath.Summary{Key: tkey(40001, "198.51.100.11"), Counters: ebpfpath.Counters{Created: 8, Segments: 5, Resets: 1}, Final: true},
		// Not a probe target: private remote.
		ebpfpath.Summary{Key: tkey(40002, "10.0.0.5"), Counters: ebpfpath.Counters{Created: 9, Segments: 50}},
	)
	waitDrained(t, fk)
	got := prefixTotals(s, "198.51.100.0/24")
	want := passive.Counts{Flows: 2, Segments: 15, Retrans: 2, Resets: 1, RTTSamples: 1, RTTSum: 40 * time.Millisecond}
	if got != want {
		t.Fatalf("totals = %+v, want %+v", got, want)
	}
	if n := len(s.win.Totals(s.now())); n != 1 {
		t.Fatalf("%d prefixes scored, want only 198.51.100.0/24", n)
	}
	s.kmu.Lock()
	reset := s.conns[tkey(40001, "198.51.100.11")]
	s.kmu.Unlock()
	if reset == nil || !reset.final {
		t.Fatalf("the reset connection is %+v, want a tombstone", reset)
	}

	// The same 4-tuple with a new Created is a new connection.
	fk.queue(ebpfpath.Summary{Key: a, Counters: ebpfpath.Counters{Created: 99, Segments: 3}})
	waitDrained(t, fk)
	got = prefixTotals(s, "198.51.100.0/24")
	if got.Flows != 3 || got.Segments != 18 {
		t.Fatalf("after a reused 4-tuple: flows %d segments %d, want 3 and 18", got.Flows, got.Segments)
	}
}

func TestKernelSweepCountsTimeoutsOnceAndScoresTails(t *testing.T) {
	fk := &fakeKernel{}
	s := startKernelSource(t, fk, "")
	a, b := tkey(40000, "203.0.113.20"), tkey(40001, "203.0.113.21")
	set := func(st ...ebpfpath.TrackState) {
		fk.mu.Lock()
		fk.states = st
		fk.mu.Unlock()
	}
	// A: SYN pending for 5s (past the 3s timeout), with segments no summary
	// has carried. B: SYN-ACK pending for 1s, not yet timed out.
	set(
		ebpfpath.TrackState{Key: a, Counters: ebpfpath.Counters{Created: 1, Segments: 8}, SynAt: 100, SynAge: 5 * time.Second},
		ebpfpath.TrackState{Key: b, Counters: ebpfpath.Counters{Created: 2}, SynAckAt: 200, SynAckAge: time.Second},
	)
	s.sweep(s.now())
	s.sweep(s.now())
	got := prefixTotals(s, "203.0.113.0/24")
	if got.Timeouts != 1 || got.Segments != 8 || got.Flows != 2 {
		t.Fatalf("after two sweeps: %+v, want 1 timeout, 8 segments, 2 flows", got)
	}
	// B's SYN-ACK times out; A is answered and sends a new SYN later.
	set(
		ebpfpath.TrackState{Key: a, Counters: ebpfpath.Counters{Created: 1, Segments: 8}, SynAt: 300, SynAge: 4 * time.Second},
		ebpfpath.TrackState{Key: b, Counters: ebpfpath.Counters{Created: 2}, SynAckAt: 200, SynAckAge: 4 * time.Second},
	)
	s.sweep(s.now())
	s.sweep(s.now())
	if got := prefixTotals(s, "203.0.113.0/24"); got.Timeouts != 3 {
		t.Fatalf("timeouts = %d, want 3: A's first SYN, B's SYN-ACK, A's second SYN", got.Timeouts)
	}
}

func TestKernelSweepForgetsIdleConnections(t *testing.T) {
	fk := &fakeKernel{}
	s := startKernelSource(t, fk, "")
	a, b := tkey(40000, "203.0.113.20"), tkey(40001, "203.0.113.21")
	fk.mu.Lock()
	fk.states = []ebpfpath.TrackState{
		{Key: a, Counters: ebpfpath.Counters{Created: 1, Segments: 3}, Idle: 3 * time.Minute},
		{Key: b, Counters: ebpfpath.Counters{Created: 2, Segments: 4}, Idle: time.Second},
	}
	fk.mu.Unlock()
	s.sweep(s.now())
	fk.mu.Lock()
	forgot := append([]ebpfpath.TrackKey(nil), fk.forgot...)
	fk.mu.Unlock()
	if len(forgot) != 1 || forgot[0] != a {
		t.Fatalf("forgot %v, want only the idle connection", forgot)
	}
	// The idle connection's last counts are scored before it goes.
	if got := prefixTotals(s, "203.0.113.0/24"); got.Segments != 7 || got.Flows != 2 {
		t.Fatalf("totals = %+v, want 7 segments in 2 flows", got)
	}
	// A second sweep that read the table before the first forgot the
	// connection scores nothing again, and its pending handshake is not a
	// second timeout.
	stale := ebpfpath.TrackState{Key: a, Counters: ebpfpath.Counters{Created: 1, Segments: 3}, Idle: 3 * time.Minute, SynAt: 50, SynAge: time.Minute}
	s.kmu.Lock()
	s.account(s.now(), stale.Key, stale.Counters, false)
	if cs := s.conns[stale.Key]; cs != nil && !cs.final {
		s.timeouts(s.now(), stale, cs)
	}
	s.kmu.Unlock()
	if got := prefixTotals(s, "203.0.113.0/24"); got.Segments != 7 || got.Flows != 2 || got.Timeouts != 0 {
		t.Fatalf("after the stale read: %+v, want 7 segments, 2 flows, no timeout", got)
	}
}

func TestKernelTrackerDropsAreReported(t *testing.T) {
	fk := &fakeKernel{ring: 4, full: 3}
	s := startKernelSource(t, fk, "")
	got := s.Truncated()
	if got["ebpf_ring_full"] != 4 || got["max_flows"] != 3 {
		t.Fatalf("truncated = %v", got)
	}
}

func TestKernelTrackerFallsBackToUserspaceTracker(t *testing.T) {
	fc := &fakeCapture{frames: retransFrames()}
	s := mustSource(t, baseYAML+"ebpf: true\nebpf_track: true\n")
	kernelCalls := 0
	s.openKernel = func(ebpfpath.TrackOptions) (kernelTracker, error) {
		kernelCalls++
		return nil, errors.New("attach TCX: operation not supported")
	}
	s.openEBPF = func(string, bool, time.Duration) (capture, error) { return fc, nil }
	s.openRaw = func(string, bool, time.Duration) (capture, error) {
		t.Error("AF_PACKET opened although the eBPF capture loaded")
		return nil, errors.New("unexpected")
	}
	startSource(t, s)
	waitRetrans(t, s)
	if kernelCalls != 1 || s.kt != nil {
		t.Fatalf("kernel tracker tried %d times, kt=%v", kernelCalls, s.kt)
	}
}

func TestKernelTrackerOffNeverTriesIt(t *testing.T) {
	fc := &fakeCapture{frames: retransFrames()}
	s := mustSource(t, baseYAML+"ebpf: true\n")
	s.openKernel = func(ebpfpath.TrackOptions) (kernelTracker, error) {
		t.Error("kernel tracker tried although ebpf_track is off")
		return nil, errors.New("unexpected")
	}
	s.openEBPF = func(string, bool, time.Duration) (capture, error) { return fc, nil }
	startSource(t, s)
	waitRetrans(t, s)
}

func TestKernelTrackerNeedsEBPF(t *testing.T) {
	for _, y := range []string{
		baseYAML + "ebpf_track: true\n",
		"pcap_file: /var/lib/packeteer/x.pcap\nebpf_track: true\nlocal: [192.0.2.0/24]\n",
	} {
		_, err := build(y)
		if err == nil || !strings.Contains(err.Error(), "ebpf_track requires ebpf: true") {
			t.Errorf("%q: err = %v", y, err)
		}
	}
	if _, err := build(baseYAML + "ebpf: true\nebpf_track: true\n"); err != nil {
		t.Fatal(err)
	}
}

// A handshake that is still pending when its connection goes idle is a
// timeout: the table read counts it before it forgets the connection.
func TestKernelSweepCountsTimeoutOfIdleConnection(t *testing.T) {
	fk := &fakeKernel{}
	s := startKernelSource(t, fk, "")
	fk.mu.Lock()
	fk.states = []ebpfpath.TrackState{{
		Key: tkey(40000, "203.0.113.20"), Counters: ebpfpath.Counters{Created: 1},
		SynAt: 100, SynAge: 3 * time.Minute, Idle: 3 * time.Minute,
	}}
	fk.mu.Unlock()
	s.sweep(s.now())
	if got := prefixTotals(s, "203.0.113.0/24"); got.Timeouts != 1 || got.Flows != 1 {
		t.Fatalf("totals = %+v, want 1 timeout in 1 flow", got)
	}
}

// A table read taken before the kernel forgot a reset connection arrives
// after its final summary and must not score the connection again.
func TestKernelStaleTableReadAfterFinalSummaryAddsNothing(t *testing.T) {
	fk := &fakeKernel{}
	s := startKernelSource(t, fk, "")
	a := tkey(40000, "198.51.100.10")
	c := ebpfpath.Counters{Created: 7, Segments: 10, Resets: 1}
	fk.queue(ebpfpath.Summary{Key: a, Counters: c, Final: true})
	waitDrained(t, fk)
	fk.mu.Lock()
	fk.states = []ebpfpath.TrackState{{Key: a, Counters: c, SynAt: 5, SynAge: time.Minute}}
	fk.mu.Unlock()
	s.sweep(s.now())
	want := passive.Counts{Flows: 1, Segments: 10, Resets: 1}
	if got := prefixTotals(s, "198.51.100.0/24"); got != want {
		t.Fatalf("totals = %+v, want %+v (no second flow, no timeout for a reset connection)", got, want)
	}
}

// The source reads the table on its own every second, so timeouts show up
// without a probe round asking for them.
func TestKernelRunSweepsTheTable(t *testing.T) {
	fk := &fakeKernel{}
	s := startKernelSource(t, fk, "")
	fk.mu.Lock()
	fk.states = []ebpfpath.TrackState{{Key: tkey(40000, "203.0.113.20"), Counters: ebpfpath.Counters{Created: 1}, SynAt: 9, SynAge: 5 * time.Second}}
	fk.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for prefixTotals(s, "203.0.113.0/24").Timeouts != 1 {
		if time.Now().After(deadline) {
			t.Fatal("the timeout was not counted without a sweep request")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// When the ring buffer fails, the tracker is closed and the source stops
// using it.
func TestKernelTrackerFailureClosesIt(t *testing.T) {
	fk := &fakeKernel{ring: 2}
	s := startKernelSource(t, fk, "")
	fk.mu.Lock()
	fk.err = errors.New("ring buffer closed")
	fk.mu.Unlock()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.capMu.Lock()
		gone := s.kt == nil
		s.capMu.Unlock()
		fk.mu.Lock()
		closed := fk.closed
		fk.mu.Unlock()
		if gone && closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("kt cleared=%v closed=%v", gone, closed)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, ok := s.Truncated()["ebpf_ring_full"]; ok {
		t.Fatal("drop counters of a closed tracker still reported")
	}
}
