//go:build linux

package ebpfpath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// ErrTimeout means no frame arrived inside the read timeout.
var ErrTimeout = errors.New("read timeout")

const license = "Dual MIT/GPL"

func ethernetIface(name string) (*net.Interface, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", name, err)
	}
	if len(ifi.HardwareAddr) == 0 && ifi.Flags&net.FlagLoopback == 0 {
		return nil, fmt.Errorf("interface %q has no Ethernet header: %w", name, ErrUnsupported)
	}
	return ifi, nil
}

// closers closes everything it holds, newest first.
type closers []io.Closer

func (c closers) Close() error {
	var first error
	for i := len(c) - 1; i >= 0; i-- {
		if err := c[i].Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func attach(prog *ebpf.Program, ifindex int, types ...ebpf.AttachType) (closers, error) {
	var ls closers
	for _, t := range types {
		l, err := link.AttachTCX(link.TCXOptions{Interface: ifindex, Program: prog, Attach: t})
		if err != nil {
			_ = ls.Close()
			return nil, fmt.Errorf("attach TCX (needs Linux 6.6, CAP_BPF and CAP_NET_ADMIN): %w", err)
		}
		ls = append(ls, l)
	}
	return ls, nil
}

// Capture reads TCP frame heads that the capture program copied into a
// ring buffer.
type Capture struct {
	rd      *ringbuf.Reader
	drops   *ebpf.Map
	timeout time.Duration
	rec     ringbuf.Record
	hold    closers
}

// OpenCapture attaches the capture program to both directions of iface.
// With promisc it also joins promiscuous mode through an AF_PACKET socket
// that is never read, so the kernel leaves promiscuous mode when the
// process dies (needs CAP_NET_RAW, as the AF_PACKET path does).
func OpenCapture(iface string, promisc bool, timeout time.Duration) (*Capture, error) {
	ifi, err := ethernetIface(iface)
	if err != nil {
		return nil, err
	}
	var hold closers
	fail := func(err error) (*Capture, error) {
		_ = hold.Close()
		return nil, err
	}
	ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: ringBytes})
	if err != nil {
		return fail(fmt.Errorf("ring buffer: %w", err))
	}
	hold = append(hold, ring)
	drops, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 1})
	if err != nil {
		return fail(fmt.Errorf("drop counter: %w", err))
	}
	hold = append(hold, drops)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		License:      license,
		Instructions: CaptureProgram(ring.FD(), drops.FD()),
	})
	if err != nil {
		return fail(fmt.Errorf("load capture program: %w", err))
	}
	hold = append(hold, prog)
	// Loopback delivers every frame twice, once out and once in, so it is
	// read on ingress only.
	dirs := []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress}
	if ifi.Flags&net.FlagLoopback != 0 {
		dirs = dirs[:1]
	}
	ls, err := attach(prog, ifi.Index, dirs...)
	if err != nil {
		return fail(err)
	}
	hold = append(hold, ls...)
	if promisc {
		p, err := joinPromisc(ifi.Index)
		if err != nil {
			return fail(err)
		}
		hold = append(hold, p)
	}
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		return fail(fmt.Errorf("ring buffer reader: %w", err))
	}
	hold = append(hold, rd)
	return &Capture{rd: rd, drops: drops, timeout: timeout, hold: hold}, nil
}

type fdCloser int

func (f fdCloser) Close() error { return unix.Close(int(f)) }

func joinPromisc(ifindex int) (io.Closer, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("promiscuous mode (needs CAP_NET_RAW): %w", err)
	}
	mreq := unix.PacketMreq{Ifindex: int32(ifindex), Type: unix.PACKET_MR_PROMISC}
	if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("promiscuous mode: %w", err)
	}
	return fdCloser(fd), nil
}

// Read copies one captured frame into buf, truncated to len(buf), and
// returns its length. ErrTimeout means nothing arrived in time.
func (c *Capture) Read(buf []byte) (int, error) {
	for {
		c.rd.SetDeadline(time.Now().Add(c.timeout))
		err := c.rd.ReadInto(&c.rec)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, ErrTimeout
			}
			return 0, err
		}
		frame, ok := Frame(c.rec.RawSample)
		if !ok {
			continue
		}
		return copy(buf, frame), nil
	}
}

// Drops is how many frames the kernel could not queue because the ring
// buffer was full.
func (c *Capture) Drops() (uint64, error) {
	var per []uint64
	if err := c.drops.Lookup(uint32(0), &per); err != nil {
		return 0, err
	}
	var n uint64
	for _, v := range per {
		n += v
	}
	return n, nil
}

// Close detaches the program and frees the maps.
func (c *Capture) Close() error { return c.hold.Close() }

// Flows reads the per-flow counters of the flow program.
type Flows struct {
	m    *ebpf.Map
	hold closers
}

// OpenFlows attaches the flow program to the egress of iface. maxEntries
// bounds the flow map; the kernel evicts the least recently used flow past it.
func OpenFlows(iface string, maxEntries int) (*Flows, error) {
	if maxEntries < MinFlowEntries || maxEntries > MaxFlowEntries {
		return nil, fmt.Errorf("max_entries %d must be between %d and %d", maxEntries, MinFlowEntries, MaxFlowEntries)
	}
	ifi, err := ethernetIface(iface)
	if err != nil {
		return nil, err
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LRUCPUHash, KeySize: KeySize, ValueSize: ValueSize, MaxEntries: uint32(maxEntries)})
	if err != nil {
		return nil, fmt.Errorf("flow map: %w", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: ebpf.SchedCLS, License: license, Instructions: FlowProgram(m.FD())})
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("load flow program: %w", err)
	}
	ls, err := attach(prog, ifi.Index, ebpf.AttachTCXEgress)
	if err != nil {
		_ = prog.Close()
		_ = m.Close()
		return nil, err
	}
	return &Flows{m: m, hold: append(closers{m, prog}, ls...)}, nil
}

type cpuValue struct{ Bytes, Packets uint64 }

// Snapshot returns the cumulative counters of every flow in the map.
func (f *Flows) Snapshot() (map[FlowKey]Totals, error) {
	out := map[FlowKey]Totals{}
	var key [KeySize]byte
	var per []cpuValue
	it := f.m.Iterate()
	for it.Next(&key, &per) {
		k, err := decodeKey(key)
		if err != nil {
			continue
		}
		var t Totals
		for _, v := range per {
			t.Bytes += v.Bytes
			t.Packets += v.Packets
		}
		out[k] = t
	}
	return out, it.Err()
}

// Close detaches the program and frees the map.
func (f *Flows) Close() error { return f.hold.Close() }

// TrackOptions configure OpenTracker.
type TrackOptions struct {
	Interface string
	Promisc   bool
	// Local are the prefixes of the networks the traffic belongs to; the
	// kernel tells the local end of a connection by them.
	Local []netip.Prefix
	// SYNTimeout bounds the handshake round trips the kernel reports.
	SYNTimeout time.Duration
	// MaxFlows bounds the connection table. A new connection past it is
	// not tracked and is counted in Drops.
	MaxFlows int
	// Timeout is how long Next waits for a summary.
	Timeout time.Duration
}

// Tracker reads the connection summaries of the tracker program.
type Tracker struct {
	rd      *ringbuf.Reader
	flows   *ebpf.Map
	drops   *ebpf.Map
	timeout time.Duration
	rec     ringbuf.Record
	hold    closers
}

// OpenTracker attaches the tracker program to both directions of the
// interface, as OpenCapture does.
func OpenTracker(o TrackOptions) (*Tracker, error) {
	if o.MaxFlows < MinTrackFlows || o.MaxFlows > MaxTrackFlows {
		return nil, fmt.Errorf("max_flows %d must be between %d and %d", o.MaxFlows, MinTrackFlows, MaxTrackFlows)
	}
	if len(o.Local) == 0 {
		return nil, errors.New("no local prefixes")
	}
	ifi, err := ethernetIface(o.Interface)
	if err != nil {
		return nil, err
	}
	var hold closers
	fail := func(err error) (*Tracker, error) {
		_ = hold.Close()
		return nil, err
	}
	local, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.LPMTrie, KeySize: LocalKeySize, ValueSize: 4,
		MaxEntries: uint32(len(o.Local)), Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		return fail(fmt.Errorf("local prefix map: %w", err))
	}
	hold = append(hold, local)
	for _, p := range o.Local {
		if err := local.Put(NewLocalKey(p), uint32(1)); err != nil {
			return fail(fmt.Errorf("local prefix %s: %w", p, err))
		}
	}
	flows, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: TrackKeySize, ValueSize: TrackValueSize,
		MaxEntries: uint32(o.MaxFlows), Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		return fail(fmt.Errorf("connection map: %w", err))
	}
	hold = append(hold, flows)
	ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: trackRingBytes})
	if err != nil {
		return fail(fmt.Errorf("ring buffer: %w", err))
	}
	hold = append(hold, ring)
	drops, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: dropSlots})
	if err != nil {
		return fail(fmt.Errorf("drop counters: %w", err))
	}
	hold = append(hold, drops)
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		License:      license,
		Instructions: TrackProgram(flows.FD(), local.FD(), ring.FD(), drops.FD(), o.SYNTimeout),
	})
	if err != nil {
		return fail(fmt.Errorf("load tracker program: %w", err))
	}
	hold = append(hold, prog)
	dirs := []ebpf.AttachType{ebpf.AttachTCXIngress, ebpf.AttachTCXEgress}
	if ifi.Flags&net.FlagLoopback != 0 {
		dirs = dirs[:1]
	}
	ls, err := attach(prog, ifi.Index, dirs...)
	if err != nil {
		return fail(err)
	}
	hold = append(hold, ls...)
	if o.Promisc {
		p, err := joinPromisc(ifi.Index)
		if err != nil {
			return fail(err)
		}
		hold = append(hold, p)
	}
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		return fail(fmt.Errorf("ring buffer reader: %w", err))
	}
	hold = append(hold, rd)
	return &Tracker{rd: rd, flows: flows, drops: drops, timeout: o.Timeout, hold: hold}, nil
}

// Next returns the next summary. ErrTimeout means none arrived in time.
func (t *Tracker) Next() (Summary, error) {
	for {
		t.rd.SetDeadline(time.Now().Add(t.timeout))
		if err := t.rd.ReadInto(&t.rec); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return Summary{}, ErrTimeout
			}
			return Summary{}, err
		}
		if s, ok := DecodeSummary(t.rec.RawSample); ok {
			return s, nil
		}
	}
}

// batch is how many connections one map read returns.
const batch = 4096

// Flows reads every connection in the table.
func (t *Tracker) Flows() ([]TrackState, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return nil, err
	}
	now := uint64(ts.Nano())
	var (
		out  []TrackState
		cur  ebpf.MapBatchCursor
		keys = make([][TrackKeySize]byte, batch)
		vals = make([][TrackValueSize]byte, batch)
	)
	for {
		n, err := t.flows.BatchLookup(&cur, keys, vals, nil)
		for i := range n {
			if st, derr := DecodeTrackState(keys[i], vals[i], now); derr == nil {
				out = append(out, st)
			}
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

// Forget removes a connection from the table.
func (t *Tracker) Forget(k TrackKey) error {
	err := t.flows.Delete(encodeTrackKey(k))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func encodeTrackKey(k TrackKey) [TrackKeySize]byte {
	var b [TrackKeySize]byte
	if k.Local.Addr().Is4() {
		b[0] = famV4
	} else {
		b[0] = famV6
	}
	binary.BigEndian.PutUint16(b[kLocalPort:], k.Local.Port())
	binary.BigEndian.PutUint16(b[kRemotePort:], k.Remote.Port())
	l, r := k.Local.Addr().As16(), k.Remote.Addr().As16()
	copy(b[kLocal:], l[:])
	copy(b[kRemote:], r[:])
	return b
}

// Drops is how many summaries the kernel could not queue because the ring
// buffer was full, and how many connections it could not track because
// the table was full.
func (t *Tracker) Drops() (ring, flows uint64, err error) {
	sum := func(slot uint32) (uint64, error) {
		var per []uint64
		if err := t.drops.Lookup(slot, &per); err != nil {
			return 0, err
		}
		var n uint64
		for _, v := range per {
			n += v
		}
		return n, nil
	}
	if ring, err = sum(dropRing); err != nil {
		return 0, 0, err
	}
	flows, err = sum(dropFlows)
	return ring, flows, err
}

// Close detaches the program and frees the maps.
func (t *Tracker) Close() error { return t.hold.Close() }
