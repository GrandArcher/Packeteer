// Package ebpfpath is the optional eBPF data path (#229).
//
// It loads two small tc programs with a pure Go loader. The programs are
// assembled here from cilium/ebpf instructions, so there is no C source, no
// runtime compiler, and no BTF or CO-RE relocation: the only kernel struct
// they read is __sk_buff, whose layout is stable UAPI.
//
//   - The capture program copies the first SnapLen bytes of every TCP
//     frame into a BPF ring buffer. Everything else stays in the kernel.
//     The span source reads those frames in place of an AF_PACKET socket.
//   - The flow program counts bytes and packets of every IP packet leaving
//     an interface, per source, destination, and protocol, in an LRU
//     per-CPU hash map. Nothing is sampled. The flow source polls it.
//
// Both attach with TCX (Linux 6.6 or newer) and are tied to a link fd, so
// the kernel detaches them when the process exits. Neither program drops,
// edits, or redirects a packet: they return TCX_NEXT. Loading needs
// CAP_BPF and CAP_NET_ADMIN (CAP_PERFMON on kernels that require it for
// ring buffers). Every failure is returned to the caller, which falls back
// to the path it used before.
package ebpfpath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf/asm"
)

// ErrUnsupported is returned where the eBPF path cannot run at all.
var ErrUnsupported = errors.New("eBPF data path is not supported here")

// Sizes shared by the kernel programs and the readers.
const (
	// KeySize is the flow map key: family, protocol, 6 zero bytes, the
	// source address (16 bytes, an IPv4 address in the first 4), and the
	// destination address in the same form.
	KeySize = 40
	// ValueSize is one per-CPU flow value: bytes then packets, both u64.
	ValueSize = 16
	// SnapLen is how many bytes of a frame the capture program copies.
	SnapLen = 128
	// recordHeader is the capture record header: wire length, captured
	// length, both u32 in host byte order.
	recordHeader = 8
	// RecordSize is the fixed ring buffer record.
	RecordSize = recordHeader + SnapLen
	// DefaultFlowEntries bounds the flow map. Past it the kernel evicts
	// the least recently used flow.
	DefaultFlowEntries = 65536
	// MinFlowEntries and MaxFlowEntries bound the configurable map size.
	MinFlowEntries = 1024
	MaxFlowEntries = 4194304
	// ringBytes is the ring buffer size, a power of two and a multiple of
	// the page size. About 30000 records.
	ringBytes = 4 << 20

	ethHeader  = 14
	minTCPSize = ethHeader + 20 + 20
	protoTCP   = 6

	tcxNext   = -1
	noExist   = 1
	ctxLen    = 0
	ctxProto  = 16
	keyOff    = -40
	zeroOff   = -56
	dropKey   = -64
	ethIPv4   = 0x0800
	ethIPv6   = 0x86dd
	famV4     = 4
	famV6     = 6
	keyProto  = 1
	keySrc    = 8
	keyDst    = 24
	v4Proto   = ethHeader + 9
	v4Src     = ethHeader + 12
	v4Dst     = ethHeader + 16
	v6Next    = ethHeader + 6
	v6Src     = ethHeader + 8
	v6Dst     = ethHeader + 24
	labelExit = "exit"
)

// htons16 is an Ethernet protocol as __sk_buff.protocol holds it: the
// network byte order value read as a native u32.
func htons16(v uint16) int32 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return int32(binary.NativeEndian.Uint16(b[:]))
}

type builder struct {
	insns   asm.Instructions
	pending string
}

func (b *builder) add(i ...asm.Instruction) {
	if b.pending != "" && len(i) > 0 {
		i[0] = i[0].WithSymbol(b.pending)
		b.pending = ""
	}
	b.insns = append(b.insns, i...)
}

// label names the next instruction added.
func (b *builder) label(name string) { b.pending = name }

// at adds an instruction that is a jump target.
func (b *builder) at(label string, i asm.Instruction) { b.add(i.WithSymbol(label)) }

// stackPtr leaves r10+off in dst.
func (b *builder) stackPtr(dst asm.Register, off int32) {
	b.add(asm.Mov.Reg(dst, asm.R10), asm.Add.Imm(dst, off))
}

// zero clears n stack bytes at off. The verifier needs every byte of a map
// key or value initialised, and StoreImm has no 64-bit form.
func (b *builder) zero(off int16, n int16) {
	for i := int16(0); i < n; i += 4 {
		b.add(asm.StoreImm(asm.R10, off+i, 0, asm.Word))
	}
}

// loadBytes copies n packet bytes at off into the stack at stackOff, and
// leaves the program when the packet is shorter. r6 holds the context.
func (b *builder) loadBytes(off int32, stackOff int32, n int32) {
	b.add(asm.Mov.Reg(asm.R1, asm.R6), asm.Mov.Imm(asm.R2, off))
	b.stackPtr(asm.R3, stackOff)
	b.add(asm.Mov.Imm(asm.R4, n), asm.FnSkbLoadBytes.Call(), asm.JNE.Imm(asm.R0, 0, labelExit))
}

// parse fills the stack key from the IP header. With addrs false only the
// family and protocol are read.
func (b *builder) parse(addrs bool) {
	b.add(asm.Mov.Reg(asm.R6, asm.R1))
	b.zero(keyOff, KeySize)
	b.add(
		asm.LoadMem(asm.R2, asm.R6, ctxProto, asm.Word),
		asm.JEq.Imm(asm.R2, htons16(ethIPv4), "v4"),
		asm.JEq.Imm(asm.R2, htons16(ethIPv6), "v6"),
		asm.Ja.Label(labelExit),
	)
	b.at("v4", asm.StoreImm(asm.R10, keyOff, famV4, asm.Byte))
	b.loadBytes(v4Proto, keyOff+keyProto, 1)
	if addrs {
		b.loadBytes(v4Src, keyOff+keySrc, 4)
		b.loadBytes(v4Dst, keyOff+keyDst, 4)
	}
	b.add(asm.Ja.Label("parsed"))
	b.at("v6", asm.StoreImm(asm.R10, keyOff, famV6, asm.Byte))
	b.loadBytes(v6Next, keyOff+keyProto, 1)
	if addrs {
		b.loadBytes(v6Src, keyOff+keySrc, 16)
		b.loadBytes(v6Dst, keyOff+keyDst, 16)
	}
}

// lookup leaves the map value pointer, or zero, in r0.
func (b *builder) lookup(mapFD int, keyStack int32) {
	b.add(asm.LoadMapPtr(asm.R1, mapFD))
	b.stackPtr(asm.R2, keyStack)
	b.add(asm.FnMapLookupElem.Call())
}

func (b *builder) exit() {
	b.at(labelExit, asm.Mov.Imm(asm.R0, tcxNext))
	b.add(asm.Return())
}

// FlowProgram counts every IP packet it sees in the per-CPU hash map
// flowsFD: the first packet of a flow inserts a zero value, then every
// packet adds its length and one packet.
func FlowProgram(flowsFD int) asm.Instructions {
	var b builder
	b.parse(true)
	b.label("parsed")
	b.zero(zeroOff, ValueSize)
	b.lookup(flowsFD, keyOff)
	b.add(asm.JNE.Imm(asm.R0, 0, "hit"))
	b.add(asm.LoadMapPtr(asm.R1, flowsFD))
	b.stackPtr(asm.R2, keyOff)
	b.stackPtr(asm.R3, zeroOff)
	b.add(asm.Mov.Imm(asm.R4, noExist), asm.FnMapUpdateElem.Call())
	b.lookup(flowsFD, keyOff)
	b.add(asm.JEq.Imm(asm.R0, 0, labelExit))
	// The counted bytes are IP bytes, as in NetFlow: the frame without its
	// Ethernet header. The program only gets here after reading IP header
	// bytes past that header, so the frame is longer than it.
	b.at("hit", asm.LoadMem(asm.R2, asm.R6, ctxLen, asm.Word))
	b.add(
		asm.Sub.Imm(asm.R2, ethHeader),
		asm.StoreXAdd(asm.R0, asm.R2, asm.DWord),
		asm.Mov.Imm(asm.R3, 1),
		asm.Mov.Reg(asm.R4, asm.R0),
		asm.Add.Imm(asm.R4, 8),
		asm.StoreXAdd(asm.R4, asm.R3, asm.DWord),
	)
	b.exit()
	return b.insns
}

// CaptureProgram copies the head of every TCP frame into the ring buffer
// ringFD. Frames it cannot reserve room for are counted in the per-CPU
// array dropsFD, slot 0.
func CaptureProgram(ringFD, dropsFD int) asm.Instructions {
	var b builder
	b.parse(false)
	b.at("parsed", asm.LoadMem(asm.R2, asm.R10, keyOff+keyProto, asm.Byte))
	b.add(
		asm.JNE.Imm(asm.R2, protoTCP, labelExit),
		asm.LoadMem(asm.R8, asm.R6, ctxLen, asm.Word),
		asm.JLT.Imm(asm.R8, minTCPSize, labelExit),
		asm.Mov.Reg(asm.R9, asm.R8),
		asm.JLE.Imm(asm.R9, SnapLen, "capped"),
		asm.Mov.Imm(asm.R9, SnapLen),
	)
	b.at("capped", asm.LoadMapPtr(asm.R1, ringFD))
	b.add(asm.Mov.Imm(asm.R2, RecordSize), asm.Mov.Imm(asm.R3, 0), asm.FnRingbufReserve.Call(),
		asm.JNE.Imm(asm.R0, 0, "reserved"))
	b.add(asm.StoreImm(asm.R10, dropKey, 0, asm.Word))
	b.lookup(dropsFD, dropKey)
	b.add(
		asm.JEq.Imm(asm.R0, 0, labelExit),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Ja.Label(labelExit),
	)
	b.at("reserved", asm.Mov.Reg(asm.R7, asm.R0))
	b.add(
		asm.StoreMem(asm.R7, 0, asm.R8, asm.Word),
		asm.StoreMem(asm.R7, 4, asm.R9, asm.Word),
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Mov.Imm(asm.R2, 0),
		asm.Mov.Reg(asm.R3, asm.R7),
		asm.Add.Imm(asm.R3, recordHeader),
		asm.Mov.Reg(asm.R4, asm.R9),
		asm.FnSkbLoadBytes.Call(),
		asm.JNE.Imm(asm.R0, 0, "discard"),
		asm.Mov.Reg(asm.R1, asm.R7),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
		asm.Ja.Label(labelExit),
	)
	b.at("discard", asm.Mov.Reg(asm.R1, asm.R7))
	b.add(asm.Mov.Imm(asm.R2, 0), asm.FnRingbufDiscard.Call())
	b.exit()
	return b.insns
}

// Frame returns the captured frame of one ring buffer record. ok is false
// for a malformed record.
func Frame(rec []byte) (frame []byte, ok bool) {
	if len(rec) < recordHeader {
		return nil, false
	}
	wireLen := binary.NativeEndian.Uint32(rec[0:4])
	capLen := binary.NativeEndian.Uint32(rec[4:8])
	if capLen == 0 || capLen > SnapLen || int(capLen) > len(rec)-recordHeader || capLen > wireLen {
		return nil, false
	}
	return rec[recordHeader : recordHeader+int(capLen)], true
}

// FlowKey identifies one counted flow.
type FlowKey struct {
	Src, Dst netip.Addr
	Proto    uint8
}

// Totals are the bytes and packets counted for a flow.
type Totals struct{ Bytes, Packets uint64 }

func decodeKey(k [KeySize]byte) (FlowKey, error) {
	var out FlowKey
	out.Proto = k[keyProto]
	switch k[0] {
	case famV4:
		out.Src = netip.AddrFrom4([4]byte(k[keySrc : keySrc+4]))
		out.Dst = netip.AddrFrom4([4]byte(k[keyDst : keyDst+4]))
	case famV6:
		out.Src = netip.AddrFrom16([16]byte(k[keySrc : keySrc+16]))
		out.Dst = netip.AddrFrom16([16]byte(k[keyDst : keyDst+16]))
	default:
		return out, fmt.Errorf("flow key has unknown family %d", k[0])
	}
	return out, nil
}

// Delta is the growth of one flow since the previous snapshot.
type Delta struct {
	Key FlowKey
	Totals
}

// Differ turns successive snapshots of cumulative counters into deltas. A
// counter that went down is a flow the kernel evicted and counted again
// from zero, so its whole value is new. It holds at most one snapshot.
type Differ struct{ prev map[FlowKey]Totals }

// Next returns the flows that grew, and remembers cur.
func (d *Differ) Next(cur map[FlowKey]Totals) []Delta {
	var out []Delta
	for k, t := range cur {
		p := d.prev[k]
		if t.Bytes < p.Bytes || t.Packets < p.Packets {
			p = Totals{}
		}
		if t.Bytes == p.Bytes && t.Packets == p.Packets {
			continue
		}
		out = append(out, Delta{Key: k, Totals: Totals{Bytes: t.Bytes - p.Bytes, Packets: t.Packets - p.Packets}})
	}
	d.prev = cur
	return out
}
