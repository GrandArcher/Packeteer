package ebpfpath

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf/asm"
)

// The tracker program (#631) follows TCP connections in the kernel, as the
// span source's userspace tracker does from frame heads. The kernel keeps
// one entry per connection, oriented local to remote with the local
// prefixes in an LPM trie, and hands the connection's running counts to
// userspace through a ring buffer. The counts only grow, so userspace turns
// them into deltas and can also read them from the table. What the kernel
// cannot do without a timer stays in userspace: SYN timeouts, and expiry of
// idle connections.
// The program only reads packets and returns TCX_NEXT.

// Sizes shared by the tracker program and its readers.
const (
	// TrackKeySize is the connection key: family, one pad byte, local and
	// remote port (network order), then the local and remote address as 16
	// bytes each, an IPv4 address in its IPv4-mapped IPv6 form.
	TrackKeySize = 40
	// TrackValueSize is the kernel's per-connection state.
	TrackValueSize = 88
	// SummarySize is the fixed ring buffer record.
	SummarySize = 96
	// LocalKeySize is the LPM trie key: a u32 prefix length, then a 16
	// byte address in IPv4-mapped form.
	LocalKeySize = 20
	// MinTrackFlows and MaxTrackFlows bound the connection table.
	MinTrackFlows = 1
	MaxTrackFlows = 10000000
	// ReportEvery is how often a connection that keeps sending reports its
	// counts. Events (new connection, retransmission, handshake RTT, reset,
	// FIN) report at once.
	ReportEvery = time.Second
	// trackRingBytes holds about 10000 summaries.
	trackRingBytes = 1 << 20
	// Slots of the drop counter array.
	dropRing  = 0
	dropFlows = 1
	dropSlots = 2
)

// Connection state, as the kernel lays it out in the flow map value.
const (
	vSynAt    = 0  // u64 ktime of the pending local SYN, 0 when none
	vSynAckAt = 8  // u64 ktime of the pending local SYN-ACK, 0 when none
	vLast     = 16 // u64 ktime of the last packet
	vReportAt = 24 // u64 ktime of the last summary
	// Six u64 counters that only grow, in the order of the summary record.
	vSegs    = 32 // outbound payload segments
	vRetrans = 40 // of those, repeats of bytes already sent
	vRTTSum  = 48 // nanoseconds
	vRTTN    = 56 // handshake round trips measured
	vResets  = 64 // RSTs from the remote side
	vCreated = 72 // ktime the connection was first seen; tells reused 4-tuples apart
	vNextSeq = 80 // u32 next expected outbound sequence number
	vFlags   = 84 // u32 flag* bits

	flagHaveSeq    = 1
	flagSynRetx    = 2
	flagSynAckRetx = 4

	// A summary is the six counters, then 1 when the kernel forgot the
	// connection with it, then the key.
	sumFinal = 48
	sumKey   = 56
)

// TCP flag bits.
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// Stack layout of the tracker program, from r10.
const (
	sLPM     = -68  // LPM key: u32 prefix length, 16 byte address at -64
	sNow     = -80  // u64 ktime
	sSeq     = -88  // u32 sequence number, host order
	sPay     = -96  // u32 TCP payload length
	sFlags   = -104 // u32 TCP flags
	sOut     = -112 // u32 1 when the local side sent the packet
	sEmit    = -120 // u32 0 nothing, 1 report, 2 report and forget the connection
	sTOff    = -128 // u32 offset of the TCP header
	sL4      = -136 // u32 TCP length from the IP header
	sTmp     = -144 // scratch for small header reads
	sTCP     = -176 // 20 TCP header bytes
	sDropKey = -184
	sNew     = -280 // zero value for a new connection

	kLocalPort  = 2
	kRemotePort = 4
	kLocal      = 8
	kRemote     = 24

	tkLocal  = keyOff + kLocal
	tkRemote = keyOff + kRemote
)

// TrackProgram is the tc program of the tracker. synTimeout bounds the
// handshake round trips it will report: a SYN-ACK later than that is the
// userspace sweep's timeout, not an RTT.
func TrackProgram(flowsFD, localFD, ringFD, dropsFD int, synTimeout time.Duration) asm.Instructions {
	var b builder
	b.add(asm.Mov.Reg(asm.R6, asm.R1))
	b.zero(keyOff, TrackKeySize)
	b.add(
		asm.StoreImm(asm.R10, sLPM, 128, asm.Word),
		asm.StoreImm(asm.R10, sEmit, 0, asm.Word),
		asm.LoadMem(asm.R2, asm.R6, ctxProto, asm.Word),
		asm.JEq.Imm(asm.R2, htons16(ethIPv4), "v4"),
		asm.JEq.Imm(asm.R2, htons16(ethIPv6), "v6"),
		asm.Ja.Label(labelExit),
	)

	// IPv4: TCP only, not a later fragment. r9 is the header length, r8
	// the total length.
	b.at("v4", asm.StoreImm(asm.R10, keyOff, famV4, asm.Byte))
	b.loadBytes(v4Proto, sTmp, 1)
	b.add(asm.LoadMem(asm.R2, asm.R10, sTmp, asm.Byte), asm.JNE.Imm(asm.R2, protoTCP, labelExit))
	b.loadBytes(ethHeader, sTmp, 1)
	b.add(
		asm.LoadMem(asm.R9, asm.R10, sTmp, asm.Byte),
		asm.And.Imm(asm.R9, 0x0f),
		asm.LSh.Imm(asm.R9, 2),
		asm.JLT.Imm(asm.R9, 20, labelExit),
	)
	b.loadBytes(ethHeader+6, sTmp, 2)
	b.add(
		asm.LoadMem(asm.R2, asm.R10, sTmp, asm.Half),
		asm.HostTo(asm.BE, asm.R2, asm.Half),
		asm.And.Imm(asm.R2, 0x1fff),
		asm.JNE.Imm(asm.R2, 0, labelExit),
	)
	b.loadBytes(ethHeader+2, sTmp, 2)
	b.add(
		asm.LoadMem(asm.R8, asm.R10, sTmp, asm.Half),
		asm.HostTo(asm.BE, asm.R8, asm.Half),
		asm.StoreImm(asm.R10, tkLocal+10, 0xffff, asm.Half),
		asm.StoreImm(asm.R10, tkRemote+10, 0xffff, asm.Half),
	)
	b.loadBytes(v4Src, tkLocal+12, 4)
	b.loadBytes(v4Dst, tkRemote+12, 4)
	b.add(
		asm.Sub.Reg(asm.R8, asm.R9),
		asm.JSLT.Imm(asm.R8, 20, labelExit),
		asm.StoreMem(asm.R10, sL4, asm.R8, asm.Word),
		asm.Add.Imm(asm.R9, ethHeader),
		asm.StoreMem(asm.R10, sTOff, asm.R9, asm.Word),
		asm.Ja.Label("tcp"),
	)

	// IPv6: TCP directly after the fixed header. A packet with extension
	// headers is not tracked.
	b.at("v6", asm.StoreImm(asm.R10, keyOff, famV6, asm.Byte))
	b.loadBytes(v6Next, sTmp, 1)
	b.add(asm.LoadMem(asm.R2, asm.R10, sTmp, asm.Byte), asm.JNE.Imm(asm.R2, protoTCP, labelExit))
	b.loadBytes(ethHeader+4, sTmp, 2)
	b.add(
		asm.LoadMem(asm.R8, asm.R10, sTmp, asm.Half),
		asm.HostTo(asm.BE, asm.R8, asm.Half),
		asm.JLT.Imm(asm.R8, 20, labelExit),
		asm.StoreMem(asm.R10, sL4, asm.R8, asm.Word),
		asm.StoreImm(asm.R10, sTOff, ethHeader+40, asm.Word),
	)
	b.loadBytes(v6Src, tkLocal, 16)
	b.loadBytes(v6Dst, tkRemote, 16)

	// TCP header: ports in packet orientation for now, sequence number in
	// host order, payload length, flags.
	b.at("tcp", asm.Mov.Reg(asm.R1, asm.R6))
	b.add(asm.LoadMem(asm.R2, asm.R10, sTOff, asm.Word))
	b.stackPtr(asm.R3, sTCP)
	b.add(asm.Mov.Imm(asm.R4, 20), asm.FnSkbLoadBytes.Call(), asm.JNE.Imm(asm.R0, 0, labelExit))
	b.add(
		asm.LoadMem(asm.R2, asm.R10, sTCP, asm.Half),
		asm.StoreMem(asm.R10, keyOff+kLocalPort, asm.R2, asm.Half),
		asm.LoadMem(asm.R2, asm.R10, sTCP+2, asm.Half),
		asm.StoreMem(asm.R10, keyOff+kRemotePort, asm.R2, asm.Half),
		asm.LoadMem(asm.R2, asm.R10, sTCP+4, asm.Word),
		asm.HostTo(asm.BE, asm.R2, asm.Word),
		asm.StoreMem(asm.R10, sSeq, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R10, sTCP+12, asm.Byte),
		asm.And.Imm(asm.R2, 0xf0),
		asm.RSh.Imm(asm.R2, 2),
		asm.JLT.Imm(asm.R2, 20, labelExit),
		asm.LoadMem(asm.R3, asm.R10, sL4, asm.Word),
		asm.JLT.Reg(asm.R3, asm.R2, labelExit),
		asm.Sub.Reg(asm.R3, asm.R2),
		asm.StoreMem(asm.R10, sPay, asm.R3, asm.Word),
		asm.LoadMem(asm.R2, asm.R10, sTCP+13, asm.Byte),
		asm.StoreMem(asm.R10, sFlags, asm.R2, asm.Word),
	)

	// Orientation: exactly one side must be in a local prefix. Afterwards
	// the key holds the local side first.
	b.lpm(localFD, tkLocal)
	b.add(asm.JEq.Imm(asm.R0, 0, "srcRemote"))
	b.lpm(localFD, tkRemote)
	b.add(
		asm.JNE.Imm(asm.R0, 0, labelExit),
		asm.StoreImm(asm.R10, sOut, 1, asm.Word),
		asm.Ja.Label("oriented"),
	)
	b.label("srcRemote")
	b.lpm(localFD, tkRemote)
	b.add(
		asm.JEq.Imm(asm.R0, 0, labelExit),
		asm.StoreImm(asm.R10, sOut, 0, asm.Word),
		asm.LoadMem(asm.R1, asm.R10, tkLocal, asm.DWord),
		asm.LoadMem(asm.R2, asm.R10, tkLocal+8, asm.DWord),
		asm.LoadMem(asm.R3, asm.R10, tkRemote, asm.DWord),
		asm.LoadMem(asm.R4, asm.R10, tkRemote+8, asm.DWord),
		asm.StoreMem(asm.R10, tkLocal, asm.R3, asm.DWord),
		asm.StoreMem(asm.R10, tkLocal+8, asm.R4, asm.DWord),
		asm.StoreMem(asm.R10, tkRemote, asm.R1, asm.DWord),
		asm.StoreMem(asm.R10, tkRemote+8, asm.R2, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, keyOff+kLocalPort, asm.Half),
		asm.LoadMem(asm.R2, asm.R10, keyOff+kRemotePort, asm.Half),
		asm.StoreMem(asm.R10, keyOff+kLocalPort, asm.R2, asm.Half),
		asm.StoreMem(asm.R10, keyOff+kRemotePort, asm.R1, asm.Half),
	)

	// Find or create the connection. A stray RST does not create one. A
	// full table counts the connection as dropped, like max_flows.
	b.label("oriented")
	b.add(asm.FnKtimeGetNs.Call(), asm.StoreMem(asm.R10, sNow, asm.R0, asm.DWord))
	b.lookup(flowsFD, keyOff)
	b.add(
		asm.JNE.Imm(asm.R0, 0, "have"),
		asm.LoadMem(asm.R2, asm.R10, sFlags, asm.Word),
		asm.JSet.Imm(asm.R2, tcpRST, labelExit),
	)
	b.zero(sNew, TrackValueSize)
	b.add(asm.LoadMapPtr(asm.R1, flowsFD))
	b.stackPtr(asm.R2, keyOff)
	b.stackPtr(asm.R3, sNew)
	b.add(asm.Mov.Imm(asm.R4, noExist), asm.FnMapUpdateElem.Call(), asm.JNE.Imm(asm.R0, 0, "updateFailed"))
	b.lookup(flowsFD, keyOff)
	b.add(
		asm.JEq.Imm(asm.R0, 0, labelExit),
		asm.LoadMem(asm.R1, asm.R10, sNow, asm.DWord),
		asm.StoreMem(asm.R0, vCreated, asm.R1, asm.DWord),
		asm.StoreImm(asm.R10, sEmit, 1, asm.Word),
		asm.Ja.Label("have"),
	)
	b.label("updateFailed")
	b.lookup(flowsFD, keyOff)
	b.add(asm.JNE.Imm(asm.R0, 0, "have"))
	b.countDrop(dropsFD, dropFlows)

	b.at("have", asm.Mov.Reg(asm.R7, asm.R0))
	b.add(
		asm.LoadMem(asm.R1, asm.R10, sNow, asm.DWord),
		asm.StoreMem(asm.R7, vLast, asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, asm.R10, sOut, asm.Word),
		asm.JEq.Imm(asm.R1, 0, "inbound"),
		asm.LoadMem(asm.R8, asm.R10, sFlags, asm.Word),
		asm.JSet.Imm(asm.R8, tcpRST, "outRST"),
		asm.Mov.Reg(asm.R1, asm.R8),
		asm.And.Imm(asm.R1, tcpSYN|tcpACK),
		asm.JEq.Imm(asm.R1, tcpSYN|tcpACK, "synack"),
		asm.JEq.Imm(asm.R1, tcpSYN, "syn"),
		asm.Ja.Label("data"),
	)

	// Outbound.
	b.at("outRST", asm.StoreImm(asm.R10, sEmit, 2, asm.Word))
	b.add(asm.Ja.Label("flush"))
	b.handshakeOut("syn", vSynAt, flagSynRetx)
	b.handshakeOut("synack", vSynAckAt, flagSynAckRetx)

	// Outbound payload: count the segment, then tell a new one from a
	// repeat in 32-bit sequence space. A one-byte probe that repeats the
	// last byte is a keepalive, not a retransmission.
	b.at("data", asm.LoadMem(asm.R2, asm.R10, sPay, asm.Word))
	b.add(
		asm.JEq.Imm(asm.R2, 0, "post"),
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, vSegs),
		asm.LoadMem(asm.R3, asm.R10, sSeq, asm.Word),
		asm.Mov.Reg(asm.R4, asm.R3),
		asm.Add.Reg32(asm.R4, asm.R2),
		asm.LoadMem(asm.R5, asm.R7, vFlags, asm.Word),
		asm.JSet.Imm(asm.R5, flagHaveSeq, "haveSeq"),
		asm.Or.Imm(asm.R5, flagHaveSeq),
		asm.StoreMem(asm.R7, vFlags, asm.R5, asm.Word),
		asm.StoreMem(asm.R7, vNextSeq, asm.R4, asm.Word),
		asm.Ja.Label("post"),
	)
	b.at("haveSeq", asm.LoadMem(asm.R5, asm.R7, vNextSeq, asm.Word))
	b.add(
		asm.Mov.Reg(asm.R0, asm.R4),
		asm.Sub.Reg32(asm.R0, asm.R5),
		asm.JEq.Imm(asm.R0, 0, "endEqual"),
		asm.JSet.Imm(asm.R0, -0x80000000, "retrans"),
		asm.Mov.Reg(asm.R0, asm.R3),
		asm.Sub.Reg32(asm.R0, asm.R5),
		asm.JSet.Imm(asm.R0, -0x80000000, "retransAdvance"),
		asm.Ja.Label("advance"),
	)
	b.at("endEqual", asm.JEq.Imm(asm.R2, 1, "post"))
	b.add(asm.Ja.Label("retrans"))
	b.at("retransAdvance", asm.StoreMem(asm.R7, vNextSeq, asm.R4, asm.Word))
	b.at("retrans", asm.Mov.Imm(asm.R1, 1))
	b.add(
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, vRetrans),
		asm.StoreImm(asm.R10, sEmit, 1, asm.Word),
		asm.Ja.Label("post"),
	)
	b.at("advance", asm.StoreMem(asm.R7, vNextSeq, asm.R4, asm.Word))
	b.add(asm.Ja.Label("post"))

	// Inbound: a RST ends the connection, a SYN-ACK answers a local SYN,
	// and an ACK answers a local SYN-ACK.
	b.at("inbound", asm.LoadMem(asm.R8, asm.R10, sFlags, asm.Word))
	b.add(
		asm.JSet.Imm(asm.R8, tcpRST, "inRST"),
		asm.Mov.Reg(asm.R1, asm.R8),
		asm.And.Imm(asm.R1, tcpSYN|tcpACK),
		asm.JEq.Imm(asm.R1, tcpSYN|tcpACK, "inSynAck"),
		asm.JSet.Imm(asm.R8, tcpACK, "inAck"),
		asm.Ja.Label("post"),
	)
	b.at("inRST", asm.Mov.Imm(asm.R1, 1))
	b.add(
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, vResets),
		asm.StoreImm(asm.R10, sEmit, 2, asm.Word),
		asm.Ja.Label("flush"),
	)
	b.handshakeIn("inSynAck", vSynAt, flagSynRetx, synTimeout)
	b.handshakeIn("inAck", vSynAckAt, flagSynAckRetx, synTimeout)

	// Report when something happened, when the connection closes, or when
	// it has unreported segments and the last report is old.
	b.at("post", asm.LoadMem(asm.R1, asm.R10, sEmit, asm.Word))
	b.add(
		asm.JNE.Imm(asm.R1, 0, "flush"),
		asm.LoadMem(asm.R2, asm.R10, sFlags, asm.Word),
		asm.JSet.Imm(asm.R2, tcpFIN, "flush"),
		asm.LoadMem(asm.R2, asm.R7, vSegs, asm.DWord),
		asm.JEq.Imm(asm.R2, 0, labelExit),
		asm.LoadMem(asm.R3, asm.R10, sNow, asm.DWord),
		asm.LoadMem(asm.R4, asm.R7, vReportAt, asm.DWord),
		asm.Sub.Reg(asm.R3, asm.R4),
		asm.JLT.Imm(asm.R3, int32(ReportEvery), labelExit),
	)

	// Summary: copy the counters and the key into a ring buffer record.
	// Each counter only grows, so the copy needs no lock.
	b.at("flush", asm.LoadMapPtr(asm.R1, ringFD))
	b.add(asm.Mov.Imm(asm.R2, SummarySize), asm.Mov.Imm(asm.R3, 0), asm.FnRingbufReserve.Call(),
		asm.JNE.Imm(asm.R0, 0, "reserved"))
	b.countDropThen(dropsFD, dropRing, "flushed")
	b.at("reserved", asm.Mov.Reg(asm.R8, asm.R0))
	for off := int16(0); off < vCreated-vSegs+8; off += 8 {
		b.add(
			asm.LoadMem(asm.R1, asm.R7, vSegs+off, asm.DWord),
			asm.StoreMem(asm.R8, off, asm.R1, asm.DWord),
		)
	}
	b.add(
		asm.LoadMem(asm.R1, asm.R10, sEmit, asm.Word),
		asm.RSh.Imm(asm.R1, 1),
		asm.StoreMem(asm.R8, sumFinal, asm.R1, asm.DWord),
	)
	for off := int16(0); off < TrackKeySize; off += 8 {
		b.add(
			asm.LoadMem(asm.R1, asm.R10, keyOff+off, asm.DWord),
			asm.StoreMem(asm.R8, sumKey+off, asm.R1, asm.DWord),
		)
	}
	b.add(
		asm.LoadMem(asm.R1, asm.R10, sNow, asm.DWord),
		asm.StoreMem(asm.R7, vReportAt, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.R8),
		asm.Mov.Imm(asm.R2, 0),
		asm.FnRingbufSubmit.Call(),
	)
	b.at("flushed", asm.LoadMem(asm.R1, asm.R10, sEmit, asm.Word))
	b.add(asm.JNE.Imm(asm.R1, 2, labelExit))
	b.add(asm.LoadMapPtr(asm.R1, flowsFD))
	b.stackPtr(asm.R2, keyOff)
	b.add(asm.FnMapDeleteElem.Call())
	b.exit()
	return b.insns
}

// lpm looks up the 16 byte address at stack offset addr in the local
// prefix trie. r0 is the value pointer, or zero.
func (b *builder) lpm(mapFD int, addr int32) {
	b.add(
		asm.LoadMem(asm.R2, asm.R10, int16(addr), asm.DWord),
		asm.StoreMem(asm.R10, sLPM+4, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.R10, int16(addr+8), asm.DWord),
		asm.StoreMem(asm.R10, sLPM+12, asm.R2, asm.DWord),
	)
	b.lookup(mapFD, sLPM)
}

// countDrop adds one to slot of the drop counters and leaves the program.
func (b *builder) countDrop(dropsFD int, slot int64) {
	b.countDropThen(dropsFD, slot, labelExit)
}

func (b *builder) countDropThen(dropsFD int, slot int64, next string) {
	b.add(asm.StoreImm(asm.R10, sDropKey, slot, asm.Word))
	b.lookup(dropsFD, sDropKey)
	b.add(
		asm.JEq.Imm(asm.R0, 0, next),
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R0, asm.R1, asm.DWord, 0),
		asm.Ja.Label(next),
	)
}

// handshakeOut records a local SYN or SYN-ACK. The first one starts the
// round trip clock; a repeat before it was answered marks the handshake
// retransmitted, so it yields no RTT. Either sets the sequence number.
func (b *builder) handshakeOut(label string, at int16, retx int32) {
	b.at(label, asm.LoadMem(asm.R2, asm.R7, at, asm.DWord))
	b.add(
		asm.LoadMem(asm.R3, asm.R7, vFlags, asm.Word),
		asm.JNE.Imm(asm.R2, 0, label+"Repeat"),
		asm.JSet.Imm(asm.R3, retx, label+"Repeat"),
		asm.LoadMem(asm.R4, asm.R10, sNow, asm.DWord),
		asm.StoreMem(asm.R7, at, asm.R4, asm.DWord),
		asm.Ja.Label(label+"Seq"),
	)
	b.at(label+"Repeat", asm.Or.Imm(asm.R3, retx))
	b.at(label+"Seq", asm.Or.Imm(asm.R3, flagHaveSeq))
	b.add(
		asm.StoreMem(asm.R7, vFlags, asm.R3, asm.Word),
		asm.LoadMem(asm.R4, asm.R10, sSeq, asm.Word),
		asm.Add.Imm(asm.R4, 1),
		asm.StoreMem(asm.R7, vNextSeq, asm.R4, asm.Word),
		asm.Ja.Label("post"),
	)
}

// handshakeIn closes a round trip. It reports an RTT only for a handshake
// that was not retransmitted and was answered inside the SYN timeout.
func (b *builder) handshakeIn(label string, at int16, retx int32, synTimeout time.Duration) {
	b.at(label, asm.LoadMem(asm.R2, asm.R7, at, asm.DWord))
	b.add(
		asm.JEq.Imm(asm.R2, 0, "post"),
		asm.Mov.Imm(asm.R1, 0),
		asm.StoreMem(asm.R7, at, asm.R1, asm.DWord),
		asm.LoadMem(asm.R3, asm.R7, vFlags, asm.Word),
		asm.JSet.Imm(asm.R3, retx, "post"),
		asm.LoadMem(asm.R4, asm.R10, sNow, asm.DWord),
		asm.Sub.Reg(asm.R4, asm.R2),
		asm.LoadImm(asm.R5, int64(synTimeout), asm.DWord),
		asm.JGE.Reg(asm.R4, asm.R5, "post"),
		asm.AddAtomic.Mem(asm.R7, asm.R4, asm.DWord, vRTTSum),
		asm.Mov.Imm(asm.R1, 1),
		asm.AddAtomic.Mem(asm.R7, asm.R1, asm.DWord, vRTTN),
		asm.StoreImm(asm.R10, sEmit, 1, asm.Word),
		asm.Ja.Label("post"),
	)
}

// TrackKey is one connection, local side first.
type TrackKey struct {
	Local, Remote netip.AddrPort
}

// DecodeTrackKey reads a flow map key.
func DecodeTrackKey(k [TrackKeySize]byte) (TrackKey, error) {
	if k[0] != famV4 && k[0] != famV6 {
		return TrackKey{}, fmt.Errorf("tracker key has unknown family %d", k[0])
	}
	local := netip.AddrFrom16([16]byte(k[kLocal : kLocal+16])).Unmap()
	remote := netip.AddrFrom16([16]byte(k[kRemote : kRemote+16])).Unmap()
	return TrackKey{
		Local:  netip.AddrPortFrom(local, binary.BigEndian.Uint16(k[kLocalPort:])),
		Remote: netip.AddrPortFrom(remote, binary.BigEndian.Uint16(k[kRemotePort:])),
	}, nil
}

// Counters are the running counts of one connection. They only grow while
// the connection lives; Created tells a connection from an earlier one that
// used the same 4-tuple.
type Counters struct {
	Created, Segments, Retrans, Resets, RTTSamples uint64
	RTTSum                                         time.Duration
}

func decodeCounters(b []byte) Counters {
	u := func(off int) uint64 { return binary.NativeEndian.Uint64(b[off-vSegs:]) }
	return Counters{
		Segments:   u(vSegs),
		Retrans:    u(vRetrans),
		RTTSum:     time.Duration(u(vRTTSum)),
		RTTSamples: u(vRTTN),
		Resets:     u(vResets),
		Created:    u(vCreated),
	}
}

// TrackState is a connection as read from the table. SynAt and SynAckAt
// identify a pending local SYN or SYN-ACK (zero when none is pending);
// the ages and Idle are measured at the read.
type TrackState struct {
	Key TrackKey
	Counters
	SynAt, SynAckAt         uint64
	SynAge, SynAckAge, Idle time.Duration
}

// DecodeTrackState reads a flow map entry. now is the kernel clock
// (CLOCK_MONOTONIC) in nanoseconds when the entry was read.
func DecodeTrackState(key [TrackKeySize]byte, val [TrackValueSize]byte, now uint64) (TrackState, error) {
	k, err := DecodeTrackKey(key)
	if err != nil {
		return TrackState{}, err
	}
	st := TrackState{
		Key:      k,
		Counters: decodeCounters(val[vSegs : vCreated+8]),
		SynAt:    binary.NativeEndian.Uint64(val[vSynAt:]),
		SynAckAt: binary.NativeEndian.Uint64(val[vSynAckAt:]),
	}
	age := func(t uint64) time.Duration {
		if t == 0 || t > now {
			return 0
		}
		return time.Duration(now - t)
	}
	st.SynAge, st.SynAckAge = age(st.SynAt), age(st.SynAckAt)
	st.Idle = age(binary.NativeEndian.Uint64(val[vLast:]))
	return st, nil
}

// Summary is one ring buffer record: a connection's counters at the time
// of the report. Final is set when the kernel forgot the connection with
// it (a RST).
type Summary struct {
	Key TrackKey
	Counters
	Final bool
}

// DecodeSummary reads a ring buffer record. ok is false for a malformed one.
func DecodeSummary(rec []byte) (Summary, bool) {
	if len(rec) < SummarySize {
		return Summary{}, false
	}
	key, err := DecodeTrackKey([TrackKeySize]byte(rec[sumKey : sumKey+TrackKeySize]))
	if err != nil {
		return Summary{}, false
	}
	return Summary{
		Key:      key,
		Counters: decodeCounters(rec[:vCreated-vSegs+8]),
		Final:    binary.NativeEndian.Uint64(rec[sumFinal:]) != 0,
	}, true
}

// LocalKey is the LPM trie key of a local prefix.
type LocalKey struct {
	PrefixLen uint32
	Addr      [16]byte
}

// NewLocalKey is the trie key of p, with an IPv4 prefix in its mapped form.
func NewLocalKey(p netip.Prefix) LocalKey {
	p = p.Masked()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	return LocalKey{PrefixLen: uint32(bits), Addr: p.Addr().As16()}
}
