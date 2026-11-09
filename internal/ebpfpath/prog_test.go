package ebpfpath

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func marshal(t *testing.T, insns asm.Instructions) int {
	t.Helper()
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, binary.LittleEndian); err != nil {
		t.Fatalf("marshal (unresolved jump label?): %v", err)
	}
	return buf.Len() / asm.InstructionSize
}

func TestProgramsAssemble(t *testing.T) {
	for name, insns := range map[string]asm.Instructions{
		"flow":    FlowProgram(3),
		"capture": CaptureProgram(4, 5),
	} {
		n := marshal(t, insns)
		if n < 20 || n > 4096 {
			t.Errorf("%s program has %d instructions", name, n)
		}
		last := insns[len(insns)-1]
		if last.OpCode.JumpOp() != asm.Exit {
			t.Errorf("%s program does not end with exit: %v", name, last)
		}
	}
}

// Every path out of both programs returns TCX_NEXT (-1): the
// program must never drop or redirect traffic.
func TestProgramsOnlyReturnNext(t *testing.T) {
	for name, insns := range map[string]asm.Instructions{
		"flow":    FlowProgram(3),
		"capture": CaptureProgram(4, 5),
	} {
		var r0 []int64
		for _, i := range insns {
			if i.Dst == asm.R0 && i.OpCode.ALUOp() == asm.Mov && i.OpCode.Class().IsALU() && i.OpCode.Source() == asm.ImmSource {
				r0 = append(r0, i.Constant)
			}
		}
		if len(r0) != 1 || r0[0] != tcxNext {
			t.Errorf("%s program sets r0 to %v, want only %d", name, r0, tcxNext)
		}
	}
}

func TestFlowKeyLayout(t *testing.T) {
	var k [KeySize]byte
	k[0], k[keyProto] = famV4, 17
	copy(k[keySrc:], netip.MustParseAddr("192.0.2.1").AsSlice())
	copy(k[keyDst:], netip.MustParseAddr("198.51.100.7").AsSlice())
	got, err := decodeKey(k)
	if err != nil {
		t.Fatal(err)
	}
	want := FlowKey{Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.7"), Proto: 17}
	if got != want {
		t.Fatalf("v4 key = %+v, want %+v", got, want)
	}
	k = [KeySize]byte{}
	k[0], k[keyProto] = famV6, 6
	copy(k[keySrc:], netip.MustParseAddr("2001:db8::1").AsSlice())
	copy(k[keyDst:], netip.MustParseAddr("2001:db8:1::2").AsSlice())
	got, err = decodeKey(k)
	if err != nil || got.Dst != netip.MustParseAddr("2001:db8:1::2") || got.Src != netip.MustParseAddr("2001:db8::1") || got.Proto != 6 {
		t.Fatalf("v6 key = %+v, %v", got, err)
	}
	k[0] = 0
	if _, err := decodeKey(k); err == nil {
		t.Fatal("unknown family accepted")
	}
}

func rec(wire, capLen uint32, payload int) []byte {
	b := make([]byte, recordHeader+payload)
	binary.NativeEndian.PutUint32(b[0:], wire)
	binary.NativeEndian.PutUint32(b[4:], capLen)
	for i := range payload {
		b[recordHeader+i] = byte(i)
	}
	return b
}

func TestFrame(t *testing.T) {
	f, ok := Frame(rec(1500, 60, SnapLen))
	if !ok || len(f) != 60 || f[59] != 59 {
		t.Fatalf("frame len=%d ok=%v", len(f), ok)
	}
	for name, b := range map[string][]byte{
		"short header":        {1, 2, 3},
		"zero capture":        rec(100, 0, SnapLen),
		"capture over snap":   rec(1500, SnapLen+1, SnapLen+8),
		"capture over record": rec(1500, 100, 50),
		"capture over wire":   rec(40, 60, SnapLen),
	} {
		if _, ok := Frame(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDiffer(t *testing.T) {
	a := FlowKey{Src: netip.MustParseAddr("192.0.2.1"), Dst: netip.MustParseAddr("198.51.100.7"), Proto: 17}
	b := FlowKey{Src: a.Src, Dst: netip.MustParseAddr("203.0.113.9"), Proto: 6}
	var d Differ
	got := d.Next(map[FlowKey]Totals{a: {Bytes: 1000, Packets: 10}})
	if len(got) != 1 || got[0].Bytes != 1000 || got[0].Packets != 10 {
		t.Fatalf("first = %+v", got)
	}
	got = d.Next(map[FlowKey]Totals{a: {Bytes: 1500, Packets: 12}, b: {Bytes: 60, Packets: 1}})
	m := map[FlowKey]Totals{}
	for _, x := range got {
		m[x.Key] = x.Totals
	}
	if len(m) != 2 || m[a] != (Totals{500, 2}) || m[b] != (Totals{60, 1}) {
		t.Fatalf("second = %+v", m)
	}
	if got := d.Next(map[FlowKey]Totals{a: {Bytes: 1500, Packets: 12}}); len(got) != 0 {
		t.Fatalf("idle flow reported: %+v", got)
	}
	// a was evicted and counted again from zero: the new value is all new.
	got = d.Next(map[FlowKey]Totals{a: {Bytes: 40, Packets: 1}})
	if len(got) != 1 || got[0].Totals != (Totals{40, 1}) {
		t.Fatalf("restarted counter = %+v", got)
	}
}
