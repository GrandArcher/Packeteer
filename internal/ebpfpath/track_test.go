package ebpfpath

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func put64(b []byte, off int, v uint64) { binary.NativeEndian.PutUint64(b[off:], v) }

func trackKeyBytes(local, remote string, lport, rport uint16) [TrackKeySize]byte {
	var k [TrackKeySize]byte
	la, ra := netip.MustParseAddr(local), netip.MustParseAddr(remote)
	k[0] = famV4
	if la.Is6() {
		k[0] = famV6
	}
	binary.BigEndian.PutUint16(k[kLocalPort:], lport)
	binary.BigEndian.PutUint16(k[kRemotePort:], rport)
	l, r := la.As16(), ra.As16()
	copy(k[kLocal:], l[:])
	copy(k[kRemote:], r[:])
	return k
}

func TestTrackKeyDecode(t *testing.T) {
	for _, c := range []struct{ local, remote string }{
		{"192.0.2.10", "198.51.100.7"},
		{"2001:db8:1::10", "2001:db8:ffff::20"},
	} {
		got, err := DecodeTrackKey(trackKeyBytes(c.local, c.remote, 40000, 443))
		if err != nil {
			t.Fatal(err)
		}
		want := TrackKey{
			Local:  netip.AddrPortFrom(netip.MustParseAddr(c.local), 40000),
			Remote: netip.AddrPortFrom(netip.MustParseAddr(c.remote), 443),
		}
		if got != want {
			t.Errorf("key = %+v, want %+v", got, want)
		}
	}
	var bad [TrackKeySize]byte
	if _, err := DecodeTrackKey(bad); err == nil {
		t.Fatal("unknown family accepted")
	}
}

func TestSummaryDecode(t *testing.T) {
	rec := make([]byte, SummarySize)
	// Counters in the order of the flow map value.
	for i, v := range []uint64{276, 36, 480_000_000, 12, 2, 777} {
		put64(rec, i*8, v)
	}
	put64(rec, sumFinal, 1)
	k := trackKeyBytes("192.0.2.10", "198.51.100.7", 40000, 443)
	copy(rec[sumKey:], k[:])
	got, ok := DecodeSummary(rec)
	if !ok {
		t.Fatal("record rejected")
	}
	want := Summary{
		Key:      TrackKey{Local: netip.MustParseAddrPort("192.0.2.10:40000"), Remote: netip.MustParseAddrPort("198.51.100.7:443")},
		Counters: Counters{Segments: 276, Retrans: 36, RTTSum: 480 * time.Millisecond, RTTSamples: 12, Resets: 2, Created: 777},
		Final:    true,
	}
	if got != want {
		t.Fatalf("summary = %+v, want %+v", got, want)
	}
	if _, ok := DecodeSummary(rec[:SummarySize-1]); ok {
		t.Error("short record accepted")
	}
	copy(rec[sumKey:], make([]byte, TrackKeySize))
	if _, ok := DecodeSummary(rec); ok {
		t.Error("record with an unknown family accepted")
	}
}

func TestTrackStateDecode(t *testing.T) {
	val := make([]byte, TrackValueSize)
	put64(val, vSynAt, 900)
	put64(val, vSynAckAt, 1500) // after now: no age
	put64(val, vLast, 400)
	put64(val, vSegs, 5)
	put64(val, vRetrans, 1)
	put64(val, vCreated, 100)
	st, err := DecodeTrackState(trackKeyBytes("2001:db8:1::10", "2001:db8:ffff::20", 1, 2), [TrackValueSize]byte(val), 1000)
	if err != nil {
		t.Fatal(err)
	}
	if st.SynAt != 900 || st.SynAge != 100 || st.SynAckAge != 0 || st.Idle != 600 {
		t.Errorf("handshake state = %+v", st)
	}
	if st.Segments != 5 || st.Retrans != 1 || st.Created != 100 {
		t.Errorf("counters = %+v", st.Counters)
	}
}

func TestLocalKey(t *testing.T) {
	v4 := NewLocalKey(netip.MustParsePrefix("192.0.2.77/24"))
	if v4.PrefixLen != 96+24 || netip.AddrFrom16(v4.Addr) != netip.MustParseAddr("::ffff:192.0.2.0") {
		t.Errorf("v4 key = %+v", v4)
	}
	v6 := NewLocalKey(netip.MustParsePrefix("2001:db8:1::/48"))
	if v6.PrefixLen != 48 || netip.AddrFrom16(v6.Addr) != netip.MustParseAddr("2001:db8:1::") {
		t.Errorf("v6 key = %+v", v6)
	}
}
