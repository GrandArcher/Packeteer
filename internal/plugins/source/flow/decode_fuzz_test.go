package flow

import (
	"net/netip"
	"testing"
	"time"
)

// fuzzDecode feeds one input twice to a fresh decoder, so templates from the
// first pass meet data in the second, and checks what bounds its memory.
func fuzzDecode(t *testing.T, p []byte, dec func(*decoder, netip.Addr, time.Time, []byte) ([]observation, error)) {
	d := &decoder{}
	for i := 0; i < 2; i++ {
		obs, _ := dec(d, boundsExporter, time.Time{}, p)
		if len(obs) > len(p) {
			t.Fatalf("%d observations from %d bytes", len(obs), len(p))
		}
		for _, o := range obs {
			if !o.dst.IsValid() || o.bytes == 0 {
				t.Fatalf("observation %+v", o)
			}
		}
		putObs(obs)
		checkDecoder(t, d)
	}
}

func FuzzDecodeIPFIX(f *testing.F) {
	dst := netip.MustParseAddr("198.51.100.7")
	f.Add(buildIPFIX(1, sampledTemplate(), sampledData()))
	f.Add(buildIPFIX(1, sampledTemplate(), sampledData(), tmplSetIPFIX(2, nil)))
	f.Add(buildIPFIX(3, ipfixEnterpriseTemplate(256), dataSet(256, []byte{0x11, 0x22, 0x33, 0x44, 0x04}, putU32(500), v4only(dst))))
	f.Add(buildIPFIX(1, hugeTemplateSet(2), hugeTemplateSet(3)))
	f.Add(buildIPFIX(1, tmplSetIPFIX(256, [][2]uint16{{ieDstV6, 16}, {ieOutBytes, 8}}), dataSet(256, ip6rec(netip.MustParseAddr("2001:db8::7"), 64))))
	f.Fuzz(func(t *testing.T, p []byte) {
		fuzzDecode(t, p, (*decoder).decodeIPFIX)
	})
}

func FuzzDecodeV9(f *testing.F) {
	dst := netip.MustParseAddr("203.0.113.4")
	opt := optionsSetV9(257, 4, [][2]uint16{{1, 4}}, [][2]uint16{{ieSamplingInterval, 4}})
	flowT := tmplSetV9(256, [][2]uint16{{ieOutBytes, 4}, {ieDstV4, 4}, {ieInBytes, 4}})
	f.Add(buildV9(7, opt, flowT, dataSet(257, putU32(0), putU32(10)), dataSet(256, putU32(1), v4only(dst), putU32(25))))
	f.Add(buildV9(7, flowT, dataSet(256, putU32(1), v4only(dst), putU32(25)), tmplSetV9(0, nil)))
	f.Add(buildV9(7, hugeTemplateSet(0)))
	f.Fuzz(func(t *testing.T, p []byte) {
		fuzzDecode(t, p, (*decoder).decodeV9)
	})
}

func FuzzDecodeV5(f *testing.F) {
	f.Add(buildV5(0, []v5rec{{netip.MustParseAddr("198.51.100.7"), 1500}, {netip.MustParseAddr("203.0.113.4"), 40}}))
	f.Add(buildV5(0x4000|100, []v5rec{{netip.MustParseAddr("192.0.2.9"), ^uint32(0)}}))
	f.Add(buildV5(0, []v5rec{{netip.MustParseAddr("198.51.100.7"), 1500}})[:60])
	f.Fuzz(func(t *testing.T, p []byte) {
		fuzzDecode(t, p, func(_ *decoder, _ netip.Addr, _ time.Time, p []byte) ([]observation, error) { return decodeV5(p) })
	})
}

func FuzzSFlow(f *testing.F) {
	src, dst := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7")
	f.Add(buildSFlowV4(512, src, dst, 1400))
	f.Add(buildSFlowV6(1, netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:100::7"), 900))
	f.Add(buildSFlowEthernet(dst, 600))
	f.Add(sflowPackets(256, src, dst, 0x02, 0x10, 0x04))
	f.Fuzz(func(t *testing.T, p []byte) {
		fuzzDecode(t, p, func(_ *decoder, _ netip.Addr, _ time.Time, p []byte) ([]observation, error) { return decodeSFlow(p) })
	})
}
