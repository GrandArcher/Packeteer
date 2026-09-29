package bmp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// The recorded stream is a synthetic edge (router 127.0.0.1 in the
// station tests) with documentation prefixes and ASNs only. Routes are
// post-policy Adj-RIB-In and Loc-RIB; one pre-policy and one Adj-RIB-Out
// message must be ignored:
//
//	transit-a 192.0.2.21 AS 64496, transit-b 192.0.2.22 AS 64497,
//	ix-peer   192.0.2.23 AS 64498 (negotiated add-path; must be ignored)
//
// Regenerate with: go test ./internal/plugins/ribsource/bmp -run TestRecordedStream -update
var update = flag.Bool("update", false, "rewrite testdata/synthetic.bmp")

const fixture = "testdata/synthetic.bmp"

// Stream checkpoints (message indexes, exclusive): after fullRIB every
// path is known; after withdrawn transit-b's extra prefixes are gone and
// its session is undecodable; the stream ends with a termination.
const (
	fullRIB   = 12
	withdrawn = 15
)

const stamp = 1790000000 // fixed timestamp so the fixture is reproducible

func peerHeader(t *testing.T, typ, flags uint8, addr string, as uint32, id string) *gobmp.BMPPeerHeader {
	t.Helper()
	return gobmp.NewBMPPeerHeader(typ, flags, 0, addr, as, id, stamp)
}

func open(as uint32, id string, addPath bool) *bgp.BGPMessage {
	caps := []bgp.ParameterCapabilityInterface{
		bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC),
		bgp.NewCapMultiProtocol(bgp.RF_IPv6_UC),
		bgp.NewCapFourOctetASNumber(as),
	}
	if addPath {
		caps = append(caps, bgp.NewCapAddPath([]*bgp.CapAddPathTuple{bgp.NewCapAddPathTuple(bgp.RF_IPv4_UC, bgp.BGP_ADD_PATH_BOTH)}))
	}
	return bgp.NewBGPOpenMessage(uint16(as), 90, id, []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(caps)})
}

func v4Update(nh string, path []uint32, nlri ...string) *bgp.BGPMessage {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, path)}),
		bgp.NewPathAttributeNextHop(nh),
	}
	var n []*bgp.IPAddrPrefix
	for _, s := range nlri {
		n = append(n, prefix4(s))
	}
	return bgp.NewBGPUpdateMessage(nil, attrs, n)
}

func prefix4(s string) *bgp.IPAddrPrefix {
	ip, bits := splitPrefix(s)
	return bgp.NewIPAddrPrefix(bits, ip)
}

func splitPrefix(s string) (string, uint8) {
	i := bytes.IndexByte([]byte(s), '/')
	var bits uint8
	for _, c := range s[i+1:] {
		bits = bits*10 + uint8(c-'0')
	}
	return s[:i], bits
}

func ser(t *testing.T, m *gobmp.BMPMessage) []byte {
	t.Helper()
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// corruptMonitoring is a route monitoring message whose BGP UPDATE claims
// more withdrawn-route bytes than it has.
func corruptMonitoring(t *testing.T, ph *gobmp.BMPPeerHeader) []byte {
	t.Helper()
	p, err := ph.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	upd := bytes.Repeat([]byte{0xff}, 16)
	upd = binary.BigEndian.AppendUint16(upd, 23)
	upd = append(upd, bgp.BGP_MSG_UPDATE, 0xff, 0xff, 0, 0)
	body := append(p, upd...)
	h := gobmp.BMPHeader{Version: gobmp.BMP_VERSION, Type: gobmp.BMP_MSG_ROUTE_MONITORING, Length: uint32(gobmp.BMP_HEADER_SIZE + len(body))}
	hb, _ := h.Serialize()
	return append(hb, body...)
}

// syntheticStream builds the recorded stream message by message.
func syntheticStream(t *testing.T) [][]byte {
	t.Helper()
	// Peer up and peer down carry clear flags, as FRR sends them; route
	// monitoring is post-policy. aPre (pre-policy) and aOut (Adj-RIB-Out)
	// routes must be ignored.
	post := uint8(gobmp.BMP_PEER_FLAG_POST_POLICY)
	aUp := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
	bUp := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.22", 64497, "192.0.2.22")
	ixUp := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.23", 64498, "192.0.2.23")
	a := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, post, "192.0.2.21", 64496, "192.0.2.21")
	b := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, post, "192.0.2.22", 64497, "192.0.2.22")
	ix := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, post, "192.0.2.23", 64498, "192.0.2.23")
	aPre := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
	aOut := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, gobmp.BMP_PEER_FLAG_ADJ_RIB_TYP|post, "192.0.2.21", 64496, "192.0.2.21")
	loc := peerHeader(t, gobmp.BMP_PEER_TYPE_LOCAL_RIB, 0, "0.0.0.0", 64512, "192.0.2.254")
	local := open(64512, "192.0.2.254", false)

	v6 := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{64497, 64500})}),
		bgp.NewPathAttributeMpReachNLRI("2001:db8::22", []bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(48, "2001:db8:100::")}),
	}, nil)
	unreach := bgp.NewBGPUpdateMessage([]*bgp.IPAddrPrefix{prefix4("203.0.113.0/24")}, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeMpUnreachNLRI([]bgp.AddrPrefixInterface{bgp.NewIPv6AddrPrefix(48, "2001:db8:100::")}),
	}, nil)

	return [][]byte{
		/* 0 */ ser(t, gobmp.NewBMPInitiation([]gobmp.BMPInfoTLVInterface{gobmp.NewBMPInfoTLVString(gobmp.BMP_INIT_TLV_TYPE_SYS_NAME, "edge")})),
		/* 1 */ ser(t, gobmp.NewBMPPeerUpNotification(*aUp, "192.0.2.254", 179, 40001, local, open(64496, "192.0.2.21", false))),
		/* 2 */ ser(t, gobmp.NewBMPPeerUpNotification(*bUp, "192.0.2.254", 179, 40002, local, open(64497, "192.0.2.22", false))),
		/* 3 */ ser(t, gobmp.NewBMPPeerUpNotification(*ixUp, "192.0.2.254", 179, 40003, open(64512, "192.0.2.254", true), open(64498, "192.0.2.23", true))),
		/* 4 */ ser(t, gobmp.NewBMPRouteMonitoring(*a, v4Update("192.0.2.21", []uint32{64496, 64500}, "198.51.100.0/24"))),
		// transit-b's path is inactive on the router (longer AS path).
		/* 5 */ ser(t, gobmp.NewBMPRouteMonitoring(*b, v4Update("192.0.2.22", []uint32{64497, 64497, 64500}, "198.51.100.0/24", "203.0.113.0/24"))),
		/* 6 */ ser(t, gobmp.NewBMPRouteMonitoring(*b, v6)),
		/* 7 */ ser(t, gobmp.NewBMPRouteMonitoring(*aPre, v4Update("192.0.2.21", []uint32{64496}, "192.0.2.0/25"))),
		/* 8 */ ser(t, gobmp.NewBMPRouteMonitoring(*aOut, v4Update("192.0.2.254", []uint32{64512}, "192.0.2.128/25"))),
		/* 9 */ ser(t, gobmp.NewBMPRouteMonitoring(*ix, v4Update("192.0.2.23", []uint32{64498}, "198.51.100.0/24"))),
		/* 10 */ ser(t, gobmp.NewBMPRouteMonitoring(*loc, v4Update("192.0.2.21", []uint32{64496, 64500}, "198.51.100.0/24"))),
		/* 11 */ ser(t, gobmp.NewBMPStatisticsReport(*aUp, []gobmp.BMPStatsTLVInterface{gobmp.NewBMPStatsTLV32(0, 1)})),
		/* 12 */ ser(t, gobmp.NewBMPRouteMonitoring(*b, unreach)),
		/* 13 */ corruptMonitoring(t, b),
		/* 14 */ ser(t, gobmp.NewBMPRouteMonitoring(*b, v4Update("192.0.2.22", []uint32{64497}, "198.51.100.0/24"))),
		/* 15 */ ser(t, gobmp.NewBMPPeerDownNotification(*aUp, gobmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION, nil, nil)),
		/* 16 */ ser(t, gobmp.NewBMPTermination([]gobmp.BMPTermTLVInterface{gobmp.NewBMPTermTLV16(gobmp.BMP_TERM_TLV_TYPE_REASON, gobmp.BMP_TERM_REASON_ADMIN)})),
	}
}

// recorded reads the fixture and splits it into messages.
func recorded(t *testing.T) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	if err := readMessages(bytes.NewReader(raw), func(m []byte) error { out = append(out, m); return nil }); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	return out
}

func TestRecordedStream(t *testing.T) {
	want := bytes.Join(syntheticStream(t), nil)
	if *update {
		if err := os.MkdirAll(filepath.Dir(fixture), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture, want, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is out of date; rerun with -update", fixture)
	}
	if n := len(recorded(t)); n != len(syntheticStream(t)) {
		t.Fatalf("fixture has %d messages, want %d", n, len(syntheticStream(t)))
	}
}
