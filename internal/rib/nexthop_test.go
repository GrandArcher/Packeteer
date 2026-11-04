package rib

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

// TestShortNextHopTreatedAsWithdraw sends the GO-2026-4736 trigger (GoBGP
// issue 3305: a NEXT_HOP shorter than 4 bytes) to the embedded speaker.
// GoBGP v4 before v4.4.0 panics in bgp.ValidateUpdateMsg on it. v3.37.0
// replaces the UPDATE with a withdraw of its NLRI before validating, so the
// session stays up and only that prefix leaves the view. A GoBGP upgrade
// that brings the panic back fails here with the panic.
func TestShortNextHopTreatedAsWithdraw(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(ln.Addr().(*net.TCPAddr).Port)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// A raw iBGP neighbor: GoBGP will not encode a malformed attribute.
	send := func(m *bgp.BGPMessage) {
		t.Helper()
		b, err := m.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	send(bgp.NewBGPOpenMessage(asn, 90, "192.0.2.254", []bgp.OptionParameterInterface{bgp.NewOptionParameterCapability(
		[]bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC), bgp.NewCapFourOctetASNumber(asn)})}))
	send(bgp.NewBGPKeepAliveMessage())
	eventually(t, "session established", v.Ready)

	pfx := netip.MustParsePrefix("192.0.2.0/24")
	valid := bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{64496})}),
		bgp.NewPathAttributeNextHop("192.0.2.1"),
	}, []*bgp.IPAddrPrefix{bgp.NewIPAddrPrefix(24, "192.0.2.0")})
	learned := func() bool { _, ok := v.Exact(pfx); return ok }
	send(valid)
	eventually(t, "prefix learned", learned)

	// The same prefix with a 2-byte NEXT_HOP.
	short := append(bytes.Repeat([]byte{0xff}, 16),
		0x00, 0x27, bgp.BGP_MSG_UPDATE, 0x00, 0x00, 0x00, 0x0c,
		0x40, 0x01, 0x01, 0x00,
		0x40, 0x02, 0x00,
		0x40, 0x03, 0x02, 0xc0, 0x00,
		0x18, 0xc0, 0x00, 0x02)
	if _, err := conn.Write(short); err != nil {
		t.Fatal(err)
	}
	eventually(t, "prefix withdrawn", func() bool { return !learned() })
	if !v.Ready() {
		t.Fatal("session dropped; want treat-as-withdraw with the session up")
	}
	send(valid)
	eventually(t, "prefix learned again on the same session", learned)
}
