package bmp

import (
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func TestPathsKeepMED(t *testing.T) {
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint32{64501, 64500})}),
		bgp.NewPathAttributeNextHop("203.0.113.11"),
		bgp.NewPathAttributeMultiExitDisc(40),
	}
	msg := bgp.NewBGPUpdateMessage(nil, attrs, []*bgp.IPAddrPrefix{prefix4("198.51.100.0/24")})
	got := paths(msg.Body.(*bgp.BGPUpdate))
	if len(got) != 1 || got[0].MED == nil || *got[0].MED != 40 {
		t.Fatalf("med path = %+v", got)
	}
	plain := v4Update("192.0.2.1", []uint32{64496}, "198.51.100.0/24")
	got = paths(plain.Body.(*bgp.BGPUpdate))
	if len(got) != 1 || got[0].MED != nil {
		t.Fatalf("absent med = %+v", got)
	}
	zero := bgp.NewBGPUpdateMessage(nil, append(attrs[:3], bgp.NewPathAttributeMultiExitDisc(0)), []*bgp.IPAddrPrefix{prefix4("198.51.100.0/24")})
	got = paths(zero.Body.(*bgp.BGPUpdate))
	if len(got) != 1 || got[0].MED == nil || *got[0].MED != 0 {
		t.Fatalf("med 0 = %+v", got)
	}
}
