package httpapi

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/rib"
)

// BMP peers (#237): one up series per peer a BMP session reports, and the
// router's Adj-RIB-In count only where a Statistics Report gave one.
func TestMetricsBMPPeers(t *testing.T) {
	in := sampleInput()
	n := 950000
	edge := netip.MustParseAddr("192.0.2.254")
	in.BMPPeers = []rib.BMPPeer{
		{Router: edge, Peer: netip.MustParseAddr("192.0.2.21"), AdjRIBIn: &n},
		{Router: edge, LocRIB: true},
	}
	text := string(Metrics(Assemble(in)))
	for _, want := range []string{
		`packeteer_bmp_peer_up{router="192.0.2.254",peer="192.0.2.21"} 1`,
		`packeteer_bmp_peer_up{router="192.0.2.254",peer="loc-rib"} 1`,
		`packeteer_bmp_peer_adj_rib_in{router="192.0.2.254",peer="192.0.2.21"} 950000`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if strings.Contains(text, `packeteer_bmp_peer_adj_rib_in{router="192.0.2.254",peer="loc-rib"}`) {
		t.Error("a peer without a Statistics Report has a count")
	}
	in.BMPPeers = nil
	if text := string(Metrics(Assemble(in))); strings.Contains(text, "packeteer_bmp_peer") {
		t.Error("BMP series without a BMP peer")
	}
}
