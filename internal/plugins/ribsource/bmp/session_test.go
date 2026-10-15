package bmp

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// A statistics report decodes the router's Adj-RIB-In count per peer
// (#147).
func TestDecodePrefixCount(t *testing.T) {
	d := newDecoder(router, true, quietLog)
	ph := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
	evs, stop := d.message(ser(t, gobmp.NewBMPStatisticsReport(*ph, []gobmp.BMPStatsTLVInterface{
		gobmp.NewBMPStatsTLV32(gobmp.BMP_STAT_TYPE_REJECTED, 3),
		gobmp.NewBMPStatsTLV64(gobmp.BMP_STAT_TYPE_ADJ_RIB_IN, 4200),
	})))
	if stop || len(evs) != 1 {
		t.Fatalf("events = %+v stop = %v", evs, stop)
	}
	e := evs[0]
	if e.Kind != plugin.RIBPrefixCount || e.Prefixes != 4200 || e.Router != router ||
		e.Peer.Address != netip.MustParseAddr("192.0.2.21") {
		t.Fatalf("event = %+v", e)
	}
}

// Only the Adj-RIB-In type is a per-peer route count; other types and the
// Loc-RIB report are ignored.
func TestStatisticsWithoutAdjRIBInIgnored(t *testing.T) {
	d := newDecoder(router, true, quietLog)
	ph := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
	evs, _ := d.message(ser(t, gobmp.NewBMPStatisticsReport(*ph, []gobmp.BMPStatsTLVInterface{
		gobmp.NewBMPStatsTLV64(gobmp.BMP_STAT_TYPE_LOC_RIB, 7),
	})))
	if len(evs) != 0 {
		t.Fatalf("non Adj-RIB-In stats produced %+v", evs)
	}
	loc := peerHeader(t, gobmp.BMP_PEER_TYPE_LOCAL_RIB, 0, "0.0.0.0", 64512, "192.0.2.254")
	evs, _ = d.message(ser(t, gobmp.NewBMPStatisticsReport(*loc, []gobmp.BMPStatsTLVInterface{
		gobmp.NewBMPStatsTLV64(gobmp.BMP_STAT_TYPE_ADJ_RIB_IN, 7),
	})))
	if len(evs) != 0 {
		t.Fatalf("loc-rib stats produced %+v", evs)
	}
}

func TestPeerDownReason(t *testing.T) {
	cases := []struct {
		name   string
		reason uint8
		notif  *bgp.BGPMessage
		want   string
	}{
		{"remote no notification", gobmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION, nil, "remote system closed"},
		{"local no notification", gobmp.BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION, nil, "local system closed"},
		{"peer de-configured", gobmp.BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED, nil, "peer de-configured"},
		{"unknown", 9, nil, "unknown reason 9"},
		{"cease max prefixes", gobmp.BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION,
			bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil),
			"local system closed: Cease subcode 1 (maximum number of prefixes reached)"},
		{"remote hold timer", gobmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION,
			bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil),
			"remote system closed: notification 4/0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ph := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
			b := gobmp.NewBMPPeerDownNotification(*ph, c.reason, c.notif, nil)
			if got := peerDownReason(b.Body.(*gobmp.BMPPeerDownNotification)); got != c.want {
				t.Fatalf("reason = %q, want %q", got, c.want)
			}
		})
	}
}

// The peer-down event carries the decoded reason to the controller.
func TestDecodePeerDownCarriesReason(t *testing.T) {
	d := newDecoder(router, true, quietLog)
	ph := peerHeader(t, gobmp.BMP_PEER_TYPE_GLOBAL, 0, "192.0.2.21", 64496, "192.0.2.21")
	notif := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil)
	evs, _ := d.message(ser(t, gobmp.NewBMPPeerDownNotification(*ph, gobmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION, notif, nil)))
	if len(evs) != 1 || evs[0].Kind != plugin.RIBPeerDown || !strings.Contains(evs[0].Reason, "Cease subcode 1") {
		t.Fatalf("events = %+v", evs)
	}
}
