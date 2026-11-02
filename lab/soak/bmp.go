package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	gobmp "github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

// A profile with bmp: true plays the edge router's BMP client instead of
// an iBGP peer (#237). Packeteer has no bgp.neighbors: its RIB view is
// this feed alone. The router connects to Packeteer's station from
// routerAddrs[id], reports one BGP peer up per provider next hop and
// family, and sends every entry in the post-policy Adj-RIB-In of each
// provider's peer: the native path and the inactive one through the other
// provider, two paths a prefix, as a two-transit edge reports them.

// bmpProviders is how many providers have a peer: table.provider is 0 or 1
// on the synthetic table.
const bmpProviders = 2

// bmpDialWait is how long the router keeps trying to reach the station
// while Packeteer starts.
const bmpDialWait = 2 * time.Minute

func newBMPRouter(id, port int, tbl table, adv *advertised) *router {
	return &router{id: id, tbl: tbl, adv: adv, bmpPort: port, out: newAdjOut()}
}

// bmpPeerAS is the provider peer's AS, a documentation ASN.
func bmpPeerAS(prov int) uint32 { return docASNs[prov] }

// bmpPeer is the per-peer header of provider prov's session in one
// family: the post-policy Adj-RIB-In of a global peer.
func bmpPeer(prov int, v4 bool) *gobmp.BMPPeerHeader {
	addr := nextHopsV6[prov]
	if v4 {
		addr = nextHopsV4[prov]
	}
	return gobmp.NewBMPPeerHeader(gobmp.BMP_PEER_TYPE_GLOBAL, gobmp.BMP_PEER_FLAG_POST_POLICY, 0, addr,
		bmpPeerAS(prov), nextHopsV4[prov], float64(time.Now().Unix()))
}

// dialBMP opens the BMP session: Initiation, then a peer up for every
// provider peer. readLoop notices the station closing it.
func (r *router) dialBMP() error {
	d := net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(routerAddrs[r.id])}}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(r.bmpPort))
	deadline := time.Now().Add(bmpDialWait)
	var c net.Conn
	for {
		var err error
		if c, err = d.Dial("tcp", addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("router %d: bmp: %w", r.id, err)
		}
		time.Sleep(time.Second)
	}
	msgs := []*gobmp.BMPMessage{gobmp.NewBMPInitiation([]gobmp.BMPInfoTLVInterface{
		gobmp.NewBMPInfoTLVString(gobmp.BMP_INIT_TLV_TYPE_SYS_NAME, "soak-router"),
	})}
	for prov := range bmpProviders {
		for _, v4 := range []bool{true, false} {
			local := "2001:db8:ffff::fe"
			if v4 {
				local = routerIDs[r.id]
			}
			sent := bgp.NewBGPOpenMessage(labASN, holdTime, routerIDs[r.id], nil)
			recv := bgp.NewBGPOpenMessage(uint16(bmpPeerAS(prov)), holdTime, nextHopsV4[prov], nil)
			msgs = append(msgs, gobmp.NewBMPPeerUpNotification(*bmpPeer(prov, v4), local, 179, 179, sent, recv))
		}
	}
	for _, m := range msgs {
		b, err := m.Serialize()
		if err == nil {
			_, err = c.Write(b)
		}
		if err != nil {
			_ = c.Close()
			return fmt.Errorf("router %d: bmp: %w", r.id, err)
		}
	}
	ended := make(chan struct{})
	r.mu.Lock()
	r.c, r.ended = c, ended
	r.mu.Unlock()
	r.up.Store(true)
	log.Printf("router %d: bmp session to %s up", r.id, addr)
	go r.readLoop(c, ended)
	return nil
}

// bmpRoutes is the route monitoring for entries [i, j): the update from
// every provider's peer with that provider's next hop.
func (r *router) bmpRoutes(i, j int, withdraw bool) ([][]byte, error) {
	if native := r.tbl.provider(i); native < 0 || native >= bmpProviders {
		return nil, errors.New("bmp: entry without a provider peer")
	}
	v4 := i < r.tbl.v4n()
	out := make([][]byte, 0, bmpProviders)
	add := func(h *gobmp.BMPPeerHeader, m *bgp.BGPMessage) error {
		b, err := gobmp.NewBMPRouteMonitoring(*h, m).Serialize()
		out = append(out, b)
		return err
	}
	for prov := range bmpProviders {
		if err := add(bmpPeer(prov, v4), r.messageVia(i, j, withdraw, prov)); err != nil {
			return nil, err
		}
	}
	return out, nil
}
