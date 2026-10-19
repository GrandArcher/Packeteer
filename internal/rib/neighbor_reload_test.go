package rib

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
)

// peerEvent is a session-state change as the speaker's watch stream reports it.
func peerEvent(addr string, st api.PeerState_SessionState) *api.WatchEventResponse {
	return &api.WatchEventResponse{Event: &api.WatchEventResponse_Peer{Peer: &api.WatchEventResponse_PeerEvent{
		Peer: &api.Peer{State: &api.PeerState{NeighborAddress: addr, SessionState: st}},
	}}}
}

// A reload adds and removes a neighbor while the watch goroutine keeps
// delivering peer events (#378). The neighbor lookup in handleEvent must
// hold mu; without it -race reports the read against AddNeighbors and
// RemoveNeighbors writes, and a real map race is a fatal runtime error.
func TestPeerEventsDuringNeighborReload(t *testing.T) {
	v, err := New(Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: 179, LocalAddress: netip.MustParseAddr("127.0.0.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	dyn := Neighbor{Address: netip.MustParseAddr("127.0.0.3"), Port: 179, LocalAddress: netip.MustParseAddr("127.0.0.4")}

	const rounds = 300
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range rounds {
			st := api.PeerState_ESTABLISHED
			if i%2 == 1 {
				st = api.PeerState_ACTIVE
			}
			v.handleEvent(peerEvent("127.0.0.1", st))
			v.handleEvent(peerEvent("127.0.0.3", st))
		}
	}()
	go func() {
		defer wg.Done()
		for range rounds {
			if err := v.AddNeighbors(context.Background(), []Neighbor{dyn}); err != nil {
				t.Error(err)
				return
			}
			if err := v.RemoveNeighbors(context.Background(), []netip.Addr{dyn.Address}); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()

	// The last RemoveNeighbors ran after every event the goroutines sent,
	// so an event for the removed neighbor must not have re-created its peer.
	peers := v.Peers()
	if len(peers) != 1 || peers[0].Address != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("peers after reload = %+v, want only 127.0.0.1", peers)
	}
}
