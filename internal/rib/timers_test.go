package rib

import (
	"context"
	"net/netip"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
)

func routerWithTimers(t *testing.T, peer *api.Peer) *fakeRouter {
	t.Helper()
	r := &fakeRouter{srv: server.NewBgpServer(quiet()), port: freePort(t)}
	go r.srv.Serve()
	ctx := context.Background()
	if err := r.srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: asn, RouterId: "192.0.2.254", ListenPort: int32(r.port), ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatal(err)
	}
	peer.Conf = &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: asn}
	peer.Transport = &api.Transport{PassiveMode: true}
	if err := r.srv.AddPeer(ctx, &api.AddPeerRequest{Peer: peer}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.stop)
	return r
}

func TestSessionTimersReportNegotiatedHoldTime(t *testing.T) {
	r := routerWithTimers(t, &api.Peer{Timers: &api.Timers{Config: &api.TimersConfig{HoldTime: 9, KeepaliveInterval: 3}}})
	v := newView(t, r)
	ctx := context.Background()
	got, err := v.SessionTimers(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("before the session is up: %v, %v", got, err)
	}
	eventually(t, "session up", v.Ready)
	eventually(t, "timers read", func() bool {
		got, _ = v.SessionTimers(ctx)
		return len(got) == 1
	})
	if got[0].Address != netip.MustParseAddr("127.0.0.1") || got[0].HoldTime != 9*time.Second {
		t.Fatalf("timers = %+v, want 127.0.0.1 with a 9s hold time", got[0])
	}
	if got[0].LocalGR || got[0].RouterGR {
		t.Fatalf("graceful restart reported with none configured: %+v", got[0])
	}
}

func TestSessionTimersSeeRouterGracefulRestartNotOurs(t *testing.T) {
	r := routerWithTimers(t, &api.Peer{GracefulRestart: &api.GracefulRestart{Enabled: true, RestartTime: 120}})
	v := newView(t, r)
	eventually(t, "session up", v.Ready)
	var got []SessionTimers
	eventually(t, "timers read", func() bool {
		got, _ = v.SessionTimers(context.Background())
		return len(got) == 1
	})
	if !got[0].RouterGR {
		t.Fatalf("router graceful restart capability not seen: %+v", got[0])
	}
	if got[0].LocalGR {
		t.Fatalf("Packeteer advertised graceful restart: %+v", got[0])
	}
}

func TestSessionTimersNilView(t *testing.T) {
	var v *View
	if got, err := v.SessionTimers(context.Background()); err != nil || got != nil {
		t.Fatalf("nil view = %v, %v", got, err)
	}
}
