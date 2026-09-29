package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	gobgplog "github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type quietLog struct{}

func (quietLog) Panic(string, gobgplog.Fields) {}
func (quietLog) Fatal(string, gobgplog.Fields) {}
func (quietLog) Error(string, gobgplog.Fields) {}
func (quietLog) Warn(string, gobgplog.Fields)  {}
func (quietLog) Info(string, gobgplog.Fields)  {}
func (quietLog) Debug(string, gobgplog.Fields) {}
func (quietLog) SetLevel(gobgplog.LogLevel)    {}
func (quietLog) GetLevel() gobgplog.LogLevel   { return gobgplog.PanicLevel }

var v4 = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}

// edgeRouter is a simulated edge (GoBGP) that originates the operator's
// prefix 203.0.113.0/24 and peers with Packeteer at 127.0.0.2.
func edgeRouter(t *testing.T) (*server.BgpServer, int) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	srv := server.NewBgpServer(server.LoggerOption(quietLog{}))
	go srv.Serve()
	ctx := context.Background()
	if err := srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 64512, RouterId: "192.0.2.254", ListenPort: int32(port), ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 64512},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis:  []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: v4, Enabled: true}}},
	}}); err != nil {
		t.Fatal(err)
	}
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: "203.0.113.0", PrefixLen: 24})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	if _, err := srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.StopBgp(context.Background(), &api.StopBgpRequest{})
		srv.Stop()
	})
	return srv, port
}

// steerFromPacketeer returns the communities on Packeteer's path for the
// operator prefix, or nil when there is none.
func steerFromPacketeer(t *testing.T, srv *server.BgpServer) map[uint32]bool {
	t.Helper()
	var out map[uint32]bool
	err := srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: "127.0.0.2", Family: v4}, func(d *api.Destination) {
		if d.Prefix != "203.0.113.0/24" {
			return
		}
		for _, p := range d.Paths {
			if p.IsWithdraw {
				continue
			}
			out = map[uint32]bool{}
			for _, a := range p.Pattrs {
				var ca api.CommunitiesAttribute
				if a.MessageIs(&ca) && a.UnmarshalTo(&ca) == nil {
					for _, c := range ca.Communities {
						out[c] = true
					}
				}
			}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestDaemonInboundSteerAnnounceAndWithdraw runs the controller against a
// simulated edge: transit-a's inbound 95th is over commit, so the operator
// prefix is re-announced with the marker, transit-a's catalog communities,
// the packeteer community, and NO_EXPORT. Shutdown withdraws it while the
// session is still up.
func TestDaemonInboundSteerAnnounceAndWithdraw(t *testing.T) {
	srv, port := edgeRouter(t)
	dir := t.TempDir()
	usage := filepath.Join(dir, "usage.yaml")
	over := "providers:\n  - {name: transit-a, commit_mbps: 100, usage_mbps: 10, in_mbps: 150}\n  - {name: transit-b, commit_mbps: 100, usage_mbps: 10, in_mbps: 10}\n"
	if err := os.WriteFile(usage, []byte(over), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
http: {listen: ""}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["203.0.113.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
telemetry:
  - type: fixed
    config: {file: %s}
inbound:
  mode: inject
  prefixes: [203.0.113.0/24]
  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - {provider: transit-a, name: prepend-2, prepend: 2, communities: ["64512:1102", "64496:3"]}
        - {provider: transit-b, communities: ["64512:1202"]}
`, port, usage)
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, noEnv, &out, &logs) }()

	want := []uint32{64512<<16 | 666, 64512<<16 | 667, 64512<<16 | 1102, 64496<<16 | 3, 0xFFFFFF01}
	deadline := time.Now().Add(20 * time.Second)
	for {
		comms := steerFromPacketeer(t, srv)
		ok := comms != nil && len(comms) == len(want)
		for _, c := range want {
			ok = ok && comms[c]
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no steer route on the edge (comms %v)\n%s", comms, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	text := logs.String()
	if !strings.Contains(text, "inbound steer routes withdrawn") {
		t.Fatalf("shutdown did not withdraw steer routes:\n%s", text)
	}
	for !time.Now().After(deadline.Add(10 * time.Second)) {
		if steerFromPacketeer(t, srv) == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("steer route still on the edge after shutdown")
}

func TestEventWatchInbound(t *testing.T) {
	rec := &sink{}
	w := newEventWatch(rec, "inject")
	now := time.Now()
	steer := inbound.Steer{Provider: "transit-a", InMbps95: 150, CommitMbps: 100,
		Action: plugin.InboundAction{Provider: "transit-a", Name: "prepend-2", Prepend: 2, Communities: []string{"64512:1102"}}}
	w.inbound(now, "suggest", []inbound.Change{
		{Action: inbound.ActionSteer, Steer: steer, Reason: "over"},
		{Action: inbound.ActionRelease, Steer: steer, Reason: "under"},
	})
	evs := rec.take()
	if len(evs) != 2 || evs[0].Kind != plugin.EventInboundSteered || evs[1].Kind != plugin.EventInboundReleased {
		t.Fatalf("events = %+v", evs)
	}
	if !strings.Contains(evs[0].Message, "suggest: not announced") || evs[0].Fields["prepend"] != "2" ||
		evs[0].Fields["communities"] != "64512:1102" || evs[0].DedupKey() != evs[1].DedupKey() {
		t.Fatalf("steer event = %+v", evs[0])
	}
	var nilW *eventWatch
	nilW.inbound(now, "inject", []inbound.Change{{Action: inbound.ActionSteer}})
}
