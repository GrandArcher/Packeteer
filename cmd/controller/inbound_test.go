package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
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
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
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
	dir := t.TempDir()
	usage := filepath.Join(dir, "usage.yaml")
	over := "providers:\n  - {name: transit-a, commit_mbps: 100, usage_mbps: 10, in_mbps: 150}\n  - {name: transit-b, commit_mbps: 100, usage_mbps: 10, in_mbps: 10}\n"
	if err := os.WriteFile(usage, []byte(over), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf(`probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
telemetry:
  - type: fixed
    config: {file: %s}
`, usage)
	logs := runInboundDaemon(t, dir, extra, "", []uint32{64512<<16 | 1102, 64496<<16 | 3})
	if !strings.Contains(logs, "trigger=commit") {
		t.Fatalf("steer was not a commit steer:\n%s", logs)
	}
}

// TestDaemonInboundPerformanceSteer: no telemetry, transit-a's probes are
// 200 ms slower than transit-b's, so the performance trigger steers away
// from transit-a. The outbound thresholds are out of reach, so nothing
// else is announced. Shutdown withdraws the steer.
func TestDaemonInboundPerformanceSteer(t *testing.T) {
	extra := `probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 210}, {provider: transit-b, rtt_ms: 10}]}
sources:
  - type: static
    config:
      targets:
        - {prefix: 198.51.100.0/24}
        - {prefix: 192.0.2.128/25}
`
	perf := "  performance: {latency_ms: 100, min_prefixes: 2}\n"
	logs := runInboundDaemon(t, t.TempDir(), extra, perf, []uint32{64512<<16 | 1102, 64496<<16 | 3})
	if !strings.Contains(logs, "trigger=performance") {
		t.Fatalf("steer was not a performance steer:\n%s", logs)
	}
}

// runInboundDaemon runs the controller in inject against a simulated edge
// until the steer route away from transit-a (catalog communities away)
// reaches the edge, then stops it and waits for the withdraw. It returns
// the logs.
func runInboundDaemon(t *testing.T, dir, extra, inboundExtra string, away []uint32) string {
	t.Helper()
	srv, port := edgeRouter(t)
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}
http: {listen: ""}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["203.0.113.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
%s
inbound:
  mode: inject
  prefixes: [203.0.113.0/24]
  damping: {confirm: 1s, backoff: 2, max_hold: 8s}
%s  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - {provider: transit-a, name: prepend-2, prepend: 2, communities: ["64512:1102", "64496:3"]}
        - {provider: transit-b, communities: ["64512:1202"]}
`, port, extra, inboundExtra)
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, noEnv, &out, &logs) }()

	want := append([]uint32{64512<<16 | 666, 64512<<16 | 667, 0xFFFFFF01}, away...)
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
	if strings.Contains(text, `msg=injected`) {
		t.Fatalf("an outbound improvement was announced:\n%s", text)
	}
	for !time.Now().After(deadline.Add(10 * time.Second)) {
		if steerFromPacketeer(t, srv) == nil {
			return text
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("steer route still on the edge after shutdown")
	return ""
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
	perf := steer
	perf.Trigger, perf.Moderated, perf.Hold, perf.Flaps = inbound.TriggerPerformance, true, 10*time.Second, 1
	w.inbound(now, "inject", []inbound.Change{{Action: inbound.ActionSteer, Steer: perf, Reason: "worst"}})
	evs = rec.take()
	if len(evs) != 1 || !strings.Contains(evs[0].Message, "moderated: not announced") || evs[0].Fields["trigger"] != "performance" ||
		evs[0].Fields["hold"] != "10s" || evs[0].Fields["flaps"] != "1" || evs[0].Fields["moderated"] != "true" {
		t.Fatalf("moderated event = %+v", evs)
	}
	var nilW *eventWatch
	nilW.inbound(now, "inject", []inbound.Change{{Action: inbound.ActionSteer}})
}

func TestInboundInputKeepsMeasuredPathsFromLiveSources(t *testing.T) {
	now := time.Now()
	p := netip.MustParsePrefix("198.51.100.0/24")
	in := policy.Input{
		ProviderUp: map[string]bool{"transit-a": true, "transit-b": false},
		Results: []probe.Result{
			{Provider: "transit-a", Prefix: p, Stats: probe.Stats{Sent: 4, Received: 4, RTTAvg: 20 * time.Millisecond}, Time: now},
			{Provider: "transit-a", Prefix: netip.MustParsePrefix("192.0.2.0/25"), Err: "no route", Time: now},
			{Provider: "transit-b", Prefix: p, Stats: probe.Stats{Sent: 4, Received: 4}, Time: now},
		},
	}
	got := inboundInput(context.Background(), &pluginhost.Set{}, in)
	if len(got.Paths) != 1 || got.Paths[0].Provider != "transit-a" || got.Paths[0].RTT != 20*time.Millisecond {
		t.Fatalf("paths = %+v", got.Paths)
	}
}
