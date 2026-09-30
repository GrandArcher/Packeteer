package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// haEdge is a simulated edge (GoBGP) with two Packeteer instances as iBGP
// neighbors: pk-a from 127.0.0.2 and pk-b from 127.0.0.3. Its 3s hold time
// wins against Packeteer's 90s proposal. Packeteer's routes get local
// preference 50, so the edge's own path stays best and it keeps advertising
// the prefix to both instances.
type haEdge struct {
	t    *testing.T
	srv  *server.BgpServer
	port int
}

var haPeers = []string{"127.0.0.2", "127.0.0.3"}

func newHAEdge(t *testing.T) *haEdge {
	t.Helper()
	port := freePort(t)
	srv := server.NewBgpServer(server.LoggerOption(quietLog{}))
	go srv.Serve()
	ctx := context.Background()
	if err := srv.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 64512, RouterId: "192.0.2.254", ListenPort: int32(port), ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatal(err)
	}
	e := &haEdge{t: t, srv: srv, port: port}
	for _, p := range haPeers {
		e.addPeer(p)
	}
	if err := srv.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_NEIGHBOR, Name: "packeteer", List: []string{"127.0.0.2/32", "127.0.0.3/32"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddPolicy(ctx, &api.AddPolicyRequest{Policy: &api.Policy{Name: "from-packeteer", Statements: []*api.Statement{{
		Name:       "low",
		Conditions: &api.Conditions{NeighborSet: &api.MatchSet{Name: "packeteer"}},
		Actions:    &api.Actions{RouteAction: api.RouteAction_ACCEPT, LocalPref: &api.LocalPrefAction{Value: 50}},
	}}}}); err != nil {
		t.Fatal(err)
	}
	if err := srv.AddPolicyAssignment(ctx, &api.AddPolicyAssignmentRequest{Assignment: &api.PolicyAssignment{
		Name: "global", Direction: api.PolicyDirection_IMPORT, Policies: []*api.Policy{{Name: "from-packeteer"}}, DefaultAction: api.RouteAction_ACCEPT,
	}}); err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	if _, err := srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.StopBgp(context.Background(), &api.StopBgpRequest{})
		srv.Stop()
	})
	return e
}

func (e *haEdge) addPeer(addr string) {
	e.t.Helper()
	if err := e.srv.AddPeer(context.Background(), &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: addr, PeerAsn: 64512},
		Transport: &api.Transport{PassiveMode: true},
		Timers:    &api.Timers{Config: &api.TimersConfig{HoldTime: 3, KeepaliveInterval: 1}},
		AfiSafis:  []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: v4, Enabled: true}}},
	}}); err != nil {
		e.t.Fatal(err)
	}
}

// dropPeer tears down one instance's session (session loss).
func (e *haEdge) dropPeer(addr string) {
	e.t.Helper()
	if err := e.srv.DeletePeer(context.Background(), &api.DeletePeerRequest{Address: addr}); err != nil {
		e.t.Fatal(err)
	}
}

// routes lists, per instance address, the Packeteer routes the edge holds
// from it. Every route must be the learned prefix toward transit-b with
// the packeteer community and NO_EXPORT.
func (e *haEdge) routes() map[string][]string {
	out := map[string][]string{}
	for _, peer := range haPeers {
		err := e.srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: peer, Family: v4}, func(d *api.Destination) {
			for _, p := range d.Paths {
				if p.IsWithdraw {
					continue
				}
				var nh string
				comms := map[uint32]bool{}
				for _, a := range p.Pattrs {
					var ca api.CommunitiesAttribute
					var na api.NextHopAttribute
					switch {
					case a.MessageIs(&ca) && a.UnmarshalTo(&ca) == nil:
						for _, c := range ca.Communities {
							comms[c] = true
						}
					case a.MessageIs(&na) && a.UnmarshalTo(&na) == nil:
						nh = na.NextHop
					}
				}
				if d.Prefix != "198.51.100.0/24" || !comms[64512<<16|666] || !comms[0xFFFFFF01] || nh != "192.0.2.2" {
					e.t.Errorf("%s from %s: next hop %s, communities %v", d.Prefix, peer, nh, comms)
				}
				out[peer] = append(out[peer], d.Prefix)
			}
		})
		if err != nil && !strings.Contains(err.Error(), "doesn't exist") {
			e.t.Fatal(err)
		}
	}
	return out
}

// haInstance is one controller of the pair.
type haInstance struct {
	id, addr string
	http     int
	cancel   context.CancelFunc
	done     chan int
	logs     *syncBuf
}

func startHA(t *testing.T, edge *haEdge, lease, id, addr, routerID string) *haInstance {
	t.Helper()
	in := &haInstance{id: id, addr: addr, http: freePort(t), done: make(chan int, 1), logs: &syncBuf{}}
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: %s
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["198.51.100.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: %s}
announcer: {type: gobgp}
ha:
  type: lease
  config: {path: %s, id: %s, ttl: 2s, renew: 400ms}
`, routerID, in.http, edge.port, addr, lease, id)
	path := filepath.Join(t.TempDir(), id+".yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	in.cancel = cancel
	var out syncBuf
	go func() { in.done <- run(ctx, []string{"-config", path}, noEnv, &out, in.logs) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-in.done:
		case <-time.After(20 * time.Second):
		}
	})
	return in
}

func (in *haInstance) stop(t *testing.T) {
	t.Helper()
	in.cancel()
	select {
	case code := <-in.done:
		if code != 0 {
			t.Fatalf("%s exit %d\n%s", in.id, code, in.logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("%s did not stop", in.id)
	}
}

// role reads /api/ha.
func (in *haInstance) role() (role, holder string) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/ha", in.http))
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	var v struct{ Role, Holder string }
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return "", ""
	}
	return v.Role, v.Holder
}

// TestDaemonHAActiveStandby runs two controllers in inject against one
// simulated edge with a shared lease (#31). Only the active one ever has
// routes on the edge: the standby announces nothing while the active one
// runs; session loss on the active one withdraws and hands over; a clean
// shutdown withdraws, resigns, and hands back; shutting down the last
// instance leaves nothing on the edge. A sampler fails the test if the
// edge ever holds routes from both at once.
func TestDaemonHAActiveStandby(t *testing.T) {
	if testing.Short() {
		t.Skip("daemon HA test")
	}
	edge := newHAEdge(t)
	lease := filepath.Join(t.TempDir(), "ha", "lease.json")
	a := startHA(t, edge, lease, "pk-a", "127.0.0.2", "192.0.2.10")

	waitOnly := func(what, addr string, logs ...*syncBuf) {
		t.Helper()
		deadline := time.Now().Add(40 * time.Second)
		for {
			r := edge.routes()
			ok := len(r) == 1 && slices.Equal(r[addr], []string{"198.51.100.0/24"})
			if addr == "" {
				ok = len(r) == 0
			}
			if ok {
				return
			}
			if time.Now().After(deadline) {
				var l strings.Builder
				for _, b := range logs {
					l.WriteString(b.String())
				}
				t.Fatalf("timed out waiting for %s: edge has %v\n%s", what, r, l.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	stayOnly := func(what, addr string, d time.Duration) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			r := edge.routes()
			if len(r) != 1 || len(r[addr]) != 1 {
				t.Fatalf("%s: edge has %v, want only %s", what, r, addr)
			}
		}
	}
	waitRole := func(in *haInstance, want, holder string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			r, h := in.role()
			if r == want && (holder == "" || h == holder) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: role %s holder %s, want %s %s\n%s", in.id, r, h, want, holder, in.logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	waitOnly("pk-a to announce", "127.0.0.2", a.logs)
	waitRole(a, "active", "pk-a")

	b := startHA(t, edge, lease, "pk-b", "127.0.0.3", "192.0.2.20")
	waitRole(b, "standby", "pk-a")
	// From here on nothing starts a BGP speaker in this process (GoBGP's
	// StartBgp races ListPath on another server in its own globals).
	var both atomic.Bool
	var bothAt atomic.Value
	stopSampler := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stopSampler:
				return
			case <-time.After(50 * time.Millisecond):
			}
			r := edge.routes()
			if len(r["127.0.0.2"]) > 0 && len(r["127.0.0.3"]) > 0 {
				both.Store(true)
				bothAt.Store(fmt.Sprint(r))
			}
		}
	}()
	defer func() {
		close(stopSampler)
		wg.Wait()
		if both.Load() {
			t.Errorf("the edge held routes from both instances: %v", bothAt.Load())
		}
	}()

	// The standby measures and has the prefix in its RIB, but announces
	// nothing, for longer than a lease takeover would take.
	stayOnly("standby must not announce", "127.0.0.2", 8*time.Second)
	if !strings.Contains(b.logs.String(), "ha lease elector started") {
		t.Fatalf("pk-b logs:\n%s", b.logs.String())
	}

	// Session loss on the active instance: its routes go with the
	// session, it steps down and resigns, and pk-b takes over.
	edge.dropPeer("127.0.0.2")
	waitOnly("pk-b to take over after pk-a lost its session", "127.0.0.3", a.logs, b.logs)
	waitRole(b, "active", "pk-b")
	waitRole(a, "standby", "")
	if !strings.Contains(a.logs.String(), "ha: standby; Packeteer routes withdrawn") {
		t.Fatalf("pk-a did not step down:\n%s", a.logs.String())
	}

	// pk-a's session is back: it is eligible but stays standby.
	edge.addPeer("127.0.0.2")
	waitRole(a, "standby", "pk-b")
	stayOnly("recovered standby must not announce", "127.0.0.3", 8*time.Second)

	// Clean shutdown of the active instance: withdraw, resign, and pk-a
	// takes over without waiting for the lease to run out.
	stopped := time.Now()
	b.stop(t)
	waitOnly("pk-a to take over after pk-b stopped", "127.0.0.2", a.logs, b.logs)
	if d := time.Since(stopped); d > 15*time.Second {
		t.Fatalf("takeover after a clean shutdown took %s", d)
	}
	for _, want := range []string{"ha: shutting down; Packeteer routes withdrawn", "ha: lease released"} {
		if !strings.Contains(b.logs.String(), want) {
			t.Fatalf("pk-b logs lack %q:\n%s", want, b.logs.String())
		}
	}

	a.stop(t)
	waitOnly("no Packeteer routes after both stopped", "")
}
