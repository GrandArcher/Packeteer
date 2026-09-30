package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

// msEdge is a simulated edge (GoBGP) for more-specific injection (#56).
// An import policy lowers the local preference of Packeteer's routes to 50,
// so the edge's own path stays best and it keeps advertising it to
// Packeteer (as FRR's weight does in the lab): a later DeletePath is a real
// RIB leave, not a best-path hide.
type msEdge struct {
	t    *testing.T
	srv  *server.BgpServer
	port int
	mu   sync.Mutex
	adv  map[string]*api.Path
	ever map[string]bool // every prefix the edge has advertised
}

func newMSEdge(t *testing.T) *msEdge {
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
	if err := srv.AddDefinedSet(ctx, &api.AddDefinedSetRequest{DefinedSet: &api.DefinedSet{
		DefinedType: api.DefinedType_NEIGHBOR, Name: "packeteer", List: []string{"127.0.0.2/32"},
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
	t.Cleanup(func() {
		_ = srv.StopBgp(context.Background(), &api.StopBgpRequest{})
		srv.Stop()
	})
	return &msEdge{t: t, srv: srv, port: port, adv: map[string]*api.Path{}, ever: map[string]bool{}}
}

func (e *msEdge) advertise(prefixes ...string) {
	e.t.Helper()
	for _, s := range prefixes {
		p := netip.MustParsePrefix(s)
		nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())})
		origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
		nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
		path := &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}
		if _, err := e.srv.AddPath(context.Background(), &api.AddPathRequest{Path: path}); err != nil {
			e.t.Fatal(err)
		}
		e.mu.Lock()
		e.adv[s] = path
		e.ever[s] = true
		e.mu.Unlock()
	}
}

func (e *msEdge) withdraw(prefixes ...string) {
	e.t.Helper()
	for _, s := range prefixes {
		e.mu.Lock()
		path := e.adv[s]
		delete(e.adv, s)
		e.mu.Unlock()
		if err := e.srv.DeletePath(context.Background(), &api.DeletePathRequest{Family: v4, Path: path}); err != nil {
			e.t.Fatal(err)
		}
	}
}

// fromPacketeer lists the prefixes Packeteer has on the edge, sorted. It
// fails the test on a route for a prefix the edge never advertised, or
// one that lacks the packeteer community, NO_EXPORT, or transit-b's next
// hop. (A prefix the edge just withdrew stays until the leave is
// confirmed; waitWire checks that it then goes.)
func (e *msEdge) fromPacketeer() []string {
	e.t.Helper()
	var out []string
	err := e.srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: "127.0.0.2", Family: v4}, func(d *api.Destination) {
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
			if !comms[64512<<16|666] || !comms[0xFFFFFF01] || nh != "192.0.2.2" {
				e.t.Errorf("%s from Packeteer: next hop %s, communities %v", d.Prefix, nh, comms)
			}
			out = append(out, d.Prefix)
		}
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, p := range out {
		if !e.ever[p] {
			e.t.Errorf("Packeteer announced %s, which the edge never advertised", p)
		}
	}
	slices.Sort(out)
	return out
}

// TestDaemonMoreSpecificLearnedOnlyCapLeaveShutdown runs the controller in
// inject with more_specific on and max_routes 3 against a simulated edge.
// Only prefixes the edge advertises reach it; a second improvement waits
// at the cap, whole; a real RIB leave of a more-specific withdraws it; the
// first improvement leaving withdraws its more-specifics and makes room;
// shutdown withdraws everything.
func TestDaemonMoreSpecificLearnedOnlyCapLeaveShutdown(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24", "203.0.113.0/25", "203.0.113.128/26")
	httpPort := freePort(t)
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["198.51.100.0/24", "203.0.113.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}, {prefix: 203.0.113.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
more_specific: {enabled: true, max_routes: 3}
`, httpPort, edge.port)
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, func(string) string { return "" }, &out, &logs) }()

	waitWire := func(what string, want ...string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			got := edge.fromPacketeer()
			if slices.Equal(got, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s: edge has %v, want %v\n%s", what, got, want, logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	stayWire := func(what string, d time.Duration, want ...string) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			if got := edge.fromPacketeer(); !slices.Equal(got, want) {
				t.Fatalf("%s: edge has %v, want %v\n%s", what, got, want, logs.String())
			}
		}
	}

	first := []string{"203.0.113.0/24", "203.0.113.0/25", "203.0.113.128/26"}
	waitWire("the improvement and its learned more-specifics", first...)
	if !strings.Contains(out.String(), "announce more_specific: learned more-specifics only, max_routes=3") {
		t.Fatalf("startup summary lacks more_specific:\n%s", out.String())
	}

	// A second /24 with one learned more-specific needs 2 routes; 3 of 3
	// are in use. Neither is announced.
	edge.advertise("198.51.100.0/24", "198.51.100.0/25")
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(logs.String(), "more_specific.max_routes (3) reached: 198.51.100.0/24 needs 2 routes, 3 in use") {
		if time.Now().After(deadline) {
			t.Fatalf("no route-cap refusal for 198.51.100.0/24:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Past policy.NativePathConfirm, so the next leave is a confirmed one.
	stayWire("at the route cap", 6*time.Second, first...)

	// A real RIB leave of a more-specific withdraws only that route. 2
	// routes in use + 2 needed is still over the cap.
	edge.withdraw("203.0.113.128/26")
	waitWire("the more-specific withdrawn after it left the RIB", "203.0.113.0/24", "203.0.113.0/25")
	if !strings.Contains(logs.String(), `msg="more-specific left the RIB; withdrawn" prefix=203.0.113.128/26 improvement=203.0.113.0/24`) {
		t.Fatalf("no leave log for 203.0.113.128/26:\n%s", logs.String())
	}
	stayWire("after the more-specific left", 3*time.Second, "203.0.113.0/24", "203.0.113.0/25")

	// The improvement's own prefix leaves: it and its more-specific (still
	// learned) are withdrawn, and the waiting improvement fits whole.
	edge.withdraw("203.0.113.0/24")
	waitWire("room for the second improvement", "198.51.100.0/24", "198.51.100.0/25")

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	waitWire("every route gone after shutdown")
}
