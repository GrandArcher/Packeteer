package main

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	checks "github.com/GrandArcher/Packeteer/internal/preflight"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func preflightConfig(t *testing.T, providers string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
` + providers + `
bgp:
  neighbors:
    - address: 127.0.0.1
announcer:
  type: gobgp
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// hopFrom answers the first-hop probe by source address.
func hopFrom(answers map[string]netip.Addr, errs map[string]error) pathHop {
	return func(_ context.Context, src, _ netip.Addr, _, _ int, _ time.Duration) (netip.Addr, bool, error) {
		return answers[src.String()], false, errs[src.String()]
	}
}

func TestPreflightProvidersCheckTheFirstHop(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the path check runs on Linux only")
	}
	cfg := preflightConfig(t, `
  - {name: ok, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: wrong, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
  - {name: silent, source_ip: 192.0.2.13, next_hop: 192.0.2.3}
  - {name: nosrc, source_ip: 192.0.2.14, next_hop: 192.0.2.4}
  - {name: opted-out, source_ip: 192.0.2.15, next_hop: 192.0.2.5, path_check: false}
  - {name: loop, source_ip: 127.0.0.1, next_hop: 192.0.2.6}
`)
	src := &preflightSource{live: &liveConfig{cfg: cfg}, log: discardLog(), hop: hopFrom(
		map[string]netip.Addr{"192.0.2.11": netip.MustParseAddr("192.0.2.1"), "192.0.2.12": netip.MustParseAddr("192.0.2.99")},
		map[string]error{"192.0.2.14": plugin.ErrSourceUnavailable},
	)}
	got := map[string]checks.Provider{}
	for _, p := range src.providers(context.Background(), cfg) {
		got[p.Name] = p
	}
	if p := got["ok"]; p.Egress != checks.EgressOK || p.FirstHop != "192.0.2.1" {
		t.Errorf("ok = %+v", p)
	}
	if p := got["wrong"]; p.Egress != checks.EgressMismatch || p.FirstHop != "192.0.2.99" {
		t.Errorf("wrong = %+v", p)
	}
	if p := got["silent"]; p.Egress != checks.EgressNoReply || p.Why != "no first hop answered" {
		t.Errorf("silent = %+v", p)
	}
	if p := got["nosrc"]; p.Egress != checks.EgressNoReply || !strings.Contains(p.Why, "not configured on this host") {
		t.Errorf("nosrc = %+v", p)
	}
	if p := got["opted-out"]; p.Egress != checks.EgressUnchecked || p.Why != "path_check is off for this provider" {
		t.Errorf("opted-out = %+v", p)
	}
	if p := got["loop"]; p.Egress != checks.EgressUnchecked || !strings.Contains(p.Why, "loopback") {
		t.Errorf("loop = %+v", p)
	}
	rep := checks.Run(checks.Facts{Providers: src.providers(context.Background(), cfg)}, time.Now())
	for _, r := range rep.Results {
		if r.ID == checks.CheckEgress && (r.Status != checks.Fail || !strings.Contains(r.Detail, "wrong: probes from 192.0.2.12 left through 192.0.2.99, expected 192.0.2.2")) {
			t.Errorf("egress result = %+v", r)
		}
	}
}

func TestPreflightProvidersSkipTheCheckWhenItIsOff(t *testing.T) {
	cfg := preflightConfig(t, `
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
`)
	off := false
	cfg.Probe.PathCheck.Enabled = &off
	src := &preflightSource{live: &liveConfig{cfg: cfg}, log: discardLog(), hop: hopFrom(nil, nil)}
	got := src.providers(context.Background(), cfg)
	if len(got) != 1 || got[0].Egress != checks.EgressUnchecked || (runtime.GOOS == "linux" && got[0].Why != "probe.path_check is off") {
		t.Fatalf("providers = %+v", got)
	}
}

func TestPreflightFingerprintFollowsASNCommunityAndRouters(t *testing.T) {
	cfg := preflightConfig(t, "  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}")
	base := preflightFingerprint(cfg)
	if again := preflightFingerprint(cfg); again != base {
		t.Fatal("fingerprint is not stable")
	}
	for name, mut := range map[string]func(*config.Config){
		"asn":       func(c *config.Config) { c.ASN = 64513 },
		"community": func(c *config.Config) { c.PacketeerCommunity = "64512:667" },
		"router": func(c *config.Config) {
			c.BGP.Neighbors = append(c.BGP.Neighbors, config.BGPNeighbor{Address: "192.0.2.253"})
		},
	} {
		next := *cfg
		next.BGP.Neighbors = append([]config.BGPNeighbor(nil), cfg.BGP.Neighbors...)
		mut(&next)
		if preflightFingerprint(&next) == base {
			t.Errorf("changing the %s kept the fingerprint, so a confirmation would survive", name)
		}
	}
	other := *cfg
	other.Providers = nil
	if preflightFingerprint(&other) != base {
		t.Error("providers must not void a filter confirmation")
	}
}

const gateCandidate = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
bgp:
  neighbors:
    - address: 127.0.0.1
`

func TestPreflightGateComparesTheCandidateWithTheRunningSetup(t *testing.T) {
	cfg := preflightConfig(t, "  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}")
	live := &liveConfig{cfg: cfg}
	src := func(context.Context) checks.Facts { return checks.Facts{Fingerprint: preflightFingerprint(cfg)} }
	api := preflightAPI{Runner: checks.NewRunner(src, nil, nil), live: live}

	var notReady *checks.NotReadyError
	if err := api.Gate(context.Background(), []byte(gateCandidate)); !errors.As(err, &notReady) || !notReady.Report.AnnouncerMissing {
		t.Fatalf("same setup: %v, want the checks to decide with no announcer", err)
	}
	if err := api.Gate(context.Background(), []byte(gateCandidate+"announcer:\n  type: gobgp\n")); !errors.As(err, &notReady) || notReady.Report.AnnouncerMissing {
		t.Fatalf("candidate with an announcer: %v, want the checks to count it", err)
	}
	for name, change := range map[string]func(string) string{
		"asn":       func(y string) string { return strings.Replace(y, "asn: 64512", "asn: 64513", 1) },
		"community": func(y string) string { return strings.Replace(y, "64512:666", "64512:667", 1) },
		"neighbor":  func(y string) string { return strings.Replace(y, "127.0.0.1", "127.0.0.2", 1) },
	} {
		if err := api.Gate(context.Background(), []byte(change(gateCandidate))); !errors.Is(err, checks.ErrSetupChanged) {
			t.Errorf("%s: %v, want ErrSetupChanged", name, err)
		}
	}
	if err := api.Gate(context.Background(), []byte("mode: [")); err == nil || errors.Is(err, checks.ErrSetupChanged) {
		t.Errorf("unparsable candidate: %v", err)
	}
}

// The announcer the guided inject step adds is a restart-only key, so the
// reload refuses the saved plan whole: the running observe process keeps
// announcing nothing until Packeteer restarts with the announcer.
func TestInjectStepAnnouncerWaitsForRestart(t *testing.T) {
	fresh := gateCandidate + "hold_time: 15m\nthresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}\n"
	plan, err := configedit.EnableInject(configedit.InjectInput{Allowlist: []string{"198.51.100.0/24"}, Announcer: configedit.Values{"type": "gobgp"}}, []byte(fresh))
	if err != nil {
		t.Fatal(err)
	}
	restart, _ := classify(mustParse(t, fresh), mustParse(t, plan.YAML))
	if !slices.Contains(restart, "announcer") {
		t.Fatalf("restart keys %v, want announcer", restart)
	}
}

// A real iBGP session to a simulated edge: the facts carry the established
// neighbor, the learned prefix count, and the negotiated hold time.
func TestPreflightFactsReadARealSession(t *testing.T) {
	port := freePort(t)
	edge := server.NewBgpServer(server.LoggerOption(quietLog{}))
	go edge.Serve()
	ctx := context.Background()
	if err := edge.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: 64512, RouterId: "192.0.2.254", ListenPort: int32(port), ListenAddresses: []string{"127.0.0.1"},
	}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = edge.StopBgp(context.Background(), &api.StopBgpRequest{})
		edge.Stop()
	})
	if err := edge.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 64512},
		Transport: &api.Transport{PassiveMode: true},
		Timers:    &api.Timers{Config: &api.TimersConfig{HoldTime: 9, KeepaliveInterval: 3}},
	}}); err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.1"})
	if _, err := edge.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{
		Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh},
	}}); err != nil {
		t.Fatal(err)
	}

	view, err := rib.New(rib.Options{
		ASN: 64512, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []rib.Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(port), LocalAddress: netip.MustParseAddr("127.0.0.2")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = view.Stop(context.Background()) })

	cfg := preflightConfig(t, "  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}")
	src := &preflightSource{live: &liveConfig{cfg: cfg}, view: view, log: discardLog(), hop: hopFrom(map[string]netip.Addr{"192.0.2.11": netip.MustParseAddr("192.0.2.1")}, nil)}
	var f checks.Facts
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		f = src.facts(ctx)
		if f.RIBReady && len(f.Timers) == 1 && f.Learned == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !f.RIBReady || f.Learned != 1 || len(f.Neighbors) != 1 || !f.Neighbors[0].Established {
		t.Fatalf("facts = %+v", f)
	}
	if f.Timers[0].Hold != 9*time.Second || f.Timers[0].LocalGR || f.TimersErr != "" {
		t.Fatalf("timers = %+v", f.Timers)
	}
	if f.Community != "64512:666" || f.Announcer || f.Leaks != 0 || f.Fingerprint != preflightFingerprint(cfg) {
		t.Fatalf("facts = %+v", f)
	}
	rep := checks.Run(f, time.Now())
	byID := map[string]checks.Result{}
	for _, r := range rep.Results {
		byID[r.ID] = r
	}
	if byID[checks.CheckSession].Status != checks.Warn || byID[checks.CheckTimers].Status != checks.Pass || byID[checks.CheckWithdrawal].Status != checks.Fail {
		t.Fatalf("results = %+v", byID)
	}
	if !strings.Contains(byID[checks.CheckWithdrawal].Fix, "announcer") {
		t.Fatalf("withdrawal fix = %q", byID[checks.CheckWithdrawal].Fix)
	}

	// The session drops: the session check names the neighbor and the timers are gone.
	_ = edge.StopBgp(ctx, &api.StopBgpRequest{})
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		f = src.facts(ctx)
		if len(f.Neighbors) == 1 && !f.Neighbors[0].Established {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if res := checks.Run(f, time.Now()).Results[0]; res.Status != checks.Fail || !strings.Contains(res.Detail, "127.0.0.1") {
		t.Fatalf("session after the edge stopped = %+v", res)
	}
}

// stubRouterCheck answers CheckFilters with fixed findings and records the
// queries.
type stubRouterCheck struct {
	plugin.Base
	findings []plugin.FilterFinding
	err      error
	queries  []plugin.FilterQuery
}

func (s *stubRouterCheck) CheckFilters(_ context.Context, q plugin.FilterQuery) ([]plugin.FilterFinding, error) {
	s.queries = append(s.queries, q)
	return s.findings, s.err
}

func TestPreflightReadsTheRouterWhenConfigured(t *testing.T) {
	cfg := preflightConfig(t, "  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1, path_check: false}")
	stub := &stubRouterCheck{findings: []plugin.FilterFinding{{Verdict: plugin.VerdictPass, Detail: "route-map packeteer-in permits only routes with 64512:666."}}}
	set := &pluginhost.Set{RouterCheck: &pluginhost.Instance[plugin.RouterCheck]{Name: "frr", Type: "frr", Plugin: stub}}
	src := &preflightSource{live: &liveConfig{cfg: cfg}, plugins: set, log: discardLog(), hop: hopFrom(nil, nil)}
	filters := func() checks.Result {
		for _, r := range checks.Run(src.facts(context.Background()), time.Now()).Results {
			if r.ID == checks.CheckFilters {
				return r
			}
		}
		t.Fatal("no import_filter result")
		return checks.Result{}
	}

	if r := filters(); r.Status != checks.Pass || !strings.Contains(r.Detail, "Read from the router (frr, read-only commands)") {
		t.Fatalf("import_filter = %+v", r)
	}
	want := plugin.FilterQuery{Community: "64512:666", Packeteer: netip.MustParseAddr("192.0.2.10")}
	if len(stub.queries) != 1 || stub.queries[0] != want {
		t.Fatalf("queries = %+v, want %+v", stub.queries, want)
	}

	stub.findings, stub.err = nil, errors.New("connect to the router socket: connection refused")
	if r := filters(); r.Status != checks.Unverified || !r.Confirmable || !strings.Contains(r.Detail, "could not verify the filters: connect to the router socket: connection refused.") {
		t.Fatalf("read error = %+v", r)
	}

	// With two routers the check reads neither.
	cfg.BGP.Neighbors = append(cfg.BGP.Neighbors, config.BGPNeighbor{Address: "192.0.2.253"})
	stub.queries = nil
	if r := filters(); r.Status != checks.Unverified || !strings.Contains(r.Detail, "it reads one router and bgp.neighbors has 2") || len(stub.queries) != 0 {
		t.Fatalf("two routers = %+v, queries %v", r, stub.queries)
	}

	// Off: the facts carry nothing from a router.
	src.plugins = &pluginhost.Set{}
	if f := src.facts(context.Background()); f.Router != nil {
		t.Fatalf("router facts with the check off: %+v", f.Router)
	}
}

func TestPreflightRouterCheckBuildsFromConfig(t *testing.T) {
	cfg, err := config.Parse([]byte(`mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - {name: a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
preflight:
  router_check:
    type: frr
    config:
      socket_env: PK_LAB_FRR_SOCKET
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	env := func(k string) string { return map[string]string{"PK_LAB_FRR_SOCKET": "/run/frr/bgpd.vty"}[k] }
	set, err := pluginhost.Build(cfg, pluginhost.Options{Logger: discardLog(), Getenv: env})
	if err != nil {
		t.Fatal(err)
	}
	if set.RouterCheck == nil || set.RouterCheck.Type != "frr" {
		t.Fatalf("router check = %+v", set.RouterCheck)
	}
	cfg.Preflight.RouterCheck.Type = "junos"
	if _, err := pluginhost.Build(cfg, pluginhost.Options{Logger: discardLog(), Getenv: env}); err == nil || !strings.Contains(err.Error(), "preflight.router_check") || !strings.Contains(err.Error(), "available: bird, frr, routeros") {
		t.Fatalf("unknown type = %v", err)
	}
}
