package main

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const reloadBase = `
mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1m
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.21}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.22}
allowlist: {prefixes: ["198.51.100.0/24"]}
announcer: {type: gobgp}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, rtt_ms: 1}
http: {listen: ""}
`

func mustParse(t *testing.T, y string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestPlanReload(t *testing.T) {
	one := reloadBase + "bgp:\n  neighbors:\n    - {address: 192.0.2.251, description: edge-a}\n"
	cur := mustParse(t, one)

	// Comments and YAML style are not changes.
	same := strings.Replace(one, "probers:\n  - type: fixed\n    config:\n      paths:\n        - {provider: transit-a, rtt_ms: 1}\n",
		"probers:\n  - type: fixed # the lab prober\n    config: {paths: [{provider: transit-a, rtt_ms: 1}]}\n", 1)
	plan, err := planReload(cur, mustParse(t, same), nil)
	if err != nil || !plan.empty() {
		t.Fatalf("restyled config: %+v %v", plan, err)
	}

	// A neighbor added, with per-router lists: a new table.
	two := reloadBase + `bgp:
  neighbors:
    - {address: 192.0.2.251, description: edge-a, providers: [transit-a], next_hops: {transit-b: 192.0.2.252}}
    - {address: 192.0.2.252, description: edge-b, providers: [transit-b]}
`
	plan, err = planReload(cur, mustParse(t, two), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.remove) != 0 || len(plan.add) != 1 || plan.add[0].Address != netip.MustParseAddr("192.0.2.252") || !plan.newTable || len(plan.routers) != 2 {
		t.Fatalf("add plan = %+v", plan)
	}
	if e := plan.egress["transit-b"]; len(e) != 1 || e[0] != netip.MustParseAddr("192.0.2.252") {
		t.Fatalf("egress = %v", plan.egress)
	}
	// The same table, reordered, is not a new table.
	curTwo := mustParse(t, two)
	table, _ := routerExports(curTwo)
	plan, err = planReload(curTwo, mustParse(t, two), []plugin.RouterExport{table[1], table[0]})
	if err != nil || !plan.empty() {
		t.Fatalf("same table: %+v %v", plan, err)
	}

	// Session settings of one neighbor changed: only that one is reset.
	changed := strings.Replace(two, "{address: 192.0.2.252, description: edge-b,", "{address: 192.0.2.252, description: edge-b, add_path: true,", 1)
	plan, err = planReload(curTwo, mustParse(t, changed), table)
	if err != nil || len(plan.remove) != 1 || len(plan.add) != 1 || plan.remove[0] != plan.add[0].Address || plan.newTable {
		t.Fatalf("changed session plan = %+v %v", plan, err)
	}

	// Removed.
	plan, err = planReload(curTwo, cur, table)
	if err != nil || len(plan.remove) != 1 || len(plan.add) != 0 || !plan.newTable || plan.routers != nil {
		t.Fatalf("remove plan = %+v %v", plan, err)
	}

	for name, tc := range map[string]struct{ yaml, want string }{
		"asn":       {strings.Replace(one, "asn: 64512", "asn: 64513", 1), "changed asn"},
		"providers": {strings.Replace(one, "rtt_ms: 1}", "rtt_ms: 2}", 1), "changed probers"},
		"as_path":   {one + "  as_path: native\n", "changed bgp.as_path"},
		"listen":    {one + "  listen_port: 1179\n", "changed bgp.listen_port"},
		"two keys":  {strings.Replace(strings.Replace(one, "local_pref: 250", "local_pref: 300", 1), "hold_time: 1m", "hold_time: 2m", 1), "changed local_pref"},
	} {
		if _, err := planReload(cur, mustParse(t, tc.yaml), nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	// hold_time is online, so a file that also changes local_pref names only local_pref.
	mixed := strings.Replace(strings.Replace(one, "local_pref: 250", "local_pref: 300", 1), "hold_time: 1m", "hold_time: 2m", 1)
	if _, err := planReload(cur, mustParse(t, mixed), nil); err == nil || strings.Contains(err.Error(), "hold_time") {
		t.Fatalf("hold_time should apply online: %v", err)
	}
	// Each of these applies on the next reload. The plan names the key and does not refuse.
	onlineFiles := []struct{ name, yaml, key string }{
		{"hold_time", strings.Replace(one, "hold_time: 1m", "hold_time: 2m", 1), "hold_time"},
		{"thresholds", strings.Replace(one, "min_rtt_delta_ms: 15", "min_rtt_delta_ms: 10", 1), "thresholds"},
		{"cap", one + "max_improvements: 0\n", "max_improvements"},
		{"mode", strings.Replace(one, "mode: inject", "mode: observe\n", 1), "mode"},
		{"allowlist", strings.Replace(one, `allowlist: {prefixes: ["198.51.100.0/24"]}`, `allowlist: {prefixes: ["203.0.113.0/24"]}`, 1), "allowlist"},
		{"probe", one + "probe: {interval: 3s}\n", "probe.interval"},
		{"workers", one + "probe: {workers: 4}\n", "probe.workers"},
	}
	for _, tc := range onlineFiles {
		plan, err := planReload(cur, mustParse(t, tc.yaml), nil)
		if tc.name == "workers" {
			if err == nil || !strings.Contains(err.Error(), "changed probe.workers") {
				t.Errorf("workers: err = %v", err)
			}
			continue
		}
		if err != nil || !slices.Contains(plan.online, tc.key) {
			t.Errorf("%s: plan %+v err %v", tc.name, plan.online, err)
		}
	}
}

// originRouter is a simulated edge at addr that originates
// 198.51.100.0/24 via transit-a and peers with Packeteer at 127.0.0.2.
func originRouter(t *testing.T, addr, rid string) (*server.BgpServer, int) {
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
		Asn: 64512, RouterId: rid, ListenPort: int32(port), ListenAddresses: []string{addr},
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
	nlri, _ := anypb.New(&api.IPAddressPrefix{Prefix: "198.51.100.0", PrefixLen: 24})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "192.0.2.21"})
	if _, err := srv.AddPath(ctx, &api.AddPathRequest{Path: &api.Path{Family: v4, Nlri: nlri, Pattrs: []*anypb.Any{origin, nh}}}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.StopBgp(context.Background(), &api.StopBgpRequest{})
		srv.Stop()
	})
	return srv, port
}

// steered reports whether srv holds Packeteer's route for the lab prefix,
// and its next hop.
func steered(t *testing.T, srv *server.BgpServer) (string, bool) {
	t.Helper()
	var nh string
	found := false
	err := srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: "127.0.0.2", Family: v4}, func(d *api.Destination) {
		if d.Prefix != "198.51.100.0/24" {
			return
		}
		for _, p := range d.Paths {
			if p.IsWithdraw {
				continue
			}
			found = true
			for _, a := range p.Pattrs {
				var n api.NextHopAttribute
				if a.MessageIs(&n) && a.UnmarshalTo(&n) == nil {
					nh = n.NextHop
				}
			}
		}
	})
	if err != nil {
		return "", false
	}
	return nh, found
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Online reconfiguration against two simulated edges (#27): add a
// neighbor, replace the per-router table, refuse a restart-only change and
// a broken file, and remove the neighbor, all without resetting the first
// session. The steer is on the wire throughout except for the table swap,
// which withdraws and re-announces.
func TestReloadNeighborsOnline(t *testing.T) {
	edgeA, portA := originRouter(t, "127.0.0.1", "192.0.2.251")
	edgeB, portB := originRouter(t, "127.0.0.3", "192.0.2.252")
	nbrA := "    - {address: 127.0.0.1, port: " + strconv.Itoa(portA) + ", local_address: 127.0.0.2, description: edge-a"
	nbrB := "    - {address: 127.0.0.3, port: " + strconv.Itoa(portB) + ", local_address: 127.0.0.2, description: edge-b"
	v1 := reloadBase + "bgp:\n  neighbors:\n" + nbrA + "}\n"
	v2 := reloadBase + "bgp:\n  neighbors:\n" + nbrA + "}\n" + nbrB + "}\n"
	v3 := reloadBase + "bgp:\n  neighbors:\n" + nbrA + ", providers: [transit-a], next_hops: {transit-b: 127.0.0.3}}\n" + nbrB + ", providers: [transit-b]}\n"

	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(y string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(v1)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := newController(cfg, plugins, view, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := view.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = view.Stop(context.Background()) })
	if err := ctl.Bind(view.Server()); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	waitFor(t, "edge-a learned", func() bool { _, ok := view.Exact(prefix); return ok })
	imps := []policy.Improvement{{Prefix: prefix, Provider: "transit-b", Native: "transit-a"}}
	// A route already on the wire hides the edge's own path; after a
	// withdraw the prefix is back in the RIB only once the edge re-sends
	// it, and only then is it announced again (never a prefix outside
	// the RIB). The decision loop syncs on every RIB change; so does this.
	sync := func() {
		t.Helper()
		waitFor(t, "sync", func() bool { return ctl.Sync(ctx, imps) == nil && ctl.Active() == 1 })
	}
	sync()
	waitFor(t, "edge-a steered", func() bool { nh, ok := steered(t, edgeA); return ok && nh == "192.0.2.22" })
	sinceA := view.Peers()[0].Since

	var applied []*config.Config
	rl := &reloader{path: path, getenv: noEnv, log: log, cur: cfg, view: view, ctl: ctl,
		applied: func(c *config.Config) { applied = append(applied, c) }}
	reload := func() {
		t.Helper()
		_, refused, fatal := rl.reload(ctx)
		if refused != nil || fatal != nil {
			t.Fatalf("reload: refused %v fatal %v", refused, fatal)
		}
	}
	edgeAUntouched := func() {
		t.Helper()
		for _, p := range view.Peers() {
			if p.Address == netip.MustParseAddr("127.0.0.1") && (!p.Established || !p.Since.Equal(sinceA)) {
				t.Fatalf("edge-a session was reset: %+v", p)
			}
		}
	}

	// 1. Add edge-b, no lists: it gets the steer, edge-a keeps it.
	write(v2)
	reload()
	waitFor(t, "edge-b steered", func() bool { nh, ok := steered(t, edgeB); return ok && nh == "192.0.2.22" })
	if _, ok := steered(t, edgeA); !ok {
		t.Fatal("edge-a lost the steer when edge-b was added")
	}
	edgeAUntouched()
	if len(applied) != 1 || len(applied[0].BGP.Neighbors) != 2 {
		t.Fatalf("applied after adding edge-b = %d configs", len(applied))
	}

	// 2. Per-router lists: transit-b is edge-b's; edge-a reaches it via
	// edge-b. The swap withdraws, the next sync re-announces per router.
	write(v3)
	reload()
	sync()
	waitFor(t, "edge-a via edge-b", func() bool { nh, ok := steered(t, edgeA); return ok && nh == "127.0.0.3" })
	waitFor(t, "edge-b direct", func() bool { nh, ok := steered(t, edgeB); return ok && nh == "192.0.2.22" })
	if d := view.EgressDown(); len(d) != 0 {
		t.Fatalf("egress down = %v", d)
	}
	edgeAUntouched()

	// 3. A restart-only change and a broken file are refused; nothing moves.
	write(strings.Replace(v3, "local_pref: 250", "local_pref: 300", 1))
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil || !strings.Contains(refused.Error(), "changed local_pref") {
		t.Fatalf("restart-only change: refused %v fatal %v", refused, fatal)
	}
	write("mode: [")
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil {
		t.Fatalf("broken file: refused %v fatal %v", refused, fatal)
	}
	if nh, ok := steered(t, edgeA); !ok || nh != "127.0.0.3" {
		t.Fatalf("edge-a after refused reloads: %q %v", nh, ok)
	}
	if len(applied) != 2 {
		t.Fatalf("a refused reload was reported applied: %d", len(applied))
	}

	// 4. Remove edge-b: its session closes, edge-a goes back to one table.
	write(v1)
	reload()
	sync()
	waitFor(t, "edge-a direct again", func() bool { nh, ok := steered(t, edgeA); return ok && nh == "192.0.2.22" })
	waitFor(t, "edge-b session closed", func() bool { _, ok := steered(t, edgeB); return !ok })
	if len(view.Peers()) != 1 {
		t.Fatalf("peers = %+v", view.Peers())
	}
	edgeAUntouched()

	// 5. Nothing changed: no-op.
	reload()
	if err := ctl.WithdrawAll(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "edge-a withdrawn", func() bool { _, ok := steered(t, edgeA); return !ok })
}

// TestReloadCoreOnline applies a threshold, a cap of 0, an allowlist
// shrink, and a mode change against a simulated edge (#128). A valid
// improvement stays on the wire. A cap of 0 and an allowlist that no
// longer covers the prefix withdraw it. An invalid file and a restart-only
// key are refused by name.
func TestReloadCoreOnline(t *testing.T) {
	edge, port := originRouter(t, "127.0.0.1", "192.0.2.251")
	base := reloadBase + "bgp:\n  neighbors:\n    - {address: 127.0.0.1, port: " + strconv.Itoa(port) + ", local_address: 127.0.0.2, description: edge-a}\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(y string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(base)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	view, err := newRIB(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := newController(cfg, plugins, view, nil, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := view.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = view.Stop(context.Background()) })
	if err := ctl.Bind(view.Server()); err != nil {
		t.Fatal(err)
	}
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	waitFor(t, "prefix learned", func() bool { _, ok := view.Exact(prefix); return ok })

	round := func(now time.Time) []policy.Change {
		t.Helper()
		in := policy.Input{
			Results: []probe.Result{
				{Provider: "transit-a", Prefix: prefix, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 50 * time.Millisecond}},
				{Provider: "transit-b", Prefix: prefix, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: 20 * time.Millisecond}},
			},
			ProviderUp: map[string]bool{"transit-a": true, "transit-b": true},
			RIBEnabled: true, RIBReady: true,
			Native: map[netip.Prefix]string{prefix: "transit-a"},
		}
		changes := decider.Evaluate(in, now)
		if err := ctl.Sync(ctx, decider.Improvements()); err != nil {
			t.Fatal(err)
		}
		return changes
	}
	now := time.Now()
	round(now)
	if len(decider.Improvements()) != 1 {
		t.Fatalf("improvements = %+v", decider.Improvements())
	}
	waitFor(t, "steered", func() bool { nh, ok := steered(t, edge); return ok && nh == "192.0.2.22" })

	rl := &reloader{
		path: path, getenv: noEnv, log: log, cur: cfg, view: view, ctl: ctl,
		decider: decider, plugins: plugins,
		opts: pluginhost.Options{Logger: log, Getenv: noEnv},
	}
	reload := func(key string) {
		t.Helper()
		applied, refused, fatal := rl.reload(ctx)
		if refused != nil || fatal != nil {
			t.Fatalf("reload %s: refused %v fatal %v", key, refused, fatal)
		}
		if !slices.Contains(applied, key) {
			t.Fatalf("applied = %v, want %s", applied, key)
		}
	}
	refuse := func(y, key string) {
		t.Helper()
		write(y)
		_, refused, fatal := rl.reload(ctx)
		if fatal != nil || refused == nil || !strings.Contains(refused.Error(), key) {
			t.Fatalf("refused %v fatal %v, want %q", refused, fatal, key)
		}
	}

	low := strings.Replace(base, "min_rtt_delta_ms: 15", "min_rtt_delta_ms: 10", 1)
	write(low)
	reload("thresholds")
	round(now.Add(time.Second))
	if nh, ok := steered(t, edge); !ok || nh != "192.0.2.22" || ctl.Active() != 1 {
		t.Fatalf("threshold change moved the route: nh %q ok %v active %d", nh, ok, ctl.Active())
	}

	write(low + "max_improvements: 0\n")
	reload("max_improvements")
	round(now.Add(2 * time.Second))
	if len(decider.Improvements()) != 0 {
		t.Fatalf("cap 0 left %+v", decider.Improvements())
	}
	waitFor(t, "withdrawn by cap 0", func() bool { _, ok := steered(t, edge); return !ok })

	write(base)
	reload("max_improvements")
	round(now.Add(3 * time.Second))
	waitFor(t, "route after the cap is restored", func() bool { nh, ok := steered(t, edge); return ok && nh == "192.0.2.22" })

	shrunk := strings.Replace(base, `allowlist: {prefixes: ["198.51.100.0/24"]}`, `allowlist: {prefixes: ["203.0.113.0/24"]}`, 1)
	write(shrunk)
	reload("allowlist")
	changes := round(now.Add(4 * time.Second))
	retired := false
	for _, c := range changes {
		if c.Action == policy.ActionRetire && strings.Contains(c.Old.Reason, "not allowlisted") {
			retired = true
		}
	}
	if !retired {
		t.Fatalf("allowlist shrink did not retire: %+v", changes)
	}
	waitFor(t, "withdrawn by allowlist", func() bool { _, ok := steered(t, edge); return !ok })

	refuse("mode: [", "yaml")
	refuse(strings.Replace(shrunk, "local_pref: 250", "local_pref: 300", 1), "changed local_pref")
	if _, ok := steered(t, edge); ok {
		t.Fatal("a refused reload announced the route")
	}

	write(base)
	reload("allowlist")
	round(now.Add(5 * time.Second))
	waitFor(t, "route restored", func() bool { nh, ok := steered(t, edge); return ok && nh == "192.0.2.22" })

	write(strings.Replace(base, "mode: inject", "mode: observe", 1))
	reload("mode")
	if ctl.Active() != 0 {
		t.Fatal("leaving inject left a route announced")
	}
	waitFor(t, "withdrawn by observe", func() bool { _, ok := steered(t, edge); return !ok })

	write(base)
	reload("mode")
	round(now.Add(6 * time.Second))
	waitFor(t, "route after inject", func() bool { nh, ok := steered(t, edge); return ok && nh == "192.0.2.22" })
}

// TestReloadSourcesPoliciesAndProbe starts and stops only the plugins that
// changed, and applies probe timing, without a BGP session (#128).
func TestReloadSourcesPoliciesAndProbe(t *testing.T) {
	base := `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.21}
sources:
  - type: static
    name: one
    config: {targets: [{prefix: 198.51.100.0/24}]}
  - type: static
    name: two
    config: {targets: [{prefix: 203.0.113.0/24}]}
probe: {interval: 2s, timeout: 200ms, packets: 2}
http: {listen: ""}
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	write := func(y string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(base)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := plugins.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plugins.Stop(context.Background()) })
	engine, err := newEngine(cfg, plugins, log, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		t.Fatal(err)
	}
	byName := func(name string) plugin.TargetSource {
		t.Helper()
		for _, s := range plugins.SourcesSnapshot() {
			if s.Name == name {
				return s.Plugin
			}
		}
		t.Fatalf("source %s missing", name)
		return nil
	}
	one, two := byName("one"), byName("two")
	rl := &reloader{
		path: path, getenv: noEnv, log: log, cur: cfg, plugins: plugins, engine: engine, decider: decider,
		opts: pluginhost.Options{Logger: log, Getenv: noEnv},
	}
	reload := func(key string) {
		t.Helper()
		applied, refused, fatal := rl.reload(ctx)
		if refused != nil || fatal != nil {
			t.Fatalf("reload %s: refused %v fatal %v", key, refused, fatal)
		}
		if key != "" && !slices.Contains(applied, key) {
			t.Fatalf("applied = %v, want %s", applied, key)
		}
	}

	added := strings.Replace(base, "name: two\n    config: {targets: [{prefix: 203.0.113.0/24}]}",
		"name: two\n    config: {targets: [{prefix: 203.0.113.0/24}]}\n  - type: static\n    name: three\n    config: {targets: [{prefix: 192.0.2.0/24}]}", 1)
	write(added)
	reload("sources")
	if byName("one") != one || byName("two") != two {
		t.Fatal("an added source restarted the others")
	}
	targets, err := byName("three").Targets(ctx)
	if err != nil || len(targets) != 1 || targets[0].Prefix != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("three: %+v %v", targets, err)
	}

	changed := strings.Replace(added, "{prefix: 198.51.100.0/24}", "{prefix: 198.51.100.0/25}", 1)
	write(changed)
	reload("sources")
	if byName("one") == one {
		t.Fatal("a changed source kept the old instance")
	}
	if byName("two") != two {
		t.Fatal("changing one source restarted another")
	}
	one = byName("one")

	timed := strings.Replace(changed, "interval: 2s", "interval: 5s", 1)
	write(timed)
	reload("probe.interval")
	if engine.TimingNow().Interval != 5*time.Second {
		t.Fatalf("interval = %s", engine.TimingNow().Interval)
	}
	if byName("one") != one || byName("two") != two {
		t.Fatal("probe timing restarted sources")
	}

	withPolicy := timed + "policies:\n  - type: rules\n    name: pins\n    config: {rules: [{name: skip, action: ignore, prefixes: [198.51.100.0/25]}]}\n"
	write(withPolicy)
	reload("policies")
	if len(plugins.PoliciesSnapshot()) != 1 || plugins.PoliciesSnapshot()[0].Name != "pins" {
		t.Fatalf("policies = %+v", plugins.PoliciesSnapshot())
	}
	pol := plugins.PoliciesSnapshot()[0].Plugin
	write(strings.Replace(withPolicy, "name: skip", "name: drop", 1))
	reload("policies")
	if plugins.PoliciesSnapshot()[0].Plugin == pol {
		t.Fatal("a changed policy kept the old instance")
	}
	write(timed)
	reload("policies")
	if len(plugins.PoliciesSnapshot()) != 0 {
		t.Fatal("removing the policy left it running")
	}

	write("mode: [")
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil {
		t.Fatalf("broken file: refused %v fatal %v", refused, fatal)
	}
	write(strings.Replace(timed, "asn: 64512", "asn: 64513", 1))
	if _, refused, fatal := rl.reload(ctx); fatal != nil || refused == nil || !strings.Contains(refused.Error(), "changed asn") {
		t.Fatalf("asn: refused %v fatal %v", refused, fatal)
	}
	if engine.TimingNow().Interval != 5*time.Second || byName("three") == nil {
		t.Fatal("a refused reload changed the running config")
	}
}
