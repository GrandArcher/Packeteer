package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/nonbgp"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// routerFake is the router the non-BGP tests steer: a table of tagged static
// routes, shared by every instance the factory builds.
type routerFake struct {
	plugin.Base
	mu     sync.Mutex
	routes map[netip.Prefix]netip.Addr
	// before runs ahead of each install, outside the lock; an error fails
	// the install. It stands in for a slow or failing router API.
	before func(netip.Prefix) error
}

var nonbgpRouter = &routerFake{routes: map[netip.Prefix]netip.Addr{}}

func init() {
	plugin.Steerers.Register("test-router", func(plugin.Config, plugin.Env) (plugin.Steerer, error) { return nonbgpRouter, nil })
}

func (r *routerFake) Install(_ context.Context, s plugin.SteerRoute) error {
	r.mu.Lock()
	before := r.before
	r.mu.Unlock()
	if before != nil {
		if err := before(s.Prefix); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[s.Prefix] = s.NextHop
	return nil
}

func (r *routerFake) Remove(_ context.Context, p netip.Prefix) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.routes, p)
	return nil
}

func (r *routerFake) Owned(context.Context) ([]netip.Prefix, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []netip.Prefix
	for p := range r.routes {
		out = append(out, p)
	}
	return out, nil
}

func (r *routerFake) reset() {
	r.mu.Lock()
	r.routes = map[netip.Prefix]netip.Addr{}
	r.before = nil
	r.mu.Unlock()
}

func (r *routerFake) snapshot() map[netip.Prefix]netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[netip.Prefix]netip.Addr{}
	for p, nh := range r.routes {
		out[p] = nh
	}
	return out
}

// flowFake stands in for the flow source: it records the prefix lookup the
// controller hands it.
type flowFake struct {
	plugin.Base
	lookup func(netip.Addr) (netip.Prefix, bool)
}

func (f *flowFake) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }
func (f *flowFake) SetPrefixLookup(fn func(netip.Addr) (netip.Prefix, bool)) {
	f.lookup = fn
}

const nonbgpTestConfig = `mode: %MODE%
asn: 64512
router_id: 192.0.2.10
hold_time: 1s
packeteer_community: "64512:666"
local_pref: 200
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 10}
http: {listen: ""}
providers:
  - {name: isp-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: isp-b, source_ip: 198.51.100.11, next_hop: 198.51.100.1}
allowlist: {prefixes: [198.51.100.0/24]}
probers:
  - type: icmp
sources:
  - type: flow
    config: {listen: "127.0.0.1:2055"}
nonbgp:
  install_routes: true
  default_provider: isp-a
  steerer: {type: test-router}
`

type nonbgpRig struct {
	cfg     *config.Config
	nb      *nonbgpState
	decider *policy.Engine
	flow    *flowFake
}

func newNonBGPRig(t *testing.T, mode string) *nonbgpRig {
	t.Helper()
	nonbgpRouter.reset()
	cfg, err := config.Parse([]byte(strings.Replace(nonbgpTestConfig, "%MODE%", mode, 1)))
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	flow := &flowFake{}
	set := &pluginhost.Set{
		Scorer:  &pluginhost.Instance[plugin.Scorer]{Name: "weighted", Type: "weighted", Plugin: scorer},
		Sources: []pluginhost.Instance[plugin.TargetSource]{{Name: "flow", Type: "flow", Plugin: flow}},
		Steerer: &pluginhost.Instance[plugin.Steerer]{Name: "test-router", Type: "test-router", Plugin: nonbgpRouter},
	}
	nb, err := newNonBGP(cfg, set, log)
	if err != nil {
		t.Fatal(err)
	}
	nb.wireLookup(set)
	decider, err := newDecider(cfg, set)
	if err != nil {
		t.Fatal(err)
	}
	return &nonbgpRig{cfg: cfg, nb: nb, decider: decider, flow: flow}
}

// round is one decision round for a destination: the flow source counts it
// under its synthetic prefix, isp-b answers faster, and Decide sees the
// synthetic prefix as exited through the default route. edit changes the
// input before Decide sees it.
func (r *nonbgpRig) round(t *testing.T, dst string, edit ...func(*policy.Input)) []policy.Improvement {
	t.Helper()
	p, ok := r.flow.lookup(netip.MustParseAddr(dst))
	if !ok {
		t.Fatalf("the flow lookup refused %s", dst)
	}
	now := time.Now()
	res := func(provider string, rtt time.Duration) probe.Result {
		return probe.Result{Provider: provider, Prefix: p, Time: now, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: rtt}}
	}
	r.nb.Refresh()
	in := policy.Input{
		Results:    []probe.Result{res("isp-a", 90*time.Millisecond), res("isp-b", 20*time.Millisecond)},
		ProviderUp: map[string]bool{"isp-a": true, "isp-b": true},
		Native:     map[netip.Prefix]string{},
	}
	r.nb.Fill(&in)
	for _, e := range edit {
		e(&in)
	}
	r.decider.Evaluate(in, now)
	imps := r.decider.Improvements()
	if err := r.nb.Sync(context.Background(), imps); err != nil {
		t.Fatalf("sync: %v", err)
	}
	return imps
}

// The static route leaves the router when what justified it is gone: the
// steered link is lost, its probe source fails, or its measurements go
// stale (#300).
func TestNonBGPWithdrawsOnProviderLossProbeSourceFailureAndStaleData(t *testing.T) {
	route := netip.MustParsePrefix("198.51.100.0/24")
	for name, edit := range map[string]func(*policy.Input){
		// The link is down: every probe through it fails to send.
		"provider loss": func(in *policy.Input) {
			for i := range in.Results {
				if in.Results[i].Provider == "isp-b" {
					in.Results[i].Err = "sendto: network is unreachable"
				}
			}
		},
		"probe-source failure": func(in *policy.Input) { in.ProviderUp["isp-b"] = false },
		"stale data": func(in *policy.Input) {
			for i := range in.Results {
				in.Results[i].Time = in.Results[i].Time.Add(-time.Hour)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newNonBGPRig(t, "inject")
			rig.round(t, "198.51.100.7")
			if _, ok := nonbgpRouter.snapshot()[route]; !ok {
				t.Fatal("no route was installed")
			}
			if imps := rig.round(t, "198.51.100.7", edit); len(imps) != 0 {
				t.Fatalf("the improvement survived: %+v", imps)
			}
			if routes := nonbgpRouter.snapshot(); len(routes) != 0 {
				t.Fatalf("routes left on the router: %v", routes)
			}
		})
	}
}

func TestNonBGPInjectSteersAndWithdraws(t *testing.T) {
	rig := newNonBGPRig(t, "inject")
	imps := rig.round(t, "198.51.100.7")
	if len(imps) != 1 || imps[0].Prefix != netip.MustParsePrefix("198.51.100.0/24") || imps[0].Provider != "isp-b" || imps[0].Native != "isp-a" {
		t.Fatalf("improvements = %+v", imps)
	}
	routes := nonbgpRouter.snapshot()
	if len(routes) != 1 || routes[netip.MustParsePrefix("198.51.100.0/24")] != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("router routes = %v, want one static route through isp-b's gateway", routes)
	}
	st := rig.nb.Status()
	if st.Mode != "inject" || st.DefaultProvider != "isp-a" || len(st.Routes) != 1 || st.Routes[0].Source != "synthetic" || st.Routes[0].SteeredTo != "isp-b" {
		t.Fatalf("status = %+v", st)
	}
	if !rig.nb.Has(netip.MustParsePrefix("198.51.100.0/24")) || rig.nb.Has(netip.MustParsePrefix("203.0.113.0/24")) {
		t.Fatal("Has does not follow the table")
	}

	// Shutdown: every route this process installed is removed.
	if err := rig.nb.WithdrawAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if routes := nonbgpRouter.snapshot(); len(routes) != 0 {
		t.Fatalf("routes after shutdown = %v", routes)
	}
	if len(rig.nb.Status().Routes) != 1 || rig.nb.Status().Routes[0].SteeredTo != "" {
		t.Fatal("the status still shows a steered route after the withdraw")
	}
}

func TestNonBGPOutsideAllowlistIsNeverSteered(t *testing.T) {
	rig := newNonBGPRig(t, "inject")
	imps := rig.round(t, "203.0.113.9")
	if len(imps) != 0 {
		t.Fatalf("an improvement outside the allowlist: %+v", imps)
	}
	if routes := nonbgpRouter.snapshot(); len(routes) != 0 {
		t.Fatalf("router routes = %v", routes)
	}
}

func TestNonBGPObserveRecommendsAndInstallsNothing(t *testing.T) {
	rig := newNonBGPRig(t, "observe")
	imps := rig.round(t, "198.51.100.7")
	if len(imps) != 1 || imps[0].Provider != "isp-b" {
		t.Fatalf("observe made no recommendation: %+v", imps)
	}
	if routes := nonbgpRouter.snapshot(); len(routes) != 0 {
		t.Fatalf("observe installed %v", routes)
	}
	if st := rig.nb.Status(); st.Mode != "observe" || len(st.Routes[0].SteeredTo) != 0 {
		t.Fatalf("status = %+v", st)
	}
}

func TestNonBGPSetupWarning(t *testing.T) {
	cfg := &config.Config{}
	if st := setupInfo(cfg, &pluginhost.Set{}, nil); st.NonBGPWarning != "" {
		t.Fatalf("warning with the mode off: %q", st.NonBGPWarning)
	}
	cfg.NonBGP = &config.NonBGP{}
	if st := setupInfo(cfg, &pluginhost.Set{}, nil); !strings.Contains(st.NonBGPWarning, "NOT from a learned BGP RIB view") || !strings.Contains(st.NonBGPWarning, "redistributes static routes") {
		t.Fatalf("warning = %q", st.NonBGPWarning)
	}
}

func TestNonBGPStateIsInertWhenOff(t *testing.T) {
	var nb *nonbgpState
	nb.Refresh()
	in := policy.Input{}
	nb.Fill(&in)
	if in.RIBEnabled || in.RIBReady || nb.Sync(context.Background(), nil) != nil || nb.WithdrawAll(context.Background()) != nil || nb.Has(netip.MustParsePrefix("192.0.2.0/24")) {
		t.Fatal("a nil state changed something")
	}
	m := map[string]uint64{}
	nb.addTruncated(m)
	nb.wireLookup(&pluginhost.Set{})
	nb.Run(context.Background())
	if len(m) != 0 {
		t.Fatalf("truncated = %v", m)
	}
	cfg, err := config.Parse([]byte(strings.Replace(nonbgpTestConfig, "%MODE%", "observe", 1)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.NonBGP = nil
	got, err := newNonBGP(cfg, &pluginhost.Set{}, slog.Default())
	if err != nil || got != nil {
		t.Fatalf("a BGP config built a non-BGP state: %v %v", got, err)
	}
	ctl, err := newController(cfg, &pluginhost.Set{}, nil, nil, nil, nil, nil, nil, slog.Default())
	if err != nil || ctl == nil {
		t.Fatalf("a BGP config got no controller: %v %v", ctl, err)
	}
}

func TestNonBGPHasNoBGPController(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(nonbgpTestConfig, "%MODE%", "inject", 1)))
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := newController(cfg, &pluginhost.Set{}, nil, nil, nil, nil, nil, nil, slog.Default())
	if err != nil || ctl != nil {
		t.Fatalf("a non-BGP config built an announce controller: %v %v", ctl, err)
	}
}

func TestNonBGPTruncatedCountsBlocksPastTheCap(t *testing.T) {
	rig := newNonBGPRig(t, "observe")
	rig.nb.table = nonbgp.NewTable(nonbgp.Options{WidenBits: 4, Idle: time.Hour, MaxBlocks: 1}, nil)
	rig.nb.wireLookup(&pluginhost.Set{Sources: []pluginhost.Instance[plugin.TargetSource]{{Plugin: rig.flow}}})
	for _, dst := range []string{"198.51.100.7", "203.0.113.9", "203.0.113.10"} {
		rig.flow.lookup(netip.MustParseAddr(dst))
	}
	m := map[string]uint64{"flow.max_prefixes": 3}
	rig.nb.addTruncated(m)
	if m["nonbgp.max_blocks"] != 2 || m["flow.max_prefixes"] != 3 {
		t.Fatalf("truncated = %v, want the two blocks past the cap counted", m)
	}
}

func TestNonBGPReloadKeysAreRestartOnly(t *testing.T) {
	cur, err := config.Parse([]byte(strings.Replace(nonbgpTestConfig, "%MODE%", "observe", 1)))
	if err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*config.Config){
		"mode":             func(c *config.Config) { c.Mode = config.ModeSuggest },
		"allowlist":        func(c *config.Config) { c.Allowlist.Prefixes = []string{"203.0.113.0/24"} },
		"max_improvements": func(c *config.Config) { n := 7; c.MaxImprovements = &n },
		"nonbgp":           func(c *config.Config) { c.NonBGP.DefaultProvider = "isp-b" },
		"sources":          func(c *config.Config) { c.Sources[0].Name = "flow-b" },
	} {
		next, err := config.Parse([]byte(strings.Replace(nonbgpTestConfig, "%MODE%", "observe", 1)))
		if err != nil {
			t.Fatal(err)
		}
		edit(next)
		restart, online := classify(cur, next)
		if len(restart) != 1 || !strings.HasPrefix(restart[0], name) || len(online) != 0 {
			t.Errorf("%s: restart %v online %v, want a restart only", name, restart, online)
		}
	}
	// Thresholds still reload online.
	next, _ := config.Parse([]byte(strings.Replace(nonbgpTestConfig, "%MODE%", "observe", 1)))
	next.Thresholds.MinRTTDeltaMs = 25
	if restart, online := classify(cur, next); len(restart) != 0 || len(online) != 1 || online[0] != "thresholds" {
		t.Errorf("thresholds: restart %v online %v", restart, online)
	}
}

func TestNonBGPCheckOutput(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte(strings.Replace(nonbgpTestConfig, "%MODE%", "inject", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("-check = %d: %s", code, errOut.String())
	}
	for _, want := range []string{"mode: inject", "nonbgp: install_routes=true default_provider=isp-a steerer=test-router covering=none",
		"WARNING: non-BGP mode is on. Its static routes are derived from flow data, NOT from a learned BGP RIB view",
		"steer: static routes via test-router, max_improvements=50, withdrawn on shutdown; a hard kill leaves them until the next start",
		"set packeteer_community=64512:666 and no-export", "bgp: disabled"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("-check output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "announce:") || strings.Contains(out.String(), "never exported") {
		t.Errorf("-check shows a BGP announce line or an export claim for a non-BGP site:\n%s", out.String())
	}
}

// v5Flow is a NetFlow v5 export with one record toward dst.
func v5Flow(dst string, octets uint32) []byte {
	b := make([]byte, 24+48)
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], 1)
	copy(b[24+4:24+8], netip.MustParseAddr(dst).AsSlice())
	binary.BigEndian.PutUint32(b[24+20:], octets)
	b[24+38] = 6
	return b
}

// The whole daemon on a site with no BGP: NetFlow records name a
// destination, the probes find isp-b faster, a static route goes to the
// router through isp-b's gateway, and a SIGTERM (context cancel) removes it
// again (#300).
// nonbgpDaemon is the whole daemon in non-BGP inject mode, fed NetFlow
// over UDP and steering nonbgpRouter.
type nonbgpDaemon struct {
	conn        net.Conn
	cancel      context.CancelFunc
	done        chan int
	out, errOut bytes.Buffer
}

// startNonBGPDaemon runs the daemon with the fixed prober making isp-b
// faster. allowlist replaces the test config's allowlist prefixes.
func startNonBGPDaemon(t *testing.T, allowlist string) *nonbgpDaemon {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	y := strings.Replace(nonbgpTestConfig, "%MODE%", "inject", 1)
	y = strings.Replace(y, "  - type: icmp\n", "  - type: fixed\n    config: {paths: [{provider: isp-a, rtt_ms: 90}, {provider: isp-b, rtt_ms: 20}]}\n", 1)
	y = strings.Replace(y, "127.0.0.1:2055", "127.0.0.1:"+strconv.Itoa(port), 1)
	y = strings.Replace(y, "[198.51.100.0/24]", allowlist, 1)
	y += "probe: {interval: 2s, timeout: 500ms}\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &nonbgpDaemon{cancel: cancel, done: make(chan int, 1)}
	go func() { d.done <- run(ctx, []string{"-config", path}, noEnv, &d.out, &d.errOut) }()
	d.conn, err = net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		cancel()
		<-d.done
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = d.conn.Close()
	})
	return d
}

// stop is SIGTERM: it fails the test unless the daemon exits 0 within
// limit.
func (d *nonbgpDaemon) stop(t *testing.T, limit time.Duration) {
	t.Helper()
	d.cancel()
	select {
	case code := <-d.done:
		if code != 0 {
			t.Fatalf("exit %d\nstderr: %s", code, d.errOut.String())
		}
	case <-time.After(limit):
		t.Fatalf("the daemon did not stop within %s", limit)
	}
}

func TestNonBGPDaemonSteersFromFlowAndWithdrawsOnShutdown(t *testing.T) {
	nonbgpRouter.reset()
	// A killed run left a tagged route: the start removes it.
	leftover := netip.MustParsePrefix("203.0.113.0/24")
	_ = nonbgpRouter.Install(context.Background(), plugin.SteerRoute{Prefix: leftover, NextHop: netip.MustParseAddr("198.51.100.1")})
	d := startNonBGPDaemon(t, "[198.51.100.0/24]")
	conn, out, errOut := d.conn, &d.out, &d.errOut
	route := netip.MustParsePrefix("198.51.100.0/24")
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, _ = conn.Write(v5Flow("198.51.100.7", 100000))
		if nh, ok := nonbgpRouter.snapshot()[route]; ok {
			if nh != netip.MustParseAddr("198.51.100.1") {
				t.Fatalf("route next hop = %s, want isp-b's gateway", nh)
			}
			if _, ok := nonbgpRouter.snapshot()[leftover]; ok {
				t.Fatal("the route a killed run left is still on the router")
			}
			break
		}
		if time.Now().After(deadline) {
			d.cancel()
			<-d.done
			t.Fatalf("no static route after 20s\nstdout: %s\nstderr: %s", out.String(), errOut.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Flow to a destination outside the allowlist is probed but never steered.
	_, _ = conn.Write(v5Flow("203.0.113.9", 100000))
	time.Sleep(2500 * time.Millisecond)
	if routes := nonbgpRouter.snapshot(); len(routes) != 1 {
		t.Fatalf("router routes = %v, want only the allowlisted prefix", routes)
	}

	d.stop(t, 20*time.Second)
	if routes := nonbgpRouter.snapshot(); len(routes) != 0 {
		t.Fatalf("routes left on the router after shutdown: %v", routes)
	}
	for _, want := range []string{"NOT from a learned BGP RIB view", "removed a route left on the router by an earlier run"} {
		if !strings.Contains(errOut.String()+out.String(), want) {
			t.Errorf("the log lacks %q", want)
		}
	}
}

// SIGTERM while a pass waits on a slow router API: the pass ends after the
// route in flight, no further route is started, and the shutdown withdraw
// removes what is on the router within the 10-second budget (#300).
func TestNonBGPDaemonSIGTERMStopsASlowPass(t *testing.T) {
	nonbgpRouter.reset()
	first, second := netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")
	var mu sync.Mutex
	tried := map[netip.Prefix]bool{}
	gated, started, release := false, make(chan struct{}), make(chan struct{})
	late := 0
	slow := false
	nonbgpRouter.mu.Lock()
	nonbgpRouter.before = func(p netip.Prefix) error {
		mu.Lock()
		switch {
		case !slow:
			// Until both prefixes are wanted in every round, the router refuses.
			tried[p] = true
			mu.Unlock()
			return errors.New("router busy")
		case gated:
			late++
			mu.Unlock()
			return nil
		case p != first:
			mu.Unlock()
			return errors.New("router busy")
		}
		gated = true
		mu.Unlock()
		close(started)
		<-release
		return nil
	}
	nonbgpRouter.mu.Unlock()
	t.Cleanup(nonbgpRouter.reset)
	d := startNonBGPDaemon(t, "[198.51.100.0/24, 203.0.113.0/24]")

	deadline := time.Now().Add(20 * time.Second)
	for {
		_, _ = d.conn.Write(v5Flow("198.51.100.7", 100000))
		_, _ = d.conn.Write(v5Flow("203.0.113.9", 100000))
		mu.Lock()
		both := tried[first] && tried[second]
		if both {
			slow = true
		}
		mu.Unlock()
		if both {
			break
		}
		if time.Now().After(deadline) {
			d.cancel()
			<-d.done
			t.Fatalf("both prefixes were not wanted after 20s\nstderr: %s", d.errOut.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	select {
	case <-started:
	case <-time.After(20 * time.Second):
		t.Fatal("no install reached the slow router")
	}
	d.cancel()
	close(release)
	at := time.Now()
	d.stop(t, 15*time.Second)
	if took := time.Since(at); took > 10*time.Second {
		t.Errorf("shutdown took %s after the slow route finished", took)
	}
	mu.Lock()
	defer mu.Unlock()
	if late != 0 {
		t.Errorf("%d routes were installed after SIGTERM", late)
	}
	if routes := nonbgpRouter.snapshot(); len(routes) != 0 {
		t.Fatalf("routes left on the router after shutdown: %v", routes)
	}
}
