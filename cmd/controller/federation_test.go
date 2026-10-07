package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeFed is an in-memory federation transport.
type fakeFed struct {
	plugin.Base
	mu        sync.Mutex
	peers     []plugin.PeerState
	published []plugin.InstanceSnapshot
}

func (f *fakeFed) Publish(s plugin.InstanceSnapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, s)
}

func (f *fakeFed) Peers(time.Time) []plugin.PeerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]plugin.PeerState(nil), f.peers...)
}

func (f *fakeFed) set(p []plugin.PeerState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = p
}

func (f *fakeFed) last() plugin.InstanceSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.published[len(f.published)-1]
}

// Documentation prefixes and a private ASN only.
const fedCtlYAML = `
mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
max_improvements: 50
hold_time: 1m
thresholds:
  min_loss_delta_pct: 1
  min_rtt_delta_ms: 15
domain: pop-a
inter_dc_rtt:
  pop-b: 10ms
providers:
  - name: x-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: x-b
    domain: pop-b
    next_hop: 192.0.2.253
allowlist:
  prefixes: [198.51.100.0/24]
global_commit:
  - name: carrier-x
    commit_mbps: 100
    providers: [x-a, x-b]
federation:
  type: mtls
local_pref: 250
bgp:
  neighbors:
    - address: 192.0.2.254
announcer:
  type: gobgp
`

func peerPopB(at time.Time, pfx netip.Prefix) plugin.PeerState {
	return plugin.PeerState{Name: "pop-b", Fresh: true, LastSeen: at, Snapshot: plugin.InstanceSnapshot{
		Instance: "pop-b", Domain: "pop-b", Mode: "inject", Time: at, RIBReady: true, MaxImprovements: 50,
		Providers: []plugin.FederatedProvider{{Name: "x-b", Domain: "pop-b", Up: true,
			Usage: &plugin.Usage{Provider: "x-b", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 70}}},
		Paths:  []plugin.FederatedPath{{Prefix: pfx, Provider: "x-b", Sent: 4, RTT: 20 * time.Millisecond, Time: at}},
		Routes: []plugin.FederatedRoute{{Prefix: pfx, Native: "x-b", Exit: "x-b"}},
	}}
}

// TestFederatedSteerAnnounceAndWithdraw: a fresh peer's path through a
// provider in its domain (20ms + 10ms inter-DC) beats the local 80ms, so
// the prefix is announced with the remote provider's next hop and the
// community. When the peer goes stale, the route is withdrawn.
func TestFederatedSteerAnnounceAndWithdraw(t *testing.T) {
	cfg, err := config.Parse([]byte(fedCtlYAML))
	if err != nil {
		t.Fatal(err)
	}
	pfx := netip.MustParsePrefix("198.51.100.0/24")
	ff := &fakeFed{}
	fed := newFedState(cfg, &pluginhost.Set{Federation: &pluginhost.Instance[plugin.Federation]{Name: "mtls", Type: "mtls", Plugin: ff}})
	if fed == nil {
		t.Fatal("federation state not built")
	}
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	set := &pluginhost.Set{Scorer: &pluginhost.Instance[plugin.Scorer]{Name: "weighted", Type: "weighted", Plugin: scorer}}
	decider, err := newDecider(cfg, set)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ann := &memAnn{}
	ctl, err := announce.New(announce.Config{
		Mode: "inject", LocalPref: 250, Community: cfg.PacketeerCommunity, MaxImprovements: 50,
		Allowlist: []netip.Prefix{pfx},
		NextHops:  map[string]netip.Addr{"x-a": netip.MustParseAddr("192.0.2.1"), "x-b": netip.MustParseAddr("192.0.2.253")},
	}, ann, readyRIB{pfx}, log)
	if err != nil {
		t.Fatal(err)
	}

	eval := func(now time.Time) policy.Input {
		in := policy.Input{
			Results:    []probe.Result{{Provider: "x-a", Prefix: pfx, Time: now, Stats: probe.Stats{Sent: 4, Received: 4, RTTAvg: 80 * time.Millisecond}}},
			ProviderUp: map[string]bool{"x-a": true}, RIBEnabled: true, RIBReady: true,
			Native: map[netip.Prefix]string{pfx: "x-a"},
		}
		fed.merge(&in, now)
		fed.commit(context.Background(), &in, set)
		if _, err := runDecision(now, decider, in, ctl, log, cfg.Mode, nil); err != nil {
			t.Fatal(err)
		}
		fed.publish(now, in, decider.Improvements())
		return in
	}

	t0 := time.Now()
	ff.set([]plugin.PeerState{peerPopB(t0, pfx)})
	eval(t0)
	rt, ok := ann.route(pfx)
	if !ok || rt.Provider != "x-b" || rt.NextHop.String() != "192.0.2.253" || len(rt.Communities) != 1 || rt.Communities[0] != "64512:666" {
		t.Fatalf("route = %+v %v\n%s", rt, ok, logs.String())
	}
	s := ff.last()
	if s.Instance != "pop-a" || s.Domain != "pop-a" || len(s.Improvements) != 1 || len(s.Routes) != 1 || s.Routes[0].Exit != "x-b" {
		t.Fatalf("published = %+v", s)
	}
	for _, p := range s.Paths {
		if p.Provider != "x-a" {
			t.Fatalf("published a path through %s", p.Provider)
		}
	}

	// The peer goes stale inside the hold time: withdrawn, no stale intent.
	stale := peerPopB(t0, pfx)
	stale.Fresh = false
	ff.set([]plugin.PeerState{stale})
	eval(t0.Add(2 * time.Second))
	if ann.count() != 0 {
		t.Fatalf("route onto a stale peer's provider kept:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), `msg="improvement retired"`) {
		t.Fatalf("withdraw reason not logged:\n%s", logs.String())
	}

	// Shutdown tells peers our providers are unusable.
	fed.publishDown(time.Now())
	if d := ff.last(); d.RIBReady || len(d.Routes) != 0 || len(d.Providers) != 1 || d.Providers[0].Up {
		t.Fatalf("down snapshot = %+v", d)
	}

	// The central view is served on /api/federation.
	srv, err := httpapi.New(httpapi.Options{Snapshot: func() httpapi.Snapshot { return httpapi.Snapshot{} }, Federation: fed.status})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/federation", nil))
	var view struct {
		Enabled bool   `json:"enabled"`
		Domain  string `json:"domain"`
		Peers   []struct {
			Name  string `json:"name"`
			Fresh bool   `json:"fresh"`
		} `json:"peers"`
		GlobalCommit []struct {
			Name     string `json:"name"`
			Complete bool   `json:"complete"`
		} `json:"global_commit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err, rec.Body.String())
	}
	if !view.Enabled || view.Domain != "pop-a" || len(view.Peers) != 1 || view.Peers[0].Fresh || len(view.GlobalCommit) != 1 || view.GlobalCommit[0].Name != "carrier-x" {
		t.Fatalf("view = %s", rec.Body.String())
	}
}

// TestFederatedGlobalCommitUsage: with a commit scorer, the local
// member's commit is what the global commit leaves after the peer's usage.
func TestFederatedGlobalCommitUsage(t *testing.T) {
	cfg, err := config.Parse([]byte(fedCtlYAML))
	if err != nil {
		t.Fatal(err)
	}
	pfx := netip.MustParsePrefix("198.51.100.0/24")
	ff := &fakeFed{}
	ff.set([]plugin.PeerState{peerPopB(time.Now(), pfx)})
	fed := newFedState(cfg, &pluginhost.Set{Federation: &pluginhost.Instance[plugin.Federation]{Plugin: ff}})
	set := scorerSet(t, "commit")
	in := policy.Input{Usage: []plugin.Usage{{Provider: "x-a", CommitMbps: 100, Samples: 1, Single: true, UsageMbps: 50}}}
	fed.merge(&in, time.Now())
	fed.commit(context.Background(), &in, set)
	var xa, xb bool
	for _, u := range in.Usage {
		switch u.Provider {
		case "x-a":
			xa = u.CommitMbps == 30
		case "x-b":
			xb = u.UsageMbps == 70
		}
	}
	if !xa || !xb {
		t.Fatalf("usage = %+v, want x-a commit 30 and x-b's row", in.Usage)
	}
	// Published usage is this POP's own, not the effective commit.
	fed.publish(time.Now(), in, nil)
	if u := ff.last().Providers[0].Usage; u == nil || u.CommitMbps != 100 {
		t.Fatalf("published usage = %+v", u)
	}
}

// TestRemoteProvidersNotProbed: a provider in another domain has no
// source address here; the engine and the troubleshooting tools skip it.
func TestRemoteProvidersNotProbed(t *testing.T) {
	cfg, err := config.Parse([]byte(fedCtlYAML))
	if err != nil {
		t.Fatal(err)
	}
	probers := &pluginhost.Set{Probers: []pluginhost.Instance[plugin.Prober]{{Name: "p", Type: "fake", Plugin: &hungProber{allow: 1 << 30}}}}
	engine, err := newEngine(cfg, probers, slog.Default(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ps := engine.Providers()
	if len(ps) != 1 || ps[0].Name != "x-a" {
		t.Fatalf("engine providers = %+v", ps)
	}
	tools, err := newTools(cfg, &pluginhost.Set{})
	if err != nil {
		t.Fatal(err)
	}
	if st := tools.Status(); len(st.Providers) != 1 {
		t.Fatalf("tools providers = %+v", st.Providers)
	}
	var nilFed *fedState
	if st := nilFed.status(); st.Enabled {
		t.Fatal("standalone status enabled")
	}
}
