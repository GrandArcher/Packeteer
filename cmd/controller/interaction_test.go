package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Interaction tests for docs/precedence.md. Each one runs the whole
// controller in inject against a simulated edge and asks what is on the
// wire when two steering surfaces want the same prefix.

const (
	ixCommunity = 64512<<16 | 666 // packeteer_community
	ixInMarker  = 64512<<16 | 667 // inbound announcer marker
	ixMitMarker = 64512<<16 | 668 // mitigation announcer marker
	ixNoExport  = 0xFFFFFF01

	ixNative   = "192.0.2.1" // transit-a, the edge's own path
	ixSteered  = "192.0.2.2" // transit-b, an outbound improvement
	ixDiscard  = "192.0.2.66"
	ixScrubber = "192.0.2.77"
)

type ixRoute struct {
	NextHop string
	Comms   map[uint32]bool
}

// wire lists Packeteer's paths on the edge by prefix.
func (e *msEdge) wire() map[string]ixRoute {
	e.t.Helper()
	out := map[string]ixRoute{}
	err := e.srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: "127.0.0.2", Family: v4}, func(d *api.Destination) {
		for _, p := range d.Paths {
			if p.IsWithdraw {
				continue
			}
			r := ixRoute{Comms: map[uint32]bool{}}
			for _, a := range p.Pattrs {
				var ca api.CommunitiesAttribute
				var na api.NextHopAttribute
				switch {
				case a.MessageIs(&ca) && a.UnmarshalTo(&ca) == nil:
					for _, c := range ca.Communities {
						r.Comms[c] = true
					}
				case a.MessageIs(&na) && a.UnmarshalTo(&na) == nil:
					r.NextHop = na.NextHop
				}
			}
			out[d.Prefix] = r
		}
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (r ixRoute) has(want ...uint32) bool {
	for _, c := range want {
		if !r.Comms[c] {
			return false
		}
	}
	return true
}

// ixDaemon is one controller run against an msEdge.
type ixDaemon struct {
	t      *testing.T
	edge   *msEdge
	http   int
	logs   *syncBuf
	cancel context.CancelFunc
	done   chan int
	exited bool
}

// startIX runs the controller with a common header (one iBGP session to
// edge, transit-a at 192.0.2.1 and transit-b at 192.0.2.2, the packeteer
// community, hold_time 1s, one-second rounds) followed by body.
func startIX(t *testing.T, edge *msEdge, body string) *ixDaemon {
	t.Helper()
	httpPort := freePort(t)
	return runIX(t, edge, httpPort, fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
probe: {interval: 1s, timeout: 200ms, packets: 1}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
`, httpPort, edge.port)+body)
}

// runIX runs the controller on cfg, whose API listens on httpPort.
func runIX(t *testing.T, edge *msEdge, httpPort int, cfg string) *ixDaemon {
	t.Helper()
	d := &ixDaemon{t: t, edge: edge, http: httpPort, logs: &syncBuf{}, done: make(chan int, 1)}
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "lab"
		case HTTPPassEnv:
			return "lab-only"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.cancel = cancel
	var out syncBuf
	go func() { d.done <- run(ctx, []string{"-config", path}, env, &out, d.logs) }()
	t.Cleanup(func() {
		cancel()
		if d.exited {
			return
		}
		select {
		case <-d.done:
		case <-time.After(20 * time.Second):
		}
	})
	return d
}

func (d *ixDaemon) fatalf(format string, args ...any) {
	d.t.Helper()
	d.t.Fatalf("%s\n%s", fmt.Sprintf(format, args...), d.logs.String())
}

// waitWire waits for cond to hold on Packeteer's paths at the edge.
func (d *ixDaemon) waitWire(what string, cond func(map[string]ixRoute) bool) {
	d.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		w := d.edge.wire()
		if cond(w) {
			return
		}
		if time.Now().After(deadline) {
			d.fatalf("timed out waiting for %s: edge has %v", what, w)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// holdWire fails when cond is false on any sample over dur.
func (d *ixDaemon) holdWire(what string, dur time.Duration, cond func(map[string]ixRoute) bool) {
	d.t.Helper()
	for end := time.Now().Add(dur); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if w := d.edge.wire(); !cond(w) {
			d.fatalf("%s: edge has %v", what, w)
		}
	}
}

// call is an authenticated request to the ops API.
func (d *ixDaemon) call(method, path, body string) (int, map[string]any) {
	d.t.Helper()
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", d.http, path), strings.NewReader(body))
	if err != nil {
		d.t.Fatal(err)
	}
	req.SetBasicAuth("lab", "lab-only")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

// stop shuts the controller down and requires an empty wire.
func (d *ixDaemon) stop() {
	d.t.Helper()
	d.cancel()
	select {
	case code := <-d.done:
		d.exited = true
		if code != 0 {
			d.fatalf("exit %d", code)
		}
	case <-time.After(20 * time.Second):
		d.fatalf("daemon did not stop")
	}
	d.waitWire("an empty wire after shutdown", func(w map[string]ixRoute) bool { return len(w) == 0 })
}

func routeVia(prefix, nh string, comms ...uint32) func(map[string]ixRoute) bool {
	return func(w map[string]ixRoute) bool {
		r, ok := w[prefix]
		return ok && r.NextHop == nh && r.has(comms...)
	}
}

func (d *ixDaemon) waitLog(what string) {
	d.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(d.logs.String(), what) {
		if time.Now().After(deadline) {
			d.fatalf("timed out waiting for the log line %q", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ixInbound steers prefixes away from transit-a while the telemetry file
// reports its inbound 95th over commit.
func ixInbound(usage, prefixes string) string {
	return fmt.Sprintf(`telemetry:
  - type: fixed
    config: {file: %s}
inbound:
  mode: inject
  prefixes: [%s]
  damping: {confirm: 1s, backoff: 2, max_hold: 8s}
  announcer:
    type: gobgp
    config:
      marker: "64512:667"
      providers:
        - {provider: transit-a, name: prepend-2, prepend: 2, communities: ["64512:1102"]}
        - {provider: transit-b, communities: ["64512:1202"]}
`, usage, prefixes)
}

const (
	ixOverCommit  = "providers:\n  - {name: transit-a, commit_mbps: 100, usage_mbps: 10, in_mbps: 150}\n  - {name: transit-b, commit_mbps: 100, usage_mbps: 10, in_mbps: 10}\n"
	ixUnderCommit = "providers:\n  - {name: transit-a, commit_mbps: 100, usage_mbps: 10, in_mbps: 10}\n  - {name: transit-b, commit_mbps: 100, usage_mbps: 10, in_mbps: 10}\n"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const ixMitigation = `mitigation:
  mode: inject
  allowlist: [203.0.113.0/24]
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      blackhole: {next_hop: 192.0.2.66}
      redirect:
        - {name: scrubber, next_hop: 192.0.2.77, communities: ["64512:777"]}
`

// An operator's RTBH rule takes a prefix over from an outbound
// improvement that is already on the wire. The edge never carries both: the
// improvement leaves, the discard route stays across rounds, the conflict
// is logged, and removing the rule gives the prefix back to the
// improvement, which the decision engine kept all along.
func TestInteractionMitigationTakesPrefixFromOutboundSteer(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24")
	d := startIX(t, edge, `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
allowlist: {prefixes: ["203.0.113.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 203.0.113.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
`+ixMitigation)

	steer := routeVia("203.0.113.0/24", ixSteered, ixCommunity, ixNoExport)
	d.waitWire("the outbound improvement", steer)

	code, rule := d.call(http.MethodPost, "/api/mitigations", `{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"10m"}`)
	if code != http.StatusCreated {
		d.fatalf("rule: %d %v", code, rule)
	}
	d.waitWire("the discard route", routeVia("203.0.113.0/24", ixDiscard, ixCommunity, ixMitMarker, ixNoExport))
	// The improvement is still wanted every round. It must neither return
	// nor take the discard route down with its own withdraw.
	d.holdWire("the rule owns the prefix", 5*time.Second, routeVia("203.0.113.0/24", ixDiscard, ixCommunity, ixMitMarker, ixNoExport))
	if !strings.Contains(d.logs.String(), "announce: 203.0.113.0/24 is reserved for inbound steering or threat mitigation") {
		d.fatalf("the conflict was not logged")
	}

	if code, _ := d.call(http.MethodDelete, fmt.Sprintf("/api/mitigations/%v", rule["id"]), ""); code != http.StatusNoContent && code != http.StatusOK {
		d.fatalf("delete rule: %d", code)
	}
	d.waitWire("the improvement back after the rule", steer)
	d.stop()
}

// An inbound steer and a mitigation rule on the same prefix: the rule wins
// at once and silently, the steer does not come back while the rule holds
// the prefix, and it returns when the rule is removed.
func TestInteractionMitigationTakesPrefixFromInboundSteer(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("203.0.113.0/24")
	usage := filepath.Join(t.TempDir(), "usage.yaml")
	writeFile(t, usage, ixOverCommit)
	d := startIX(t, edge, `thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}
allowlist: {prefixes: ["203.0.113.0/24"]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
`+ixInbound(usage, "203.0.113.0/24")+ixMitigation)

	// An inbound steer keeps the learned next hop and adds the marker.
	steer := routeVia("203.0.113.0/24", ixNative, ixCommunity, ixInMarker, ixNoExport)
	d.waitWire("the inbound steer", steer)

	code, rule := d.call(http.MethodPost, "/api/mitigations", `{"prefix":"203.0.113.0/24","action":"redirect","target":"scrubber","ttl":"10m"}`)
	if code != http.StatusCreated {
		d.fatalf("rule: %d %v", code, rule)
	}
	redirect := routeVia("203.0.113.0/24", ixScrubber, ixCommunity, ixMitMarker, ixNoExport)
	d.waitWire("the redirect", redirect)
	d.holdWire("the rule owns the prefix", 5*time.Second, redirect)
	if n := strings.Count(d.logs.String(), "inbound steer announced"); n != 1 {
		d.fatalf("the steer was announced %d times; it must not come back while the rule holds the prefix", n)
	}
	if strings.Contains(d.logs.String(), "is reserved for") {
		d.fatalf("an inbound steer giving way is not an announce failure")
	}

	if code, _ := d.call(http.MethodDelete, fmt.Sprintf("/api/mitigations/%v", rule["id"]), ""); code != http.StatusNoContent && code != http.StatusOK {
		d.fatalf("delete rule: %d", code)
	}
	d.waitWire("the inbound steer back after the rule", steer)
	d.stop()
}

// A prefix listed under inbound.prefixes belongs to inbound steering, not
// to the outbound surface, whether or not a steer is on the wire. The
// outbound improvement for it is refused and logged, an outbound
// improvement for another prefix is unaffected, and the steer appears when
// its trigger fires.
func TestInteractionInboundPrefixIsNeverAnOutboundSteer(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("192.0.2.0/24", "198.51.100.0/24")
	usage := filepath.Join(t.TempDir(), "usage.yaml")
	writeFile(t, usage, ixUnderCommit)
	d := startIX(t, edge, `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
allowlist: {prefixes: ["192.0.2.0/24", "198.51.100.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 192.0.2.0/24, host: 192.0.2.10}, {prefix: 198.51.100.0/24, host: 198.51.100.10}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
`+ixInbound(usage, "192.0.2.0/24"))

	out := routeVia("198.51.100.0/24", ixSteered, ixCommunity, ixNoExport)
	d.waitWire("the outbound improvement for the other prefix", out)
	d.waitLog("announce: 192.0.2.0/24 is reserved for inbound steering or threat mitigation")
	d.holdWire("no outbound route for an inbound prefix", 4*time.Second, func(w map[string]ixRoute) bool {
		_, owned := w["192.0.2.0/24"]
		return !owned && out(w)
	})

	writeFile(t, usage, ixOverCommit)
	steer := routeVia("192.0.2.0/24", ixNative, ixCommunity, ixInMarker, ixNoExport)
	d.waitWire("the inbound steer", func(w map[string]ixRoute) bool { return steer(w) && out(w) })
	d.holdWire("the steer and the improvement coexist", 3*time.Second, func(w map[string]ixRoute) bool { return steer(w) && out(w) })
	d.stop()
}

// max_improvements is shared by outbound improvements and inbound steers,
// first come first kept. Here outbound fills both slots: the inbound steer
// is refused, nothing is displaced, and an operator's RTBH rule on the
// inbound prefix still goes out because mitigation is capped by max_rules,
// not by max_improvements.
func TestInteractionSharedCapOutboundFirstMitigationUncounted(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
	usage := filepath.Join(t.TempDir(), "usage.yaml")
	writeFile(t, usage, ixUnderCommit)
	d := startIX(t, edge, `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
max_improvements: 2
allowlist: {prefixes: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 192.0.2.0/24}, {prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 80}, {provider: transit-b, rtt_ms: 10}]}
`+ixInbound(usage, "203.0.113.0/24")+ixMitigation)

	both := func(w map[string]ixRoute) bool {
		return routeVia("192.0.2.0/24", ixSteered, ixCommunity)(w) && routeVia("198.51.100.0/24", ixSteered, ixCommunity)(w)
	}
	d.waitWire("two outbound improvements", both)
	writeFile(t, usage, ixOverCommit)
	d.waitLog("inbound: shared max_improvements (2) reached")
	d.holdWire("the full cap is not shared out", 4*time.Second, func(w map[string]ixRoute) bool {
		_, steered := w["203.0.113.0/24"]
		return both(w) && !steered && len(w) == 2
	})

	if code, rule := d.call(http.MethodPost, "/api/mitigations", `{"prefix":"203.0.113.0/24","action":"blackhole","ttl":"10m"}`); code != http.StatusCreated {
		d.fatalf("rule: %d %v", code, rule)
	}
	d.waitWire("the discard route beside a full cap", func(w map[string]ixRoute) bool {
		return both(w) && routeVia("203.0.113.0/24", ixDiscard, ixMitMarker)(w)
	})
	d.stop()
}

// The other order: an inbound steer already holds the only slot, then an
// outbound improvement becomes wanted. The steer is not displaced, the
// improvement waits for room, and the refusal is logged each round.
func TestInteractionSharedCapInboundFirstIsNotDisplaced(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("198.51.100.0/24", "203.0.113.0/24")
	dir := t.TempDir()
	usage := filepath.Join(dir, "usage.yaml")
	writeFile(t, usage, ixOverCommit)
	paths := filepath.Join(dir, "paths.yaml")
	flat := "paths:\n  - {provider: transit-a, rtt_ms: 10}\n  - {provider: transit-b, rtt_ms: 10}\n"
	writeFile(t, paths, flat)
	d := startIX(t, edge, fmt.Sprintf(`thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
max_improvements: 1
allowlist: {prefixes: ["198.51.100.0/24", "203.0.113.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 198.51.100.0/24}]}
probers:
  - type: fixed
    config: {file: %s}
`, paths)+ixInbound(usage, "203.0.113.0/24"))

	steer := routeVia("203.0.113.0/24", ixNative, ixCommunity, ixInMarker, ixNoExport)
	d.waitWire("the inbound steer", steer)
	writeFile(t, paths, "paths:\n  - {provider: transit-a, rtt_ms: 80}\n  - {provider: transit-b, rtt_ms: 10}\n")
	d.waitLog("announce: max_improvements (1) reached")
	d.holdWire("the steer keeps the slot", 4*time.Second, func(w map[string]ixRoute) bool { return steer(w) && len(w) == 1 })
	d.stop()
}

// Known limitation, pinned so a change is deliberate: Decide ranks every
// probed prefix and does not know which ones inbound steering or a
// mitigation rule owns. At the cap the best-ranked owned prefix takes the
// decision slot, the announcer refuses it, and a lower-ranked prefix that
// could have used the free wire slot stays on its native path.
func TestInteractionOwnedPrefixStillTakesTheDecisionSlot(t *testing.T) {
	edge := newMSEdge(t)
	edge.advertise("192.0.2.0/24", "198.51.100.0/24")
	usage := filepath.Join(t.TempDir(), "usage.yaml")
	writeFile(t, usage, ixUnderCommit)
	d := startIX(t, edge, `thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
max_improvements: 1
allowlist: {prefixes: ["192.0.2.0/24", "198.51.100.0/24"]}
sources:
  - type: static
    config: {targets: [{prefix: 192.0.2.0/24, host: 192.0.2.10}, {prefix: 198.51.100.0/24, host: 198.51.100.10}]}
probers:
  - type: fixed
    config:
      paths:
        - {provider: transit-a, target: 192.0.2.10, rtt_ms: 200}
        - {provider: transit-b, target: 192.0.2.10, rtt_ms: 10}
        - {provider: transit-a, target: 198.51.100.10, rtt_ms: 80}
        - {provider: transit-b, target: 198.51.100.10, rtt_ms: 10}
`+ixInbound(usage, "192.0.2.0/24"))

	d.waitLog("announce: 192.0.2.0/24 is reserved for inbound steering or threat mitigation")
	d.holdWire("nothing on the wire", 4*time.Second, func(w map[string]ixRoute) bool { return len(w) == 0 })
	d.stop()
}

// The flap quarantine is decision state in memory. A leader that steps
// down withdraws and drops it with the rest of its decision state; the
// instance that leads next starts with none, decides the prefix again, and
// counts flips from zero. (docs/ha.md: no decision state is copied.)
func TestInteractionQuarantineDoesNotSurviveHAHandover(t *testing.T) {
	p := netip.MustParsePrefix("198.51.100.0/24")
	log := slog.New(slog.NewTextHandler(&syncBuf{}, nil))
	scorer, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	dec := policy.NewEngine(policy.Config{Mode: "inject", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: time.Minute,
		MaxImprovements: 50, MaxResultAge: 2 * time.Minute, Allowlist: []netip.Prefix{p},
		Flap: policy.FlapConfig{MaxFlips: 3, Window: time.Hour, Cooldown: 10 * time.Minute, MaxCooldown: time.Hour}}, scorer)
	ann := &memAnn{}
	var leader atomic.Bool
	leader.Store(true)
	ctl, err := announce.New(announce.Config{
		Mode: "inject", LocalPref: 250, Community: "64512:666", MaxImprovements: 50, Leader: leader.Load,
		Allowlist: []netip.Prefix{p},
		NextHops:  map[string]netip.Addr{"a": netip.MustParseAddr("192.0.2.1"), "b": netip.MustParseAddr("192.0.2.2")},
	}, ann, readyRIB{p}, log)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// bFaster: b is 20 ms better than the native a; aFaster: the reverse.
	round := func(bFaster bool) {
		t.Helper()
		a, b := 50*time.Millisecond, 30*time.Millisecond
		if !bFaster {
			a, b = b, a
		}
		res := []probe.Result{
			{Provider: "a", Prefix: p, Time: at, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: a}},
			{Provider: "b", Prefix: p, Time: at, Stats: probe.Stats{Sent: 10, Received: 10, RTTAvg: b}},
		}
		in := policy.Input{Results: res, ProviderUp: map[string]bool{"a": true, "b": true}, RIBEnabled: true, RIBReady: true, Native: map[netip.Prefix]string{p: "a"}}
		if _, err := runDecision(at, dec, in, ctl, log, "inject", nil); err != nil {
			t.Fatal(err)
		}
		at = at.Add(2 * time.Minute)
	}

	// improve, flip back, improve, flip back: the fourth change is parked.
	for i := range 4 {
		round(i%2 == 0)
	}
	if q := dec.Quarantined(); len(q) != 1 || q[0].Prefix != p {
		t.Fatalf("not parked: %+v", q)
	}
	round(true)
	if ann.count() != 0 {
		t.Fatal("a parked prefix is on the wire")
	}

	// Step down, as the decision loop does for a standby.
	leader.Store(false)
	dec.Reset()
	if _, err := standbyRound(at, ctl, nil, nil, log); err != nil {
		t.Fatal(err)
	}
	if len(dec.Quarantined()) != 0 || len(dec.Improvements()) != 0 || ann.count() != 0 {
		t.Fatalf("standby kept state: quarantined %v improvements %v wire %d", dec.Quarantined(), dec.Improvements(), ann.count())
	}

	// The next leader decides the prefix from fresh state: the faster
	// provider is announced at once, and it takes a full max_flips again
	// to park it.
	leader.Store(true)
	round(true)
	if _, on := ann.route(p); !on || ann.count() != 1 || len(dec.Quarantined()) != 0 {
		t.Fatalf("new leader: wire %d quarantined %v", ann.count(), dec.Quarantined())
	}
}
