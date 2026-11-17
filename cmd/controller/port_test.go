package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/pin"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/telemetry/fixed"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const portConfigYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1, cost: 8}
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    port: {capacity_mbps: 10000, commit_mbps: 6000, port_cost: 1500}
    peers:
      - {name: ix-peer-a, asn: 64501, next_hop: 203.0.113.11, source_ip: 192.0.2.31}
  - name: ix-two
    lans: [198.51.100.0/24]
    peers:
      - {name: ix-two-peer, asn: 64502, next_hop: 198.51.100.11, source_ip: 192.0.2.32}
bgp:
  neighbors:
    - {address: 192.0.2.254, add_path: true}
`

func TestPolicyConfigPorts(t *testing.T) {
	pc, err := policy.FromConfig(mustParse(t, portConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(pc.Ports) != 1 || pc.Ports[0] != (policy.PortPolicy{Name: "ix-lab", CapacityMbps: 10000, CommitMbps: 6000}) {
		t.Fatalf("ports = %+v", pc.Ports)
	}
	by := map[string]policy.ProviderPolicy{}
	for _, p := range pc.Providers {
		by[p.Name] = p
	}
	if p := by["ix-peer-a"]; p.Port != "ix-lab" || !p.HasCost || p.Cost != 0 {
		t.Fatalf("peer on a port = %+v, want port ix-lab at marginal cost 0", p)
	}
	if p := by["ix-two-peer"]; p.Port != "" || p.HasCost {
		t.Fatalf("peer on an exchange with no port block = %+v", p)
	}
	if p := by["transit-a"]; p.Port != "" || !p.HasCost || p.Cost != 8 {
		t.Fatalf("transit = %+v", p)
	}
}

func TestPortRowUsesThePortCommit(t *testing.T) {
	const bound = portConfigYAML + `telemetry:
  - type: fixed
    config:
      providers:
        - {name: ix-lab, commit_mbps: 1, usage_mbps: %s}
`
	for _, tc := range []struct {
		usage string
		want  string
	}{{"5000", ""}, {"7000", "commit.exceeded"}} {
		cfg := mustParse(t, fmt.Sprintf(bound, tc.usage))
		set, err := pluginhost.Build(cfg, pluginhost.Options{})
		if err != nil {
			t.Fatal(err)
		}
		raw := collectTelemetry(context.Background(), set)
		if len(raw) != 1 || raw[0].CommitMbps != 1 {
			t.Fatalf("usage %s: the scorers must read the binding as is: %+v", tc.usage, raw)
		}
		rows := exchange.WithPortCommit(raw, exchange.PortCommits(exchangesFromConfig(cfg)))
		if len(rows) != 1 || rows[0].Provider != "ix-lab" || rows[0].CommitMbps != 6000 {
			t.Fatalf("usage %s: rows = %+v, want the port commit 6000", tc.usage, rows)
		}
		if raw[0].CommitMbps != 1 {
			t.Fatal("WithPortCommit changed its input")
		}
		s := &sink{}
		newEventWatch(s, "observe").commit(time.Now(), raw, exchange.PortCommits(exchangesFromConfig(cfg)))
		evs := s.take()
		if got := kinds(evs); got != tc.want {
			t.Fatalf("usage %s: events %q, want %q", tc.usage, got, tc.want)
		}
		if tc.want == "" {
			continue
		}
		// An over-commit port is flagged as the exchange's port, report only.
		e := evs[0]
		if e.Fields["exchange"] != "ix-lab" || e.Fields["commit_mbps"] != "6000.0" ||
			!strings.HasPrefix(e.Message, "exchange port ix-lab 95th percentile 7000.0 Mbps is above its 6000.0 Mbps commit") ||
			!strings.Contains(e.Message, "nothing is moved off the port") {
			t.Fatalf("usage %s: event %+v", tc.usage, e)
		}
	}
}

// A pin onto an exchange peer is refused while the steer would not fit the
// port, and the error names the port (#643). The weighted scorer plans no
// commit, so the port rows and the volume are read for the port alone.
func TestPinOntoAPortPeerNeedsHeadroom(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.128/25")
	cfg := mustParse(t, portConfigYAML+"allowlist: {prefixes: [192.0.2.128/25]}\n")
	for _, tc := range []struct {
		p95  float64
		want string
	}{{5980, "exchange port: ix-lab 95th would reach 6040 of its 6000 Mbps commit with this 60 Mbps steer onto ix-peer-a"}, {5000, ""}} {
		set := scorerSet(t, "weighted", &volSrc{mbps: 60, pfx: p})
		c, err := plugin.ConfigFromYAML(fmt.Sprintf("providers:\n  - {name: ix-lab, commit_mbps: 1, usage_mbps: %v}\n", tc.p95))
		if err != nil {
			t.Fatal(err)
		}
		tel, err := fixed.New(c, plugin.Env{})
		if err != nil {
			t.Fatal(err)
		}
		set.Telemetry = []pluginhost.Instance[plugin.Telemetry]{{Name: "fixed", Type: "fixed", Plugin: tel}}
		decider, err := newDecider(cfg, set)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		in := policy.Input{Native: map[netip.Prefix]string{p: "transit-a"}}
		fillOverloadInputs(context.Background(), &in, cfg, set)
		if len(in.Usage) != 1 || in.Usage[0].Provider != "ix-lab" || in.WeightVolumeMbps[p] != 60 {
			t.Fatalf("port inputs: usage %+v volume %v", in.Usage, in.WeightVolumeMbps)
		}
		decider.Evaluate(in, now)
		pc := pinControl{store: pin.NewStore(), cfg: func() *config.Config { return cfg }, log: slog.New(slog.DiscardHandler),
			learned: func(netip.Prefix) bool { return true }, poke: func() {}, save: func() {},
			port: func(p netip.Prefix, provider string) string { return decider.PortRefusal(p, provider, now) }}
		req := pin.Request{Prefix: p, Provider: "ix-peer-a", MaxLossPct: 5, Duration: time.Hour}
		_, err = pc.Add(req, now)
		if tc.want == "" {
			if err != nil {
				t.Fatalf("port at %v: %v, want the pin set", tc.p95, err)
			}
			continue
		}
		if err == nil || err.Error() != tc.want {
			t.Fatalf("port at %v: err %v, want %q", tc.p95, err, tc.want)
		}
		req.Provider = "transit-a"
		if _, err := pc.Add(req, now); err != nil {
			t.Fatalf("a pin onto a transit is not checked against the port: %v", err)
		}
	}
}
