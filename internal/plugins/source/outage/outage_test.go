package outage

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(y string) (plugin.TargetSource, error) {
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		return nil, err
	}
	return plugin.Sources.New(TypeName, c, plugin.Env{})
}

func TestConfigValidation(t *testing.T) {
	if _, err := build("nope: true\n"); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("unknown field: %v", err)
	}
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"one prefix", "min_prefixes: 1\n", "min_prefixes"},
		{"huge minimum", "min_prefixes: 10001\n", "min_prefixes"},
		{"short window", "window: 10ms\n", "window"},
		{"long window", "window: 48h\n", "window"},
		{"loss", "loss_pct: 101\n", "loss_pct"},
		{"negative loss", "loss_pct: -1\n", "loss_pct"},
		{"negative rtt", "rtt_ms: -5\n", "rtt_ms"},
		{"short interval", "interval: 100ms\n", "interval"},
		{"zero max", "max_targets: -1\n", "max_targets"},
		{"zero asn", "ignore_asns: [0]\n", "non-zero"},
		{"duplicate asn", "ignore_asns: [64496, 64496]\n", "duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := build(tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	s, err := build("{}\n")
	if err != nil {
		t.Fatal(err)
	}
	src := s.(*Source)
	if src.Interval() != DefaultInterval || src.cfg.MinPrefixes != DefaultMinPrefixes || src.cfg.LossPct != DefaultLossPct || src.cfg.Window != DefaultWindow || src.cfg.MaxTargets != DefaultMaxTargets {
		t.Fatalf("defaults: %+v", src.cfg)
	}
	if !src.Fresh() {
		t.Fatal("outage source must be read every round")
	}
	ts, err := src.Targets(context.Background())
	if err != nil || len(ts) != 0 {
		t.Fatalf("targets before any round: %+v %v", ts, err)
	}
}

func TestEvaluateRequeuesAndNotifiesOnce(t *testing.T) {
	raw, err := build(`
min_prefixes: 3
window: 1m
loss_pct: 20
interval: 5s
max_targets: 10
`)
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*Source)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	routes := []Route{
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64500, 64496}},
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64500, 64497}},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64500, 64498}},
		{Prefix: pfx("2001:db8::/32"), ASPath: []uint32{64500, 64496}},
	}
	samples := []Sample{
		at(now, "transit-a", "192.0.2.0/24", 90),
		at(now, "transit-b", "192.0.2.0/24", 90),
		at(now, "transit-a", "198.51.100.0/24", 90),
		at(now, "transit-b", "198.51.100.0/24", 90),
		at(now, "transit-a", "203.0.113.0/24", 90),
		at(now, "transit-b", "203.0.113.0/24", 90),
	}
	s.SetSnapshots(func() []Sample { return samples }, func() []Route { return routes })
	var events []plugin.Event
	s.SetNotify(func(ev plugin.Event) { events = append(events, ev) })

	if !s.Evaluate(now) {
		t.Fatal("new incident should wake the probe loop")
	}
	if len(events) != 1 || events[0].Kind != EventAS || events[0].Severity != plugin.SeverityCritical {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Fields["asn"] != "64500" || events[0].Fields["count"] != "3" {
		t.Fatalf("fields = %+v", events[0].Fields)
	}
	if !strings.Contains(events[0].Fields["prefixes"], "192.0.2.0/24") || !strings.Contains(events[0].Fields["requeued"], "4") {
		t.Fatalf("fields = %+v", events[0].Fields)
	}
	ts, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tg := range ts {
		got[tg.Prefix.String()] = tg.Urgent
		if !tg.Urgent || tg.Interval != 5*time.Second {
			t.Errorf("first pass = %+v", tg)
		}
	}
	for _, want := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if !got[want] {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
	again, _ := s.Targets(context.Background())
	for _, tg := range again {
		if tg.Urgent {
			t.Errorf("second pass still urgent: %+v", tg)
		}
	}
	if s.Evaluate(now) {
		t.Fatal("unchanged incident must not wake again")
	}
	if len(events) != 1 {
		t.Fatalf("notified again: %+v", events)
	}
	quiet, _ := s.Targets(context.Background())
	for _, tg := range quiet {
		if tg.Urgent {
			t.Errorf("urgent without a new incident: %+v", tg)
		}
	}

	// One prefix recovers. The pattern drops below the minimum.
	samples = []Sample{
		at(now, "transit-a", "192.0.2.0/24", 0),
		at(now, "transit-b", "192.0.2.0/24", 0),
		at(now, "transit-a", "198.51.100.0/24", 90),
		at(now, "transit-b", "198.51.100.0/24", 90),
		at(now, "transit-a", "203.0.113.0/24", 90),
		at(now, "transit-b", "203.0.113.0/24", 90),
	}
	if s.Evaluate(now) {
		t.Fatal("clearing must not wake")
	}
	if len(events) != 2 || events[1].Kind != EventCleared || events[1].Severity != plugin.SeverityWarning {
		t.Fatalf("clear event = %+v", events)
	}
	if events[1].Fields["asn"] != "64500" {
		t.Fatalf("clear fields = %+v", events[1].Fields)
	}
	left, _ := s.Targets(context.Background())
	if len(left) != 0 {
		t.Fatalf("targets after recovery: %+v", left)
	}
	if s.Evaluate(now) || len(events) != 2 {
		t.Fatalf("repeat clear: wake events=%d", len(events))
	}
}

func TestSinglePrefixDoesNotNotify(t *testing.T) {
	raw, err := build("min_prefixes: 3\nwindow: 1m\n")
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*Source)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetSnapshots(
		func() []Sample {
			return []Sample{
				at(now, "transit-a", "192.0.2.0/24", 100),
				at(now, "transit-b", "192.0.2.0/24", 100),
				at(now, "transit-a", "198.51.100.0/24", 0),
			}
		},
		func() []Route {
			return []Route{
				{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64500, 64496}},
				{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64500, 64497}},
			}
		},
	)
	n := 0
	s.SetNotify(func(plugin.Event) { n++ })
	wake := s.Evaluate(now)
	if wake || n != 0 {
		t.Fatalf("single prefix woke=%v events=%d", wake, n)
	}
}

func TestCircuitEvent(t *testing.T) {
	var buf bytes.Buffer
	c, err := plugin.ConfigFromYAML("min_prefixes: 3\nwindow: 1m\nloss_pct: 20\ninterval: 5s\n")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plugin.Sources.New(TypeName, c, plugin.Env{Logger: slog.New(slog.NewTextHandler(&buf, nil))})
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*Source)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	s.SetSnapshots(
		func() []Sample {
			return []Sample{
				at(now, "transit-a", "192.0.2.0/24", 80),
				at(now, "transit-b", "192.0.2.0/24", 0),
				at(now, "transit-a", "198.51.100.0/24", 80),
				at(now, "transit-b", "198.51.100.0/24", 0),
				at(now, "transit-a", "203.0.113.0/24", 80),
				at(now, "transit-b", "203.0.113.0/24", 0),
			}
		},
		func() []Route {
			return []Route{
				{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64500, 64496}, Provider: "transit-a"},
				{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64500, 64497}, Provider: "transit-a"},
				{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64500, 64498}, Provider: "transit-a"},
			}
		},
	)
	var ev plugin.Event
	s.SetNotify(func(e plugin.Event) { ev = e })
	if !s.Evaluate(now) {
		t.Fatal("expected wake")
	}
	if ev.Kind != EventCircuit || ev.Fields["provider"] != "transit-a" || ev.Fields["count"] != "3" {
		t.Fatalf("event = %+v", ev)
	}
	if strings.Contains(buf.String(), "outage.as") || !strings.Contains(buf.String(), "circuit transit-a") {
		t.Fatalf("log = %s", buf.String())
	}
	// Shared ASN must not also open an AS incident when only one provider is sick.
	if s.Evaluate(now) {
		t.Fatal("second pass")
	}
}

func TestLossZeroUsesDefault(t *testing.T) {
	s, err := build("loss_pct: 0\nmin_prefixes: 2\n")
	if err != nil {
		t.Fatal(err)
	}
	if s.(*Source).cfg.LossPct != DefaultLossPct {
		t.Fatalf("loss = %v", s.(*Source).cfg.LossPct)
	}
}
