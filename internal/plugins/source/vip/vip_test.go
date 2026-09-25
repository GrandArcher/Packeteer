package vip

import (
	"context"
	"net/netip"
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

func TestPrefixesCarryInterval(t *testing.T) {
	s, err := build(`
interval: 10s
prefixes:
  - {prefix: 198.51.100.0/24, host: 198.51.100.9}
  - {prefix: "2001:db8:1::/48"}
`)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := s.Targets(context.Background())
	if err != nil || len(ts) != 2 {
		t.Fatalf("ts = %+v err = %v", ts, err)
	}
	if ts[0].Host.String() != "198.51.100.9" || ts[0].Interval != 10*time.Second {
		t.Errorf("first = %+v", ts[0])
	}
	if ts[1].Host.IsValid() || ts[1].Interval != 10*time.Second || ts[1].Prefix.String() != "2001:db8:1::/48" {
		t.Errorf("second = %+v", ts[1])
	}
	ts[0].Interval = time.Hour
	again, _ := s.Targets(context.Background())
	if again[0].Interval != 10*time.Second {
		t.Error("Targets returned a shared slice")
	}
}

func TestASNMatchesLearnedRoutes(t *testing.T) {
	raw, err := build(`
interval: 5s
prefixes:
  - {prefix: 203.0.113.0/24, host: 203.0.113.8}
asns: [64496, 64500]
`)
	if err != nil {
		t.Fatal(err)
	}
	s := raw.(*Source)
	// No callback yet: configured prefixes only. An unready RIB must not
	// invent targets from the ASN list.
	ts, err := s.Targets(context.Background())
	if err != nil || len(ts) != 1 || ts[0].Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("before lookup: %+v %v", ts, err)
	}
	s.SetLearnedRoutes(func() []LearnedRoute {
		return []LearnedRoute{
			{Prefix: netip.MustParsePrefix("198.51.100.0/24"), ASPath: []uint32{64511, 64496}},
			{Prefix: netip.MustParsePrefix("198.51.100.0/25"), ASPath: []uint32{64501}},
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64496}}, // duplicate of the configured prefix
			{Prefix: netip.MustParsePrefix("0.0.0.0/0"), ASPath: []uint32{64496}},
			{Prefix: netip.MustParsePrefix("2001:db8::/32"), ASPath: []uint32{64500}},
		}
	})
	ts, err = s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]time.Duration{}
	for _, tg := range ts {
		got[tg.Prefix.String()] = tg.Interval
		if tg.Prefix.String() == "203.0.113.0/24" && tg.Host.String() != "203.0.113.8" {
			t.Errorf("configured host lost: %+v", tg)
		}
	}
	for _, want := range []string{"203.0.113.0/24", "198.51.100.0/24", "2001:db8::/32"} {
		if got[want] != 5*time.Second {
			t.Errorf("missing %s in %+v", want, got)
		}
	}
	if _, ok := got["198.51.100.0/25"]; ok {
		t.Error("asn 64501 is not on the list")
	}
	if _, ok := got["0.0.0.0/0"]; ok {
		t.Error("default route must not be a VIP target")
	}
	if len(got) != 3 {
		t.Fatalf("targets = %+v", got)
	}
}

func TestConfigErrors(t *testing.T) {
	tests := map[string]string{
		"interval: 10s": "at least one prefix or asn",
		"prefixes:\n  - {prefix: 198.51.100.0/24}":                                               "interval is required",
		"interval: 10ms\nprefixes:\n  - {prefix: 198.51.100.0/24}":                               "at least 1s",
		"interval: -1s\nprefixes:\n  - {prefix: 198.51.100.0/24}":                                "must be positive",
		"interval: 10s\nprefixes:\n  - {prefix: 198.51.100.7/24}":                                "did you mean 198.51.100.0/24",
		"interval: 10s\nprefixes:\n  - {prefix: 198.51.100.0/24, host: 203.0.113.1}":             "must be an address inside",
		"interval: 10s\nprefixes:\n  - {prefix: 0.0.0.0/0}":                                      "default route",
		"interval: 10s\nprefixes:\n  - {prefix: 198.51.100.0/24}\n  - {prefix: 198.51.100.0/24}": "duplicate prefix",
		"interval: 10s\nasns: [0]":                                                               "must be non-zero",
		"interval: 10s\nasns: [64496, 64496]":                                                    "duplicate asn",
		"interval: 10s\nprefixes:\n  - {prefix: 198.51.100.0/24}\nvips: []":                      "field vips not found",
	}
	for y, want := range tests {
		if _, err := build(y); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}
