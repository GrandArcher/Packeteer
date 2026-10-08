package static

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(y string) (plugin.TargetSource, error) {
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		return nil, err
	}
	return plugin.Sources.New(TypeName, c, plugin.Env{})
}

func TestTargets(t *testing.T) {
	s, err := build(`targets:
  - {prefix: 198.51.100.0/24, host: 198.51.100.10, weight: 2}
  - {prefix: "2001:db8::/32"}
`)
	if err != nil {
		t.Fatal(err)
	}
	ts, err := s.Targets(context.Background())
	if err != nil || len(ts) != 2 {
		t.Fatalf("ts = %+v err = %v", ts, err)
	}
	if ts[0].Host.String() != "198.51.100.10" || ts[0].Weight != 2 || ts[1].Host.IsValid() {
		t.Errorf("ts = %+v", ts)
	}
	ts[0].Weight = 99 // callers must not be able to mutate the source
	again, _ := s.Targets(context.Background())
	if again[0].Weight != 2 {
		t.Error("Targets returned shared slice")
	}
}

func TestExchangeLANTargetsDropped(t *testing.T) {
	s, err := build(`targets:
  - {prefix: 198.51.100.0/24, host: 198.51.100.10}
  - {prefix: 203.0.113.0/24, host: 203.0.113.10}
  - {prefix: 203.0.113.128/25}
  - {prefix: "2001:db8:ffff::/64"}
  - {prefix: "2001:db8:1::/48"}
`)
	if err != nil {
		t.Fatal(err)
	}
	src := s.(*Source)
	src.SetExchangeLANs([]netip.Prefix{
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8:ffff::/64"),
	})
	before := exchange.LANDrops()
	ts, err := src.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if exchange.LANDrops()-before != 3 {
		t.Fatalf("drops = %d, want 3", exchange.LANDrops()-before)
	}
	if len(ts) != 2 || ts[0].Prefix.String() != "198.51.100.0/24" || ts[0].Host.String() != "198.51.100.10" || ts[1].Prefix.String() != "2001:db8:1::/48" {
		t.Fatalf("targets = %+v", ts)
	}
	// Without LANs the same list is returned whole.
	src.SetExchangeLANs(nil)
	all, err := src.Targets(context.Background())
	if err != nil || len(all) != 5 {
		t.Fatalf("cleared lans = %+v %v", all, err)
	}
}

func TestVolumes(t *testing.T) {
	s, err := build(`targets:
  - {prefix: 198.51.100.0/24, host: 198.51.100.1, mbps: 80}
  - {prefix: 203.0.113.0/24}
`)
	if err != nil {
		t.Fatal(err)
	}
	vs, ok := s.(plugin.VolumeSource)
	if !ok {
		t.Fatal("static source does not report volume")
	}
	rows, err := vs.Volumes(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Mbps() != 80 {
		t.Fatalf("rows %+v err %v", rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := vs.Volumes(ctx); err == nil {
		t.Fatal("cancelled context returned rows")
	}
}

func TestConfigErrors(t *testing.T) {
	tests := map[string]string{
		"targets:\n  - {prefix: 198.51.100.0/33}":                                "not a valid CIDR",
		"targets:\n  - {prefix: 198.51.100.7/24}":                                "did you mean 198.51.100.0/24",
		"targets:\n  - {prefix: 198.51.100.0/24}\n  - {prefix: 198.51.100.0/24}": "duplicate prefix",
		"targets:\n  - {prefix: 198.51.100.0/24, host: 203.0.113.1}":             "must be an address inside",
		"targets:\n  - {prefix: 198.51.100.0/24, weight: -1}":                    "weight must not be negative",
		"targets:\n  - {prefix: 198.51.100.0/24, mbps: -1}":                      "mbps must be between",
		"prefixes: []": "field prefixes not found",
	}
	for y, want := range tests {
		if _, err := build(y); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}
