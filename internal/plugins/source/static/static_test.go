package static

import (
	"context"
	"strings"
	"testing"

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

func TestConfigErrors(t *testing.T) {
	tests := map[string]string{
		"targets:\n  - {prefix: 198.51.100.0/33}":                                "not a valid CIDR",
		"targets:\n  - {prefix: 198.51.100.7/24}":                                "did you mean 198.51.100.0/24",
		"targets:\n  - {prefix: 198.51.100.0/24}\n  - {prefix: 198.51.100.0/24}": "duplicate prefix",
		"targets:\n  - {prefix: 198.51.100.0/24, host: 203.0.113.1}":             "must be an address inside",
		"targets:\n  - {prefix: 198.51.100.0/24, weight: -1}":                    "weight must not be negative",
		"prefixes: []": "field prefixes not found",
	}
	for y, want := range tests {
		if _, err := build(y); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
}
