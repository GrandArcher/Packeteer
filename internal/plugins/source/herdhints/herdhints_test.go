package herdhints

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func newSource(t *testing.T, yaml string) *Source {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Source)
}

func TestTargetsKeepHintsWithEnoughVantagesUpToTheCap(t *testing.T) {
	s := newSource(t, "{min_vantages: 2, max_targets: 2}")
	if got, err := s.Targets(context.Background()); err != nil || len(got) != 0 {
		t.Fatalf("no reader: %v %v", got, err)
	}
	s.SetHints(func() []Hint {
		return []Hint{
			{netip.MustParsePrefix("192.0.2.0/26"), 4},
			{netip.MustParsePrefix("198.51.100.0/24"), 1},
			{netip.MustParsePrefix("0.0.0.0/0"), 9},
			{netip.MustParsePrefix("203.0.113.0/24"), 2},
			{netip.MustParsePrefix("192.0.2.64/26"), 3},
		}
	})
	got, err := s.Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tg := range got {
		names = append(names, tg.Prefix.String())
	}
	if strings.Join(names, " ") != "192.0.2.0/26 203.0.113.0/24" {
		t.Errorf("targets = %v; want two hints with 2 or more vantages, no default route", names)
	}
}

func TestDefaultsAndBounds(t *testing.T) {
	if s := newSource(t, "{}"); s.cfg.MinVantages != DefaultMinVantages || s.cfg.MaxTargets != DefaultMaxTargets {
		t.Errorf("defaults = %+v", s.cfg)
	}
	for _, y := range []string{"{min_vantages: 65}", "{max_targets: -1}", "{max_targets: 1025}", "{loss_pct: 5}"} {
		c, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := New(c, plugin.Env{}); err == nil {
			t.Errorf("%s: accepted", y)
		}
	}
}
