package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakePassive is a target source with a passive view, as span and flow
// with a problems block have.
type fakePassive struct {
	plugin.Base
	signals map[netip.Prefix]bool
}

func (f *fakePassive) Targets(context.Context) ([]plugin.Target, error) { return nil, nil }
func (f *fakePassive) PassiveSignals() map[netip.Prefix]bool            { return f.signals }

func TestCollectPassive(t *testing.T) {
	pA := netip.MustParsePrefix("198.51.100.0/24")
	pB := netip.MustParsePrefix("203.0.113.0/24")
	pC := netip.MustParsePrefix("192.0.2.0/24")
	span := &fakePassive{signals: map[netip.Prefix]bool{pA: true, pB: false}}
	flow := &fakePassive{signals: map[netip.Prefix]bool{pB: true, pC: false}}
	plain := &fakeClassifier{}
	got := collectPassive(withSources(&pluginhost.Set{}, plain, span, flow))
	// A problem in either source counts; a prefix one source sees clean
	// and the other does not see stays clean.
	if len(got) != 3 || !got[pA] || !got[pB] || got[pC] {
		t.Fatalf("passive = %v", got)
	}
	if got := collectPassive(withSources(&pluginhost.Set{}, plain)); got != nil {
		t.Fatalf("without observers = %v", got)
	}
	if collectPassive(nil) != nil {
		t.Fatal("nil set")
	}
}

func TestPolicyConfigRequireEvidence(t *testing.T) {
	pc, err := policyConfig(mustParse(t, liveApplyConfig(179, "observe", "5m", "1h")))
	if err != nil || pc.RequireEvidence {
		t.Fatalf("default require_evidence = %v (%v)", pc.RequireEvidence, err)
	}
	on := strings.Replace(liveApplyConfig(179, "observe", "5m", "1h"),
		"thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}",
		"thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000, require_evidence: true}", 1)
	if pc, _ := policyConfig(mustParse(t, on)); !pc.RequireEvidence {
		t.Fatal("require_evidence not passed to the decision config")
	}
}
