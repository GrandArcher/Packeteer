package policy

import (
	"net/netip"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// portCfg has a transit "a" over its commit and two peers of an exchange
// port "ix" (#151). The peers carry no telemetry of their own; the port's
// row is named like the exchange.
func portCfg(capacity, commit float64) Config {
	c := cfg()
	zero := ProviderPolicy{Cost: 0, HasCost: true}
	pa, pb := zero, zero
	pa.Name, pa.Port = "ix-a", "ix"
	pb.Name, pb.Port = "ix-b", "ix"
	c.Providers = []ProviderPolicy{{Name: "a", Precedence: 10, Cost: 10, HasCost: true}, pa, pb}
	c.Ports = []PortPolicy{{Name: "ix", CapacityMbps: capacity, CommitMbps: commit}}
	return c
}

func portInput(rows ...plugin.Usage) Input {
	input := in(results(t0, pA, m{"a", 0, 40}, m{"ix-a", 0, 45}, m{"ix-b", 0, 45}), map[netip.Prefix]string{pA: "a"})
	input.ProviderUp = map[string]bool{"a": true, "ix-a": true, "ix-b": true}
	input.Usage = append([]plugin.Usage{billable("a", 100, 150)}, rows...)
	input.VolumeMbps = map[netip.Prefix]float64{pA: 60}
	return input
}

func TestCommitSteersOntoPortOnlyWhileThePortHasRoom(t *testing.T) {
	// Port: 500 of a 600 Mbps commit, 1000 Mbps capacity. 60 Mbps fits.
	st, out := Decide(NewState(), portInput(billable("ix", 1, 500)), portCfg(1000, 600), commitScorer(t, ""), t0)
	imp := st.Improvements[pA]
	if d := decision(t, out, pA); d.Action != ActionImprove || imp.Cause != plugin.CauseCommit || (imp.Provider != "ix-a" && imp.Provider != "ix-b") {
		t.Fatalf("decision %+v improvement %+v", d, imp)
	}
	// 560 of 600: the same move would push the port over its commit.
	st, out = Decide(NewState(), portInput(billable("ix", 1, 560)), portCfg(1000, 600), commitScorer(t, ""), t0)
	if len(st.Improvements) != 0 || decision(t, out, pA).Action != ActionNone {
		t.Fatalf("a move over the port commit was made: %+v %+v", decision(t, out, pA), st.Improvements)
	}
	// No telemetry row for the port: headroom unknown, nothing moves.
	st, _ = Decide(NewState(), portInput(), portCfg(1000, 600), commitScorer(t, ""), t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("a move onto a port with no reading was made: %+v", st.Improvements)
	}
}

func TestCostSteersOntoFlatPricedPortUntilCapacity(t *testing.T) {
	c := portCfg(1000, 0)
	input := portInput(billable("ix", 1, 100))
	st, _ := Decide(NewState(), input, c, costScorer(t, ""), t0)
	imp := st.Improvements[pA]
	if imp.Cause != plugin.CauseCost || (imp.Provider != "ix-a" && imp.Provider != "ix-b") {
		t.Fatalf("improvement %+v, want a cost steer onto a port peer", imp)
	}
	// 960 of 1000 Mbps in use: 60 more would exceed the port.
	st, _ = Decide(NewState(), portInput(billable("ix", 1, 960)), c, costScorer(t, ""), t0)
	if len(st.Improvements) != 0 {
		t.Fatalf("a cost move over the port capacity was made: %+v", st.Improvements)
	}
}
