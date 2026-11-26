package offload

import (
	"net/netip"
	"testing"
	"time"
)

func TestBuildVolumeSplitsByLearnedRoute(t *testing.T) {
	learned := func(p netip.Prefix) bool { return p.Addr().Is4() && p.Addr().As4()[0] == 198 }
	rates := map[netip.Prefix]float64{
		netip.MustParsePrefix("198.51.100.0/24"): 60,  // a learned BGP route covers it
		netip.MustParsePrefix("192.0.2.0/24"):    140, // connected or IGP: already in hardware
	}
	v := BuildVolume("lab-sflow", rates, learned)
	if v.Source != "lab-sflow" || v.Prefixes != 2 || v.TotalMbps != 200 || v.IGPMbps != 140 || v.BGPMbps != 60 {
		t.Fatalf("volume = %+v", v)
	}
	if v.HardwareShareMin == nil || *v.HardwareShareMin != 0.7 || len(v.BlindSpots) != 0 {
		t.Errorf("share %v blind spots %+v", v.HardwareShareMin, v.BlindSpots)
	}
}

func TestBuildVolumeNamesItsBlindSpots(t *testing.T) {
	none := BuildVolume("", nil, func(netip.Prefix) bool { return true })
	if none.HardwareShareMin != nil || len(none.BlindSpots) != 1 || none.BlindSpots[0].Code != BlindTrafficFlow {
		t.Errorf("no source: %+v", none)
	}
	silent := BuildVolume("lab-sflow", map[netip.Prefix]float64{}, func(netip.Prefix) bool { return true })
	if len(silent.BlindSpots) != 1 || silent.BlindSpots[0].Code != BlindNoVolume {
		t.Errorf("silent source: %+v", silent)
	}
}

func TestDimensionsReportReserveFreeAndAge(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	b, err := NewBudget(Config{Recheck: time.Minute, Dimensions: []Dimension{FIBv4, NextHops},
		Reserve: map[Dimension]Reserve{FIBv4: {Pct: 0.2}}})
	if err != nil {
		t.Fatal(err)
	}
	samples := map[Dimension]Sample{
		FIBv4: {Reading: Reading{Used: 50, Total: 100, Known: true}, At: now.Add(-20 * time.Second)},
		// Used above the cap is insane: the numbers are shown, the free count is not computed.
		NextHops: {Reading: Reading{Used: 9, Total: 8, Known: true}, At: now},
	}
	got := Dimensions(b, now, []Dimension{FIBv4, NextHops, CPU}, samples, []Freeze{{Reason: FreezeInsane, Dimension: NextHops}, {Reason: FreezeMissing, Dimension: CPU}})
	if r := got[0]; !r.Known || r.Used != 50 || r.Cap != 100 || r.Reserve != 20 || r.Free != 30 || *r.ReadingAgeSeconds != 20 || r.Problem != "" {
		t.Errorf("fib = %+v", r)
	}
	if r := got[1]; r.Free != 0 || r.Reserve != 0 || r.Problem != FreezeInsane {
		t.Errorf("next hops = %+v", r)
	}
	if r := got[2]; r.Known || r.ReadingAgeSeconds != nil || r.Problem != FreezeMissing {
		t.Errorf("cpu = %+v", r)
	}
}

func TestBuildFixesStates(t *testing.T) {
	pfx := netip.MustParsePrefix
	wanted := []Wanted{
		{Candidate: Candidate{Prefix: pfx("203.0.113.0/24")}, Provider: "b"},
		{Candidate: Candidate{Prefix: pfx("198.51.100.0/24"), VolumeMbps: 5}, Provider: "b"},
		{Candidate: Candidate{Prefix: pfx("192.0.2.0/24")}, Provider: "b"},
		{Candidate: Candidate{Prefix: pfx("2001:db8::/32")}, Provider: "b"},
		{Candidate: Candidate{Prefix: pfx("0.0.0.0/0")}, Provider: "b"},
	}
	plan := Plan{Decisions: []Decision{
		{Prefix: pfx("198.51.100.0/24"), Action: Install, Reason: "headroom"},
		{Prefix: pfx("203.0.113.0/24"), Action: Withhold, Reason: "no headroom"},
		{Prefix: pfx("0.0.0.0/0"), Action: Withhold, Reason: invalidReason},
		{Prefix: pfx("192.0.2.0/24"), Action: Withhold, Reason: "frozen"},
	}}
	got := BuildFixes(wanted, map[netip.Prefix]string{pfx("2001:db8::/32"): "ipv6 off"}, plan, "")
	want := []struct {
		prefix string
		state  FixState
	}{
		{"0.0.0.0/0", FixBlocked}, {"192.0.2.0/24", FixBlocked}, {"198.51.100.0/24", FixOffload},
		{"203.0.113.0/24", FixWithhold}, {"2001:db8::/32", FixSoftware},
	}
	if len(got) != len(want) {
		t.Fatalf("fixes = %+v", got)
	}
	for i, w := range want {
		if got[i].Prefix != w.prefix || got[i].State != w.state {
			t.Errorf("fix %d = %+v, want %s %s", i, got[i], w.prefix, w.state)
		}
	}
	if got[2].VolumeMbps == nil || *got[2].VolumeMbps != 5 || got[3].VolumeMbps != nil {
		t.Errorf("volumes = %v, %v", got[2].VolumeMbps, got[3].VolumeMbps)
	}
	for _, f := range BuildFixes(wanted[:1], nil, Plan{}, "no reading") {
		if f.State != FixBlocked || f.Reason != "no reading" {
			t.Errorf("blocked = %+v", f)
		}
	}
}
