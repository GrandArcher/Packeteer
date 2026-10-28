package blast

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	pA  = netip.MustParsePrefix("198.51.100.0/24")
	pB  = netip.MustParsePrefix("203.0.113.0/24")
	pC  = netip.MustParsePrefix("192.0.2.0/24")
)

func imp(p netip.Prefix, native, to string) policy.Improvement {
	return policy.Improvement{Prefix: p, Native: native, Provider: to, Cause: plugin.CausePerformance, Reason: to + ": lower loss"}
}

func what(imps ...policy.Improvement) policy.WhatIf {
	st := policy.NewState()
	for _, im := range imps {
		st.Improvements[im.Prefix] = im
	}
	return policy.WhatIf{State: st}
}

func inject(allow ...netip.Prefix) policy.Config {
	return policy.Config{Mode: "inject", Allowlist: allow, MaxImprovements: 50, MaxResultAge: 2 * time.Minute}
}

func has(rep Report, code string) *Warning {
	for i := range rep.Warnings {
		if rep.Warnings[i].Code == code {
			return &rep.Warnings[i]
		}
	}
	return nil
}

func prefixes(rs []Route) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Prefix.String())
	}
	return out
}

func TestBuildAddMoveWithdrawKeep(t *testing.T) {
	onWire := []policy.Improvement{imp(pA, "a", "b"), imp(pB, "a", "b"), imp(pC, "a", "b")}
	w := what(imp(pA, "a", "b"), imp(pB, "a", "c"))
	rep := Build(Params{Now: now, Cfg: inject(pA, pB, pC), OnWire: onWire, What: w,
		Volumes: map[netip.Prefix]float64{pB: 40, pC: 10}})
	if len(rep.Add) != 0 || rep.Keep != 1 {
		t.Fatalf("add %v keep %d, want none and one", prefixes(rep.Add), rep.Keep)
	}
	if len(rep.Move) != 1 || rep.Move[0].Prefix != pB || rep.Move[0].From != "b" || rep.Move[0].To != "c" {
		t.Fatalf("move = %+v, want %s b -> c", rep.Move, pB)
	}
	if len(rep.Withdraw) != 1 || rep.Withdraw[0].Prefix != pC || rep.Withdraw[0].From != "b" || rep.Withdraw[0].To != "a" {
		t.Fatalf("withdraw = %+v, want %s back to a", rep.Withdraw, pC)
	}
	if !rep.Changes || !rep.Announces || rep.Mode != "inject" {
		t.Fatalf("changes %v announces %v mode %s", rep.Changes, rep.Announces, rep.Mode)
	}
	by := map[string]Shift{}
	for _, s := range rep.Providers {
		by[s.Provider] = s
	}
	// Moving 40 Mbps from b to c and 10 Mbps back from b to a.
	if b := by["b"]; b.OutMbps != 50 || b.InMbps != 0 {
		t.Fatalf("b = %+v, want 50 out", b)
	}
	if c := by["c"]; c.InMbps != 40 {
		t.Fatalf("c = %+v, want 40 in", c)
	}
	if a := by["a"]; a.InMbps != 10 {
		t.Fatalf("a = %+v, want 10 in", a)
	}
}

func TestBuildAddsFromEmptyWireWithUnknownVolume(t *testing.T) {
	w := what(imp(pA, "a", "b"), imp(pB, "a", "b"))
	rep := Build(Params{Now: now, Cfg: inject(pA, pB), What: w, Volumes: map[netip.Prefix]float64{pA: 25}})
	if got := prefixes(rep.Add); !slices.Equal(got, []string{pA.String(), pB.String()}) {
		t.Fatalf("add = %v", got)
	}
	if rep.Add[0].VolumeMbps == nil || *rep.Add[0].VolumeMbps != 25 || rep.Add[1].VolumeMbps != nil {
		t.Fatalf("volumes = %v %v, want 25 and unknown", rep.Add[0].VolumeMbps, rep.Add[1].VolumeMbps)
	}
	var b Shift
	for _, s := range rep.Providers {
		if s.Provider == "b" {
			b = s
		}
	}
	if b.InMbps != 25 || b.Unknown != 1 {
		t.Fatalf("b = %+v, want 25 in and 1 unknown", b)
	}
	if v := has(rep, WarnVolume); v == nil || v.Count != 1 {
		t.Fatalf("volume warning = %+v", v)
	}
}

// A decided mode other than inject puts nothing on the wire: every route
// there now is a withdrawal.
func TestBuildNotInjectWithdrawsEverything(t *testing.T) {
	cfg := inject(pA)
	cfg.Mode = "observe"
	rep := Build(Params{Now: now, Cfg: cfg, OnWire: []policy.Improvement{imp(pA, "a", "b")}, What: what(imp(pA, "a", "b"))})
	if rep.Announces || len(rep.Add)+len(rep.Move) != 0 || len(rep.Withdraw) != 1 || rep.Keep != 0 {
		t.Fatalf("observe report = %+v", rep)
	}
	if len(rep.Warnings) != 0 {
		t.Fatalf("observe warnings = %+v", rep.Warnings)
	}
}

func TestBuildRefusedRoutesAreNotAnnounced(t *testing.T) {
	w := what(imp(pA, "a", "b"), imp(pB, "a", "b"))
	refuse := func(im policy.Improvement) string {
		if im.Prefix == pA {
			return "held out by the leak watch"
		}
		return ""
	}
	rep := Build(Params{Now: now, Cfg: inject(pA, pB), What: w, Refuse: refuse})
	if got := prefixes(rep.Add); !slices.Equal(got, []string{pB.String()}) {
		t.Fatalf("add = %v, want only %s", got, pB)
	}
	r := has(rep, WarnRefused)
	if r == nil || r.Count != 1 || !strings.Contains(r.Prefixes[0], "leak watch") {
		t.Fatalf("refused warning = %+v", r)
	}
}

// A provider that would pass its capacity limit or its commit warns; a
// provider with room does not.
func TestBuildSaturationWarnings(t *testing.T) {
	w := what(imp(pA, "a", "b"), imp(pB, "a", "c"))
	usage := []plugin.Usage{
		{Provider: "b", OutMbps: 80, CapacityMbps: 100, CommitMbps: 90},
		{Provider: "c", OutMbps: 10, CapacityMbps: 1000, CommitMbps: 500},
		{Provider: "a", OutMbps: 300, CapacityMbps: 1000},
	}
	cfg := inject(pA, pB)
	cfg.Providers = []policy.ProviderPolicy{{Name: "b", CapacityThresholdPct: 90}}
	rep := Build(Params{Now: now, Cfg: cfg, What: w, Usage: usage,
		Volumes: map[netip.Prefix]float64{pA: 30, pB: 30}})
	var capacity, commit []string
	for _, wn := range rep.Warnings {
		switch wn.Code {
		case WarnCapacity:
			capacity = append(capacity, wn.Provider)
		case WarnCommit:
			commit = append(commit, wn.Provider)
		}
	}
	if !slices.Equal(capacity, []string{"b"}) || !slices.Equal(commit, []string{"b"}) {
		t.Fatalf("capacity %v commit %v, want b only (b: 80+30=110 Mbps, limit 90, commit 90; c has room)", capacity, commit)
	}
	var b Shift
	for _, s := range rep.Providers {
		if s.Provider == "b" {
			b = s
		}
	}
	if b.ProjectedMbps != 110 || b.LimitMbps != 90 || b.CurrentMbps != 80 {
		t.Fatalf("b = %+v, want current 80 projected 110 limit 90", b)
	}
	if w := has(rep, WarnCapacity); !strings.Contains(w.Message, "110.0") || !strings.Contains(w.Message, "90.0") {
		t.Fatalf("capacity message = %q", w.Message)
	}
}

func TestBuildNoSaturationWarningWhenTrafficLeaves(t *testing.T) {
	// b is over its capacity now; moving traffic off it is no new warning.
	w := what()
	usage := []plugin.Usage{{Provider: "b", OutMbps: 120, CapacityMbps: 100}, {Provider: "a", OutMbps: 10, CapacityMbps: 1000}}
	rep := Build(Params{Now: now, Cfg: inject(pA), OnWire: []policy.Improvement{imp(pA, "a", "b")}, What: w, Usage: usage,
		Volumes: map[netip.Prefix]float64{pA: 20}})
	if has(rep, WarnCapacity) != nil {
		t.Fatalf("warnings = %+v", rep.Warnings)
	}
	for _, s := range rep.Providers {
		if s.Provider == "b" && s.ProjectedMbps != 100 {
			t.Fatalf("b projected = %v, want 100", s.ProjectedMbps)
		}
	}
}

func TestShiftZeroMbpsInJSON(t *testing.T) {
	// The Settings page reads current_mbps and projected_mbps whenever
	// capacity_mbps is set, so a zero must be sent, not dropped: b is an
	// idle backup taking pA, and all of a's traffic moves off.
	usage := []plugin.Usage{{Provider: "a", OutMbps: 20, CapacityMbps: 1000}, {Provider: "b", CapacityMbps: 1000}}
	rep := Build(Params{Now: now, Cfg: inject(pA), What: what(imp(pA, "a", "b")), Usage: usage,
		Volumes: map[netip.Prefix]float64{pA: 20}})
	raw, err := json.Marshal(rep.Providers)
	if err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]float64{"a": {20, 0}, "b": {0, 20}}
	if len(got) != len(want) {
		t.Fatalf("providers = %s", raw)
	}
	for _, s := range got {
		w := want[s["provider"].(string)]
		cur, okC := s["current_mbps"].(float64)
		proj, okP := s["projected_mbps"].(float64)
		if !okC || !okP || cur != w[0] || proj != w[1] {
			t.Fatalf("providers = %s, want %s current %v projected %v present", raw, s["provider"], w[0], w[1])
		}
	}
}

func TestBuildCapAllowlistAndMeasurementWarnings(t *testing.T) {
	cfg := inject(pA)
	cfg.MaxImprovements = 1
	w := what(imp(pA, "a", "b"))
	w.Output.Decisions = []policy.Decision{
		{Prefix: pA, Action: policy.ActionImprove, Current: "a", Recommended: "b"},
		{Prefix: pB, Action: policy.ActionCapped, Current: "a", Recommended: "b"},
		{Prefix: pC, Action: policy.ActionNone, Current: "a", Recommended: "b"},
	}
	stale := now.Add(-10 * time.Minute)
	w.Input.Results = []probe.Result{
		{Prefix: pA, Provider: "a", Time: stale, Stats: probe.Stats{Sent: 10, Received: 10}},
		{Prefix: pA, Provider: "b", Time: stale, Stats: probe.Stats{Sent: 10, Received: 10}},
	}
	cfg.Allowlist = []netip.Prefix{pA, netip.MustParsePrefix("2001:db8::/32")}
	rep := Build(Params{Now: now, Cfg: cfg, What: w})
	if c := has(rep, WarnCap); c == nil || c.Count != 1 || c.Prefixes[0] != pB.String() {
		t.Fatalf("cap warning = %+v", c)
	}
	if a := has(rep, WarnAllowlist); a == nil || a.Count != 1 || a.Prefixes[0] != pC.String() {
		t.Fatalf("allowlist warning = %+v, want %s (outside the allowlist, better path wanted)", a, pC)
	}
	if s := has(rep, WarnStale); s == nil || s.Prefixes[0] != pA.String() {
		t.Fatalf("stale warning = %+v", s)
	}
	if u := has(rep, WarnUnmeasured); u == nil || u.Prefixes[0] != "2001:db8::/32" {
		t.Fatalf("unmeasured warning = %+v", u)
	}
}

func TestBuildEmptyAllowlistWarns(t *testing.T) {
	rep := Build(Params{Now: now, Cfg: inject(), What: what()})
	if has(rep, WarnNoAllowlist) == nil {
		t.Fatalf("warnings = %+v", rep.Warnings)
	}
	if rep.Add == nil || rep.Move == nil || rep.Withdraw == nil || rep.Providers == nil || rep.Warnings == nil {
		t.Fatal("empty lists must be empty, not null, in the JSON")
	}
}

func TestWarningsNameAtMostFivePrefixes(t *testing.T) {
	cfg := inject(pA)
	w := what()
	for i := range 8 {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i * 16)}), 28)
		w.Output.Decisions = append(w.Output.Decisions, policy.Decision{Prefix: p, Action: policy.ActionImprove, Current: "a", Recommended: "b"})
	}
	rep := Build(Params{Now: now, Cfg: cfg, What: w})
	a := has(rep, WarnAllowlist)
	if a == nil || a.Count != 8 || len(a.Prefixes) != maxListed {
		t.Fatalf("allowlist warning = %+v, want count 8 and 5 named", a)
	}
}

func TestGatedAndInputsFixed(t *testing.T) {
	for _, tc := range []struct {
		online []string
		gated  bool
	}{
		{[]string{"allowlist"}, true},
		{[]string{"thresholds", "probe.interval"}, true},
		{[]string{"max_improvements"}, true},
		{[]string{"policies"}, true},
		{[]string{"sources"}, true},
		{[]string{"mode"}, true},
		{[]string{"probe.interval", "probe.timeout"}, false},
		{[]string{"inbound.mode", "mitigation.mode", "bgp.neighbors"}, false},
		{nil, false},
	} {
		if got := Gated(tc.online); got != tc.gated {
			t.Errorf("Gated(%v) = %v, want %v", tc.online, got, tc.gated)
		}
	}
	rep := Build(Params{Now: now, Cfg: inject(pA), What: what(), Changed: []string{"thresholds", "policies", "sources"}})
	w := has(rep, WarnInputs)
	if w == nil || !strings.Contains(w.Message, "policies and sources") || strings.Contains(w.Message, "thresholds") {
		t.Fatalf("inputs warning = %+v", w)
	}
	if has(Build(Params{Now: now, Cfg: inject(pA), What: what(), Changed: []string{"thresholds"}}), WarnInputs) != nil {
		t.Fatal("thresholds alone must not warn that inputs are fixed")
	}
}

// A synthesized sub-range (#122) is listed with its covering prefix and
// raises the synthesize warning; a refused one is listed as refused.
func TestBuildShowsSynthesizedRoutes(t *testing.T) {
	sub := netip.MustParsePrefix("198.51.100.0/25")
	other := netip.MustParsePrefix("198.51.100.128/25")
	s1, s2 := imp(sub, "a", "b"), imp(other, "a", "b")
	s1.Covering, s2.Covering = pA, pA
	refuse := func(im policy.Improvement) string {
		if im.Prefix == other {
			return "covering prefix 198.51.100.0/24 is not in the learned RIB"
		}
		return ""
	}
	rep := Build(Params{Now: now, Cfg: inject(pA), What: what(s1, s2, imp(pA, "a", "c")), Refuse: refuse})
	if len(rep.Add) != 2 || rep.Add[0].Prefix != pA || rep.Add[0].Covering.IsValid() || rep.Add[1].Prefix != sub || rep.Add[1].Covering != pA {
		t.Fatalf("add = %+v", rep.Add)
	}
	w := has(rep, WarnSynthesized)
	if w == nil || w.Count != 1 || w.Prefixes[0] != "198.51.100.0/25 inside 198.51.100.0/24" || !strings.Contains(w.Message, "NOT in the learned RIB") {
		t.Fatalf("synthesized warning = %+v", w)
	}
	if r := has(rep, WarnRefused); r == nil || r.Count != 1 || !strings.Contains(r.Prefixes[0], "198.51.100.128/25") {
		t.Fatalf("refused warning = %+v", r)
	}
	body, err := json.Marshal(rep.Add[1])
	if err != nil || !strings.Contains(string(body), `"covering":"198.51.100.0/24"`) {
		t.Fatalf("json = %s %v", body, err)
	}
	if body, _ := json.Marshal(rep.Add[0]); strings.Contains(string(body), "covering") {
		t.Fatalf("exact route json = %s", body)
	}
	cfg := inject(pA)
	cfg.Mode = "observe"
	if has(Build(Params{Now: now, Cfg: cfg, What: what(s1), Refuse: refuse}), WarnSynthesized) != nil {
		t.Fatal("observe preview warns about routes it would not announce")
	}
}
