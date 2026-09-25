package policy

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	t0   = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pA   = netip.MustParsePrefix("198.51.100.0/24")
	pB   = netip.MustParsePrefix("203.0.113.0/24")
	pC   = netip.MustParsePrefix("192.0.2.0/25")
	allU = map[string]bool{"a": true, "b": true, "c": true}
)

func scorer(t *testing.T) plugin.Scorer {
	t.Helper()
	s, err := weighted.New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cfg() Config {
	return Config{Mode: "observe", MinLossDeltaPct: 1, MinRTTDelta: 15 * time.Millisecond, HoldTime: 15 * time.Minute,
		MaxImprovements: 50, MaxResultAge: 2 * time.Minute}
}

// m is a measurement: provider, loss %, rtt ms.
type m struct {
	prov string
	loss float64
	rtt  float64
}

func results(at time.Time, p netip.Prefix, ms ...m) []probe.Result {
	var out []probe.Result
	for _, x := range ms {
		out = append(out, probe.Result{Provider: x.prov, Prefix: p, Time: at,
			Stats: probe.Stats{Sent: 10, Received: 10 - int(x.loss/10), LossPct: x.loss,
				RTTAvg: time.Duration(x.rtt * float64(time.Millisecond))}})
	}
	return out
}

func in(res []probe.Result, native map[netip.Prefix]string) Input {
	return Input{Results: res, ProviderUp: allU, RIBEnabled: true, RIBReady: true, Native: native}
}

func decision(t *testing.T, out Output, p netip.Prefix) Decision {
	t.Helper()
	for _, d := range out.Decisions {
		if d.Prefix == p {
			return d
		}
	}
	t.Fatalf("no decision for %s: %+v", p, out.Decisions)
	return Decision{}
}

func TestSinglePrefixDecisions(t *testing.T) {
	native := map[netip.Prefix]string{pA: "a"}
	tests := []struct {
		name       string
		ms         []m
		mutate     func(*Input, *Config)
		wantAction string
		wantProv   string // improvement provider when improving
		wantReason string
	}{
		{"latency improvement beyond threshold", []m{{"a", 0, 50}, {"b", 0, 30}}, nil, ActionImprove, "b", "b: loss"},
		{"latency improvement within threshold", []m{{"a", 0, 50}, {"b", 0, 40}}, nil, ActionNone, "", "native path is best"},
		{"loss dominates latency", []m{{"a", 5, 20}, {"b", 0, 80}}, nil, ActionImprove, "b", ""},
		{"lower latency but more loss", []m{{"a", 0, 80}, {"b", 3, 20}}, nil, ActionNone, "", "native path is best"},
		{"exact tie", []m{{"a", 0, 40}, {"b", 0, 40}}, nil, ActionNone, "", "native path is best"},
		{"picks best of several", []m{{"a", 0, 90}, {"b", 0, 60}, {"c", 0, 30}}, nil, ActionImprove, "c", ""},
		{"excluded best provider skipped", []m{{"a", 0, 90}, {"b", 0, 60}, {"c", 0, 30}},
			func(_ *Input, c *Config) { c.Excluded = map[string]bool{"c": true} }, ActionImprove, "b", ""},
		{"candidate provider down", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) { i.ProviderUp = map[string]bool{"a": true} }, ActionNone, "", "native path is best"},
		{"native provider down: no decision", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) { i.ProviderUp = map[string]bool{"b": true} }, ActionNone, "", "provider down"},
		{"stale probe data: no decision", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) {
				for k := range i.Results {
					i.Results[k].Time = t0.Add(-10 * time.Minute)
				}
			}, ActionNone, "", "stale"},
		{"probe error on native", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) { i.Results[0].Err = "boom" }, ActionNone, "", "probe error"},
		{"prefix not in RIB", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) { i.Native = map[netip.Prefix]string{} }, ActionNone, "", "not in RIB"},
		{"RIB next-hop unknown provider", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) { i.Native = map[netip.Prefix]string{pA: ""} }, ActionNone, "", "matches no provider"},
		{"no RIB configured: ranking only", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(i *Input, _ *Config) { i.RIBEnabled = false }, ActionNone, "", "ranking only"},
		{"inject mode, not allowlisted", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(_ *Input, c *Config) { c.Mode = "inject"; c.Allowlist = []netip.Prefix{pB} }, ActionNone, "", "not allowlisted"},
		{"inject mode, covered by allowlisted aggregate", []m{{"a", 0, 90}, {"b", 0, 30}},
			func(_ *Input, c *Config) {
				c.Mode = "inject"
				c.Allowlist = []netip.Prefix{netip.MustParsePrefix("198.51.0.0/16")}
			}, ActionImprove, "b", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, c := in(results(t0, pA, tt.ms...), native), cfg()
			if tt.mutate != nil {
				tt.mutate(&input, &c)
			}
			st, out := Decide(NewState(), input, c, scorer(t), t0)
			d := decision(t, out, pA)
			if d.Action != tt.wantAction || !strings.Contains(d.Reason, tt.wantReason) {
				t.Fatalf("decision = %+v", d)
			}
			imp, ok := st.Improvements[pA]
			if tt.wantProv == "" {
				if ok || len(out.Changes) != 0 {
					t.Fatalf("unexpected improvement %+v changes %+v", imp, out.Changes)
				}
				return
			}
			if !ok || imp.Provider != tt.wantProv || imp.Native != "a" || len(out.Changes) != 1 || out.Changes[0].Action != ActionImprove {
				t.Fatalf("improvement %+v changes %+v", imp, out.Changes)
			}
		})
	}
}

func TestRankingOnlyRecommends(t *testing.T) {
	input := in(results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30}), nil)
	input.RIBEnabled = false
	_, out := Decide(NewState(), input, cfg(), scorer(t), t0)
	if d := decision(t, out, pA); d.Recommended != "b" {
		t.Fatalf("recommended = %q", d.Recommended)
	}
}

// TestFlapPrevention walks a timeline: improve, native recovers inside hold
// time (keep), after hold time (retire + cooldown), alternative better again
// during cooldown (blocked), after cooldown (improve again).
func TestFlapPrevention(t *testing.T) {
	c, s := cfg(), scorer(t)
	native := map[netip.Prefix]string{pA: "a"}
	good, bad := m{"a", 0, 90}, m{"b", 0, 30} // b better
	step := func(st State, at time.Time, ms []m, nat map[netip.Prefix]string) (State, Decision) {
		st2, out := Decide(st, in(results(at, pA, ms...), nat), c, s, at)
		return st2, decision(t, out, pA)
	}
	st, d := step(NewState(), t0, []m{good, bad}, native)
	if d.Action != ActionImprove {
		t.Fatalf("t0: %+v", d)
	}
	// The prefix stays in the learned RIB for the life of the improvement.
	recovered := []m{{"a", 0, 10}, {"b", 0, 30}}
	st, d = step(st, t0.Add(time.Minute), recovered, native)
	if d.Action != ActionKeep || !strings.Contains(d.Reason, "hold_time") {
		t.Fatalf("t0+1m: %+v", d)
	}
	st, d = step(st, t0.Add(16*time.Minute), recovered, native)
	if d.Action != ActionRetire || !strings.Contains(d.Reason, "native path better") {
		t.Fatalf("t0+16m: %+v", d)
	}
	if _, ok := st.Cooldown[pA]; !ok {
		t.Fatal("no cooldown after flip-back")
	}
	st, d = step(st, t0.Add(17*time.Minute), []m{good, bad}, native)
	if d.Action != ActionNone || !strings.Contains(d.Reason, "cooldown") {
		t.Fatalf("t0+17m: %+v", d)
	}
	_, d = step(st, t0.Add(32*time.Minute), []m{good, bad}, native)
	if d.Action != ActionImprove {
		t.Fatalf("t0+32m: %+v", d)
	}
}

func TestActiveImprovementSafetyRetirements(t *testing.T) {
	base := func() State {
		s := NewState()
		s.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0}
		return s
	}
	ms := []m{{"a", 0, 90}, {"b", 0, 30}, {"c", 0, 60}}
	at := t0.Add(time.Minute) // well inside hold time: safety retirements ignore it
	tests := []struct {
		name   string
		mutate func(*Input, *Config)
		now    time.Time
		reason string
	}{
		{"improvement provider down", func(i *Input, _ *Config) { i.ProviderUp = map[string]bool{"a": true, "c": true} }, at, "provider down"},
		{"improvement provider probe error", func(i *Input, _ *Config) { i.Results[1].Err = "x" }, at, "probe error"},
		{"improvement provider stale", func(i *Input, _ *Config) { i.Results[1].Time = t0.Add(-time.Hour) }, at, "stale"},
		{"provider excluded", func(_ *Input, c *Config) { c.Excluded = map[string]bool{"b": true} }, at, "excluded"},
		{"allowlist no longer covers", func(_ *Input, c *Config) { c.Mode = "inject"; c.Allowlist = []netip.Prefix{pB} }, at, "not allowlisted"},
		{"rib session lost", func(i *Input, _ *Config) { i.RIBReady = false }, at, "rib not ready"},
		{"prefix left the RIB", func(i *Input, _ *Config) { i.Native = map[netip.Prefix]string{} }, at, "no longer in RIB"},
		{"prefix no longer probed", func(i *Input, _ *Config) { i.Results = results(at, pB, ms...) }, at, "no longer probed"},
		{"ttl expired", func(_ *Input, c *Config) { c.ImprovementTTL = 30 * time.Minute }, t0.Add(31 * time.Minute), "ttl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, c := in(results(tt.now, pA, ms...), map[netip.Prefix]string{pA: "a"}), cfg()
			tt.mutate(&input, &c)
			st, out := Decide(base(), input, c, scorer(t), tt.now)
			if _, ok := st.Improvements[pA]; ok {
				t.Fatal("improvement not retired")
			}
			if len(out.Changes) != 1 || out.Changes[0].Action != ActionRetire || !strings.Contains(out.Changes[0].Old.Reason, tt.reason) {
				t.Fatalf("changes = %+v", out.Changes)
			}
			if _, cool := st.Cooldown[pA]; cool {
				t.Error("safety retirement must not start a cooldown")
			}
		})
	}
}

func TestNativeDownKeepsImprovement(t *testing.T) {
	s := NewState()
	s.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0}
	input := in(results(t0.Add(time.Hour), pA, m{"a", 0, 10}, m{"b", 0, 30}), map[netip.Prefix]string{pA: "a"})
	input.ProviderUp = map[string]bool{"b": true}
	st, out := Decide(s, input, cfg(), scorer(t), t0.Add(time.Hour))
	if _, ok := st.Improvements[pA]; !ok || decision(t, out, pA).Action != ActionKeep {
		t.Fatalf("improvement should stay while native unusable: %+v", out.Decisions)
	}
}

func TestSwitchAfterHold(t *testing.T) {
	s := NewState()
	s.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0}
	ms := []m{{"a", 0, 90}, {"b", 0, 60}, {"c", 0, 20}}
	native := map[netip.Prefix]string{pA: "a"}
	_, out := Decide(s, in(results(t0.Add(time.Minute), pA, ms...), native), cfg(), scorer(t), t0.Add(time.Minute))
	if d := decision(t, out, pA); d.Action != ActionKeep {
		t.Fatalf("inside hold: %+v", d)
	}
	st, out := Decide(s, in(results(t0.Add(20*time.Minute), pA, ms...), native), cfg(), scorer(t), t0.Add(20*time.Minute))
	if st.Improvements[pA].Provider != "c" || out.Changes[0].Action != ActionSwitch || out.Changes[0].Old.Provider != "b" {
		t.Fatalf("switch: %+v %+v", st.Improvements[pA], out.Changes)
	}
}

func TestMaxImprovementsBiggestGainsFirst(t *testing.T) {
	var res []probe.Result
	res = append(res, results(t0, pA, m{"a", 0, 100}, m{"b", 0, 80})...) // gain 20
	res = append(res, results(t0, pB, m{"a", 0, 200}, m{"b", 0, 50})...) // gain 150
	res = append(res, results(t0, pC, m{"a", 2, 50}, m{"b", 0, 50})...)  // gain 200
	c := cfg()
	c.MaxImprovements = 2
	st, out := Decide(NewState(), in(res, map[netip.Prefix]string{pA: "a", pB: "a", pC: "a"}), c, scorer(t), t0)
	if len(st.Improvements) != 2 {
		t.Fatalf("improvements = %d", len(st.Improvements))
	}
	if d := decision(t, out, pA); d.Action != ActionCapped || d.Recommended != "b" {
		t.Fatalf("smallest gain should be capped: %+v", d)
	}
	if _, ok := st.Improvements[pB]; !ok {
		t.Error("pB missing")
	}
	if _, ok := st.Improvements[pC]; !ok {
		t.Error("pC missing")
	}
}

func TestDecideDoesNotMutatePrev(t *testing.T) {
	prev := NewState()
	prev.Improvements[pA] = Improvement{Prefix: pA, Provider: "b", Native: "a", Since: t0}
	input := in(nil, nil)
	input.RIBReady = false
	Decide(prev, input, cfg(), scorer(t), t0)
	if _, ok := prev.Improvements[pA]; !ok {
		t.Fatal("Decide mutated the previous state")
	}
}

func TestDeterministicOrdering(t *testing.T) {
	var res []probe.Result
	res = append(res, results(t0, pB, m{"b", 0, 30}, m{"a", 0, 90})...)
	res = append(res, results(t0, pA, m{"a", 0, 90}, m{"b", 0, 30})...)
	_, out := Decide(NewState(), in(res, map[netip.Prefix]string{pA: "a", pB: "a"}), cfg(), scorer(t), t0)
	if out.Decisions[0].Prefix != pA || out.Decisions[0].Candidates[0].Provider != "a" {
		t.Fatalf("ordering: %+v", out.Decisions)
	}
}
