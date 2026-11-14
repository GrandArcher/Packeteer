package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// shortRun runs lab/chaos/short.yaml against the simulated pair from the
// repository root, where the profile's config paths resolve.
func shortRun(t *testing.T, setup func(*fakeLab, *Profile)) (*Report, *fakeLab) {
	t.Helper()
	t.Chdir("../..")
	prof, err := loadProfile("lab/chaos/short.yaml")
	if err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	lab := newFakeLab(clk)
	if setup != nil {
		setup(lab, &prof)
	}
	return newRunner(lab, clk, prof, example).run(context.Background()), lab
}

func invariants(rep *Report) []string {
	var out []string
	for _, v := range rep.Violations {
		out = append(out, v.Invariant)
	}
	return out
}

func TestShortProfilePassesAndWritesReport(t *testing.T) {
	rep, lab := shortRun(t, nil)
	if !rep.Pass || len(rep.Violations) != 0 || len(rep.Errors) != 0 {
		t.Fatalf("pass %v, violations %+v, errors %v", rep.Pass, rep.Violations, rep.Errors)
	}
	for _, kind := range faultKinds {
		if rep.FaultCounts[kind] < 1 {
			t.Errorf("%s never ran: %v", kind, rep.FaultCounts)
		}
	}
	if rep.Ended.Sub(rep.Started) < time.Minute {
		t.Errorf("run ended after %v, before the 1m window", rep.Ended.Sub(rep.Started))
	}
	if want := []string{probesDown, probesUp}; !slices.Equal(lab.probeFiles[:2], want) {
		t.Errorf("probe files %v, want %v first", lab.probeFiles, want)
	}
	for _, f := range rep.Faults {
		if f.WithdrawMs == nil || f.RestoreMs == nil || f.Error != "" {
			t.Errorf("%s: withdraw %v restore %v error %q", f.Kind, f.WithdrawMs, f.RestoreMs, f.Error)
			continue
		}
		switch f.Kind {
		case faultSIGTERM:
			if f.WithdrawnWhileUp == nil || !*f.WithdrawnWhileUp || f.ExitCode == nil || *f.ExitCode != 0 {
				t.Errorf("sigterm: while up %v, exit %v", f.WithdrawnWhileUp, f.ExitCode)
			}
		case faultSIGKILL:
			if f.HoldMs != fakeHoldMs || *f.WithdrawMs > f.HoldMs+killSlack.Milliseconds() || *f.WithdrawMs < f.HoldMs {
				t.Errorf("sigkill: withdraw %dms, hold %dms", *f.WithdrawMs, f.HoldMs)
			}
			if f.ExitCode == nil || *f.ExitCode != 137 {
				t.Errorf("sigkill exit %v", f.ExitCode)
			}
		}
	}
	var session, takeover bool
	for _, e := range rep.Events {
		session = session || e.Kind == "session" && e.Subject == "pk-a" && e.Detail == "Established -> Active"
		takeover = takeover || e.Kind == "lease" && e.Subject == "pk-b" && e.Detail == `active, holder "pk-b"`
	}
	if !session || !takeover {
		t.Errorf("events lack pk-a's session drop (%v) or pk-b's takeover (%v): %+v", session, takeover, rep.Events)
	}

	dir := t.TempDir()
	if err := rep.write(dir); err != nil {
		t.Fatal(err)
	}
	var back Report
	raw, err := os.ReadFile(filepath.Join(dir, "chaos-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.Pass || back.Samples != rep.Samples || len(back.Faults) != len(rep.Faults) || back.Profile != "short" {
		t.Fatalf("chaos-result.json round trip: %+v", back)
	}
	md, err := os.ReadFile(filepath.Join(dir, "chaos-summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# Chaos soak: short", "Result: **PASS**", fmt.Sprintf("| sigkill | %d | 3000 |", rep.FaultCounts[faultSIGKILL]), "Invariant failures: none", "Errors: none"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("summary lacks %q:\n%s", want, md)
		}
	}
}

func TestShortProfileFailsOnBrokenInvariant(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*fakeLab, *Profile)
		want  string
	}{
		{"sigterm leaves routes to the session close", func(l *fakeLab, _ *Profile) { l.termNoWithdraw = true }, invSIGTERM},
		{"graceful restart on the session", func(l *fakeLab, _ *Profile) { l.gr = true }, invGR},
		{"standby announces too", func(l *fakeLab, _ *Profile) { l.both = true }, invHABoth},
		{"prefix outside the learned RIB", func(l *fakeLab, _ *Profile) { l.unlearned = true }, invLearnedRIB},
		{"edge keeps a killed peer's routes", func(l *fakeLab, _ *Profile) { l.keepAfterKill = true }, invSIGKILL},
		{"inject configs in a profile that is not an inject lab", func(_ *fakeLab, p *Profile) { p.InjectLab = false }, invConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, _ := shortRun(t, tc.setup)
			if rep.Pass {
				t.Fatal("the run passed")
			}
			if !slices.Contains(invariants(rep), tc.want) {
				t.Fatalf("violations %+v, errors %v; want %s", rep.Violations, rep.Errors, tc.want)
			}
			if !strings.Contains(rep.markdown(), "Result: **FAIL**") || !strings.Contains(rep.markdown(), "`"+tc.want+"`") {
				t.Fatalf("summary:\n%s", rep.markdown())
			}
		})
	}
}

func TestViolationRepeatsCount(t *testing.T) {
	r := newRunner(nil, &fakeClock{}, Profile{}, example)
	v := Violation{Invariant: invGR, Detail: "x"}
	r.violate(v, v, Violation{Invariant: invGR, Detail: "y"})
	r.violate(v)
	if len(r.rep.Violations) != 2 || r.rep.Violations[0].Count != 3 || r.rep.Violations[1].Count != 1 {
		t.Fatalf("%+v", r.rep.Violations)
	}
}

func TestUncleanSIGTERMExitFails(t *testing.T) {
	rep, _ := shortRun(t, func(l *fakeLab, _ *Profile) { l.termExit = 1 })
	if rep.Pass || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "exited 1 after SIGTERM, want 0") {
		t.Fatalf("pass %v, errors %v", rep.Pass, rep.Errors)
	}
}

func TestStandbyAnnouncingAfterSessionFlapFails(t *testing.T) {
	// The flapped instance takes the lease back as soon as its session
	// returns: it is not back as standby.
	clk := &fakeClock{now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)}
	lab := newFakeLab(clk)
	r := newRunner(lab, clk, Profile{Name: "flap"}, example)
	f := Fault{Kind: faultSessionFlap, At: clk.now}
	lab.after(4*time.Second, func() { lab.holder = 0 })
	err := r.sessionFlap(context.Background(), &f, pair[0], pair[1])
	if err == nil || !strings.Contains(err.Error(), "pk-a back as standby") {
		t.Fatalf("err %v", err)
	}
}

// A hosted-length run repeats the fault list, runs no pause past the
// window, and keeps the flap quarantine of the configs out of play: a
// link flap is two changes of the prefix and the default is 6 an hour.
func TestHostedProfileSpacesPasses(t *testing.T) {
	rep, _ := shortRun(t, func(_ *fakeLab, p *Profile) {
		hosted, err := loadProfile("lab/chaos/hosted.yaml")
		if err != nil {
			t.Fatal(err)
		}
		*p = withDuration(hosted, 2*time.Hour)
	})
	if !rep.Pass || len(rep.Violations) != 0 || len(rep.Errors) != 0 {
		t.Fatalf("pass %v, violations %+v, errors %v", rep.Pass, rep.Violations, rep.Errors)
	}
	var flaps []time.Time
	for _, f := range rep.Faults {
		if f.Kind == faultLinkFlap {
			flaps = append(flaps, f.At)
		}
	}
	if len(flaps) < 4 {
		t.Fatalf("%d link flaps in 2h, want at least 4 (one per 30m pause): %v", len(flaps), rep.FaultCounts)
	}
	const changesPerFlap, maxFlips = 2, 6
	for i := range flaps {
		n := 0
		for _, at := range flaps[i:] {
			if at.Sub(flaps[i]) < time.Hour {
				n++
			}
		}
		if n*changesPerFlap > maxFlips {
			t.Errorf("%d link flaps within 1h of %v: %d changes, quarantine at more than %d", n, flaps[i], n*changesPerFlap, maxFlips)
		}
	}
	if rep.Ended.Sub(rep.Started) < 2*time.Hour {
		t.Errorf("run ended after %v, before the 2h window", rep.Ended.Sub(rep.Started))
	}
	if rep.Ended.Sub(rep.Started) > 2*time.Hour+30*time.Minute {
		t.Errorf("run ended after %v, a pause ran past the window", rep.Ended.Sub(rep.Started))
	}
}

// The pause is sampled like a fault: the edge is read every tick through
// it, so a broken invariant would show in it.
func TestPassPauseIsSampled(t *testing.T) {
	const pause = 10 * time.Minute
	rep, _ := shortRun(t, func(_ *fakeLab, p *Profile) {
		p.PassPause = pause
		p.Duration = 15 * time.Minute
	})
	if !rep.Pass {
		t.Fatalf("%+v %v", rep.Violations, rep.Errors)
	}
	var flaps []time.Time
	for _, f := range rep.Faults {
		if f.Kind == faultSessionFlap {
			flaps = append(flaps, f.At)
		}
	}
	if len(flaps) != 2 {
		t.Fatalf("session flaps %v, want two passes", flaps)
	}
	if gap := flaps[1].Sub(flaps[0]); gap < pause {
		t.Errorf("second pass %v after the first began, pause is %v", gap, pause)
	}
	elapsed := rep.Ended.Sub(rep.Started)
	if got := time.Duration(rep.Samples) * tick; got < elapsed*9/10 {
		t.Errorf("%d samples cover %v of a %v run: the pause went unsampled", rep.Samples, got, elapsed)
	}
}
