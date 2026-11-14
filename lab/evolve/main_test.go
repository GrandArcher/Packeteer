package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const (
	fixture  = "testdata/history.jsonl"
	baseline = "testdata/baseline.yaml"
	worse    = "testdata/worse.yaml"
	better   = "testdata/better.yaml"
)

func noEnv(string) string { return "" }

func runJSON(t *testing.T, history string) Report {
	t.Helper()
	var out, errb bytes.Buffer
	if rc := run(context.Background(), []string{"-history", history, "-base", baseline, "-variant", worse, "-variant", better, "-json"}, noEnv, &out, &errb); rc != 0 {
		t.Fatalf("exit %d: %s", rc, errb.String())
	}
	var rep Report
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	return rep
}

// The fixture: 198.51.100.0/24 loses 10% on its native lab-a in rounds
// 10-49, 203.0.113.0/24 is 22 ms faster on lab-b throughout, and
// 192.0.2.0/24 swaps which provider is 25 ms faster every round. worse
// ignores the loss and chases the swaps; better also takes the 22 ms.
func TestFixtureScoresBaselineWorseAndBetter(t *testing.T) {
	rep := runJSON(t, fixture)
	if rep.Rounds != 60 {
		t.Fatalf("rounds %d, want 60", rep.Rounds)
	}
	b := rep.Baseline
	if len(rep.Variants) != 2 {
		t.Fatalf("variants %+v", rep.Variants)
	}
	w, g := rep.Variants[0], rep.Variants[1]
	if w.Name != "worse" || g.Name != "better" || b.Name != "baseline" {
		t.Fatalf("names %q %q %q", b.Name, w.Name, g.Name)
	}
	// 3 prefixes in each of 60 rounds, every path measured.
	for _, s := range []Score{b, w, g} {
		if s.Samples != 180 {
			t.Fatalf("%s: %d samples, want 180", s.Name, s.Samples)
		}
	}
	// The baseline takes 198.51.100.0/24 off the loss after confirm_rounds
	// 3 and stays: 3 lossy rounds of 10% on one of three prefixes.
	if b.Flaps != 0 || b.Moves != 1 || !near(b.LossPct, 3*10.0/180) {
		t.Fatalf("baseline %+v", b)
	}
	if w.Verdict != verdictWorse || w.LossPct <= b.LossPct || w.RTTMs <= b.RTTMs || w.Flaps <= b.Flaps {
		t.Fatalf("worse %+v against baseline %+v", w, b)
	}
	// better also moves 203.0.113.0/24 after round 2 and keeps it: 22 ms
	// lower in the 57 rounds after.
	if g.Verdict != verdictBetter || g.LossPct != b.LossPct || g.Flaps != 0 || !near(b.RTTMs-g.RTTMs, 22.0*57/180) {
		t.Fatalf("better %+v against baseline %+v", g, b)
	}
}

func near(a, b float64) bool { return a-b < 1e-6 && b-a < 1e-6 }

// The same rounds stored in a sqlite file, as a controller with
// round_retention keeps them, score the same as the round file.
func TestSqliteHistoryScoresLikeTheRoundFile(t *testing.T) {
	rf, err := loadRoundFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "packeteer.db")
	c, err := plugin.ConfigFromYAML("path: " + strconv.Quote(db) + "\nround_retention: 24h")
	if err != nil {
		t.Fatal(err)
	}
	st, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	last := rf.rounds[len(rf.rounds)-1].At
	st.SetClock(func() time.Time { return last })
	ctx := context.Background()
	if err := st.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := st.PutRounds(ctx, rf.rounds); err != nil {
		t.Fatal(err)
	}
	if err := st.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := runJSON(t, db), runJSON(t, fixture); !reflect.DeepEqual(got, want) {
		t.Fatalf("sqlite report %+v\nround file report %+v", got, want)
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("the replay wrote to the history file")
	}
}

func TestTextReportListsEverySide(t *testing.T) {
	var out, errb bytes.Buffer
	if rc := run(context.Background(), []string{"-history", fixture, "-base", baseline, "-variant", worse, "-variant", better}, noEnv, &out, &errb); rc != 0 {
		t.Fatalf("exit %d: %s", rc, errb.String())
	}
	t.Log("\n" + out.String())
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 5 || !strings.Contains(lines[0], "replayed 60 rounds") || !strings.Contains(lines[0], "no config was written") {
		t.Fatalf("report:\n%s", out.String())
	}
	for i, want := range [][]string{{"baseline"}, {"worse", verdictWorse}, {"better", verdictBetter}} {
		f := strings.Fields(lines[2+i])
		if f[0] != want[0] || (len(want) > 1 && f[len(f)-1] != want[1]) {
			t.Fatalf("line %q, want %v", lines[2+i], want)
		}
	}
}

func setMode(t *testing.T, path, mode string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, bytes.Replace(data, []byte("mode: observe"), []byte("mode: "+mode), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, dir, name, extra string) string {
	t.Helper()
	data, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, append(data, extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A variant that would turn inject on is refused before any round is
// replayed, and so is any other mode change.
func TestVariantMayNotChangeTheMode(t *testing.T) {
	dir := t.TempDir()
	inject := writeConfig(t, dir, "inject.yaml", `packeteer_community: "64512:666"
local_pref: 250
allowlist: {prefixes: [198.51.100.0/24]}
bgp: {neighbors: [{address: 192.0.2.254}]}
announcer: {type: gobgp}
`)
	setMode(t, inject, "inject")
	suggest := writeConfig(t, dir, "suggest.yaml", "")
	setMode(t, suggest, "suggest")
	for v, want := range map[string]string{inject: "a variant may not enable inject", suggest: "a variant may not change the mode"} {
		var out, errb bytes.Buffer
		rc := run(context.Background(), []string{"-history", fixture, "-base", baseline, "-variant", better, "-variant", v}, noEnv, &out, &errb)
		if rc == 0 || !strings.Contains(errb.String(), want) || out.Len() != 0 {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", filepath.Base(v), rc, out.String(), errb.String())
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-base", baseline, "-variant", worse},
		{"-history", fixture, "-variant", worse},
		{"-history", fixture, "-base", baseline},
		{"-nope"},
	} {
		var out, errb bytes.Buffer
		if rc := run(context.Background(), args, noEnv, &out, &errb); rc != 2 {
			t.Fatalf("%v: exit %d, want 2", args, rc)
		}
	}
}

func TestSnapshotReportsWrittenCreatedAndRemovedConfigs(t *testing.T) {
	dir := t.TempDir()
	kept, written, removed, created := filepath.Join(dir, "kept.yaml"), filepath.Join(dir, "written.yaml"), filepath.Join(dir, "removed.yaml"), filepath.Join(dir, "created.yaml")
	for _, p := range []string{kept, written, removed} {
		if err := os.WriteFile(p, []byte("mode: observe\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := takeSnapshot([]string{kept, written, removed, created})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.changed(); len(got) != 0 {
		t.Fatalf("changed before any write: %v", got)
	}
	if err := os.WriteFile(written, []byte("mode: inject\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created, []byte("mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := s.changed(), []string{created, removed, written}; !reflect.DeepEqual(got, want) {
		t.Fatalf("changed %v, want %v", got, want)
	}
}

func TestWatchedConfigsCoverTheControllerBaseAndVariants(t *testing.T) {
	getenv := func(k string) string {
		if k == controllerConfigEnv {
			return "/run/packeteer/config.yaml"
		}
		return ""
	}
	got := watchedConfigs("base.yaml", []string{"a.yaml", "b.yaml"}, getenv)
	want := []string{controllerConfigPath, "base.yaml", "/run/packeteer/config.yaml", "a.yaml", "b.yaml"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("watched %v, want %v", got, want)
	}
	if got := watchedConfigs("base.yaml", nil, noEnv); !reflect.DeepEqual(got, []string{controllerConfigPath, "base.yaml"}) {
		t.Fatalf("without the env: %v", got)
	}
}

func TestRoundFileRejectsBadHistory(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"order":   `{"at":"2026-10-01T12:00:30Z","input":{}}` + "\n" + `{"at":"2026-10-01T12:00:00Z","input":{}}`,
		"unknown": `{"at":"2026-10-01T12:00:00Z","input":{},"extra":1}`,
		"no time": `{"input":{}}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "")+".jsonl")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRoundFile(p); err == nil {
			t.Fatalf("%s: loaded", name)
		}
	}
}

func TestRoundFileWindowAndLimit(t *testing.T) {
	rf, err := loadRoundFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	from := rf.rounds[10].At
	got, err := rf.Rounds(context.Background(), from, rf.rounds[20].At, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || !got[0].At.Equal(from) || !got[3].At.Equal(rf.rounds[13].At) {
		t.Fatalf("got %d rounds from %v", len(got), got[0].At)
	}
	got, _ = rf.Rounds(context.Background(), from, rf.rounds[12].At, 100)
	if len(got) != 2 {
		t.Fatalf("[10, 12) gave %d rounds, want 2", len(got))
	}
	if _, err := rf.Rounds(context.Background(), from, from, 0); err == nil {
		t.Fatal("limit 0 accepted")
	}
}

// The harness links the scorers and the history store, never an announcer
// or a steerer. The gobgp library itself is linked: the RIB view's types
// come from it.
func TestNoAnnouncerIsLinked(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on PATH")
	}
	out, err := exec.Command(gobin, "list", "-deps", ".").Output()
	if err != nil {
		t.Fatal(err)
	}
	const mod = "github.com/GrandArcher/Packeteer/"
	linked := false
	for _, dep := range strings.Fields(string(out)) {
		if dep == mod+"internal/plugins/scorer/weighted" {
			linked = true
		}
		for _, banned := range []string{"internal/plugins/announcer/", "internal/plugins/steerer/", "internal/plugins/all", "internal/announce"} {
			if strings.HasPrefix(dep, mod+banned) {
				t.Fatalf("%s is linked", dep)
			}
		}
	}
	if !linked {
		t.Fatalf("the weighted scorer is not linked:\n%s", out)
	}
}
