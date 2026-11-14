// Command evolve is an experimental, lab-only harness (#584). It replays
// recorded decision rounds through the real Decide path under a baseline
// config and under config variants (scorer weights, thresholds, hold and
// confirm knobs), and scores each by the latency, loss, and flap count of
// the paths it would have chosen:
//
//	evolve -history packeteer.db -base config.yaml -variant a.yaml -variant b.yaml [-json]
//
// -history is a sqlite storage file with round_retention on, opened
// read-only, or a .jsonl round file such as testdata/history.jsonl. The
// harness writes no config, signals no process, and builds no announcer.
// It exits 1 when a variant changes the base's mode (so it can never turn
// inject on) or when a watched config file changed during the run, and 2
// on bad usage.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/commit"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/cost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/scorer/weighted"
	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Where the controller reads its config (cmd/controller ConfigEnv and
// DefaultConfigPath). The harness watches it so a run that changed it fails.
const (
	controllerConfigEnv  = "PACKETEER_CONFIG"
	controllerConfigPath = "/etc/packeteer/config.yaml"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("evolve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	history := fs.String("history", "", "sqlite storage file or .jsonl round file to replay")
	base := fs.String("base", "", "baseline config: the running or checked-in config")
	var variants list
	fs.Var(&variants, "variant", "config variant to score against the baseline (repeatable)")
	asJSON := fs.Bool("json", false, "print the scores as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *history == "" || *base == "" || len(variants) == 0 {
		fmt.Fprintln(stderr, "evolve: -history, -base, and at least one -variant are required")
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "evolve: %v\n", err)
		return 1
	}
	watched := []string{controllerConfigPath, *base}
	if p := getenv(controllerConfigEnv); p != "" {
		watched = append(watched, p)
	}
	watched = append(watched, variants...)
	before, err := takeSnapshot(watched)
	if err != nil {
		return fail(err)
	}
	baseCfg, err := config.Load(*base)
	if err != nil {
		return fail(err)
	}
	cfgs := []*config.Config{baseCfg}
	names := []string{"baseline"}
	for _, v := range variants {
		cfg, err := config.Load(v)
		if err != nil {
			return fail(err)
		}
		if err := sameMode(baseCfg, cfg, v); err != nil {
			return fail(err)
		}
		cfgs = append(cfgs, cfg)
		names = append(names, strings.TrimSuffix(filepath.Base(v), filepath.Ext(v)))
	}
	store, closeStore, err := openHistory(ctx, *history)
	if err != nil {
		return fail(err)
	}
	defer closeStore()
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	sides := make([]replay.Side, len(cfgs))
	paths := make([]*pathScore, len(cfgs))
	for i, cfg := range cfgs {
		s, err := replay.NewSide(names[i], cfg, pluginhost.Options{Logger: log, Getenv: getenv})
		if err != nil {
			return fail(fmt.Errorf("%s: %w", names[i], err))
		}
		paths[i] = &pathScore{}
		s.Observe = paths[i].observe
		sides[i] = s
	}
	res, err := replay.Run(ctx, store, time.Unix(0, 0), time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), sides)
	if err != nil {
		return fail(err)
	}
	if changed := before.changed(); len(changed) > 0 {
		return fail(fmt.Errorf("config changed during the run, which the harness must never do: %s", strings.Join(changed, ", ")))
	}
	rep := newReport(res, paths)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fail(err)
		}
		return 0
	}
	rep.format(stdout)
	return 0
}

// sameMode refuses a variant whose mode differs from the base's. Mode is
// not a scoring knob, and refusing a change is what keeps a variant from
// turning inject on.
func sameMode(base, v *config.Config, path string) error {
	if v.Mode == base.Mode {
		return nil
	}
	if v.Mode == "inject" {
		return fmt.Errorf("%s: mode inject where the base is %s: a variant may not enable inject", path, base.Mode)
	}
	return fmt.Errorf("%s: mode %s where the base is %s: a variant may not change the mode", path, v.Mode, base.Mode)
}

// openHistory opens a .jsonl round file, or else a sqlite storage file
// read-only.
func openHistory(ctx context.Context, path string) (replay.Source, func(), error) {
	if strings.HasSuffix(path, ".jsonl") {
		rf, err := loadRoundFile(path)
		return rf, func() {}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	c, err := plugin.ConfigFromYAML("path: " + strconv.Quote(abs))
	if err != nil {
		return nil, nil, err
	}
	st, err := sqlite.New(c, plugin.Env{Name: "history"})
	if err != nil {
		return nil, nil, err
	}
	if err := st.OpenReadOnly(ctx); err != nil {
		return nil, nil, err
	}
	return st, func() { _ = st.Stop(context.Background()) }, nil
}
