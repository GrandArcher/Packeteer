package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/replay"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// whatIfTimeout bounds one replay run from the API.
const whatIfTimeout = 2 * time.Minute

// replaySide builds one side of a replay: the decision config of cfg and a
// scorer of its own. Nothing is started and no announcer is built.
func replaySide(name string, cfg *config.Config, log *slog.Logger, getenv func(string) string) (replay.Side, error) {
	pc, err := policyConfig(cfg)
	if err != nil {
		return replay.Side{}, err
	}
	sc, err := pluginhost.BuildScorer(cfg, pluginhost.Options{Logger: log, Getenv: getenv})
	if err != nil {
		return replay.Side{}, err
	}
	return replay.Side{Name: name, Cfg: pc, Scorer: sc}, nil
}

// replayConfigs decides the stored rounds in [from, to) under the running
// config and, when next is set, under next as well, so the result carries a
// diff. It reads the store and nothing else.
func replayConfigs(ctx context.Context, store plugin.RoundStore, running, next *config.Config, from, to time.Time, log *slog.Logger, getenv func(string) string) (replay.Result, error) {
	sides := make([]replay.Side, 0, 2)
	base, err := replaySide("running config", running, log, getenv)
	if err != nil {
		return replay.Result{}, fmt.Errorf("running config: %w", err)
	}
	sides = append(sides, base)
	if next != nil {
		cand, err := replaySide("candidate config", next, log, getenv)
		if err != nil {
			return replay.Result{}, fmt.Errorf("candidate config: %w", err)
		}
		sides = append(sides, cand)
	}
	return replay.Run(ctx, store, from, to, sides)
}

// whatIfSource serves POST /api/whatif from the running controller. One
// replay runs at a time: it decides every stored round of the window again.
type whatIfSource struct {
	live   *liveConfig
	store  plugin.RoundStore
	check  func([]byte) (*config.Config, error)
	log    *slog.Logger
	getenv func(string) string
	busy   atomic.Bool
}

// Replay implements httpapi.WhatIfControl.
func (w *whatIfSource) Replay(ctx context.Context, candidate []byte, from, to string) (replay.Result, error) {
	run := w.live.snapshot()
	if run == nil {
		return replay.Result{}, errors.New("no running config")
	}
	f, t, err := replay.ParseWindow(from, to, time.Now())
	if err != nil {
		return replay.Result{}, fmt.Errorf("%w: %v", httpapi.ErrWhatIfInput, err)
	}
	var next *config.Config
	if len(candidate) > 0 {
		if next, err = w.check(candidate); err != nil {
			return replay.Result{}, fmt.Errorf("%w: %v", httpapi.ErrWhatIfInput, err)
		}
	}
	if !w.busy.CompareAndSwap(false, true) {
		return replay.Result{}, httpapi.ErrWhatIfBusy
	}
	defer w.busy.Store(false)
	ctx, cancel := context.WithTimeout(ctx, whatIfTimeout)
	defer cancel()
	res, err := replayConfigs(ctx, w.store, run, next, f, t, w.log, w.getenv)
	if errors.Is(err, context.DeadlineExceeded) {
		return replay.Result{}, fmt.Errorf("%w: the replay took longer than %s; use a shorter window", httpapi.ErrWhatIfInput, whatIfTimeout)
	}
	return res, err
}

// roundStoreOf is the storage plugin's round side, when it keeps rounds.
func roundStoreOf(plugins *pluginhost.Set) (plugin.RoundStore, bool) {
	if plugins == nil || plugins.Storage == nil {
		return nil, false
	}
	rs, ok := plugins.Storage.Plugin.(plugin.RoundStore)
	return rs, ok && rs.RoundRetention() > 0
}

// readOnlyOpener is a storage plugin that can be opened for reading alone.
type readOnlyOpener interface {
	OpenReadOnly(ctx context.Context) error
}

// openRoundStore builds the storage plugin of cfg and opens it read-only,
// so the CLI can run beside a controller that writes to the same file.
func openRoundStore(ctx context.Context, cfg *config.Config, log *slog.Logger, getenv func(string) string) (plugin.RoundStore, func(), error) {
	if cfg.Storage == nil {
		return nil, nil, errors.New("the config has no storage: replay needs stored rounds (storage: {type: sqlite, config: {round_retention: 24h}})")
	}
	sp := *cfg.Storage
	node := sp.Config
	st, err := plugin.Storages.New(sp.Type, plugin.NewConfig(&node), plugin.Env{Name: sp.InstanceName(), Logger: log, Getenv: getenv})
	if err != nil {
		return nil, nil, fmt.Errorf("storage (%s): %w", sp.InstanceName(), err)
	}
	rs, ok := st.(plugin.RoundStore)
	op, ro := st.(readOnlyOpener)
	if !ok || !ro {
		return nil, nil, fmt.Errorf("storage type %s does not keep decision rounds", sp.Type)
	}
	if err := op.OpenReadOnly(ctx); err != nil {
		return nil, nil, err
	}
	return rs, func() { _ = st.Stop(context.Background()) }, nil
}

// runWhatIf is `packeteer whatif`: it decides stored rounds again under the
// config given with -config and prints what would differ from the running
// config. It opens the history read-only, starts no probe and no BGP
// session, and has no announcer, so it cannot announce.
func runWhatIf(ctx context.Context, args []string, getenv func(string) string, now time.Time, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("whatif", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaultPath := DefaultConfigPath
	if p := getenv(ConfigEnv); p != "" {
		defaultPath = p
	}
	base := fs.String("base", defaultPath, "path to the running config; its storage is read (env "+ConfigEnv+")")
	candidate := fs.String("config", "", "path to the config to try; without it only the running config is replayed")
	from := fs.String("from", "", "start of the window: an RFC 3339 time or a duration ago such as 6h (default 24h)")
	to := fs.String("to", "", "end of the window: an RFC 3339 time or a duration ago (default now)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "packeteer: whatif: %v\n", err)
		return 1
	}
	f, t, err := replay.ParseWindow(*from, *to, now)
	if err != nil {
		return fail(err)
	}
	running, err := loadReplayConfig(*base, getenv)
	if err != nil {
		return fail(err)
	}
	var next *config.Config
	if *candidate != "" {
		if next, err = loadReplayConfig(*candidate, getenv); err != nil {
			return fail(err)
		}
	}
	log := newLogger(stderr, running.Log.Level, running.Log.Format)
	store, closeStore, err := openRoundStore(ctx, running, log, getenv)
	if err != nil {
		return fail(err)
	}
	defer closeStore()
	res, err := replayConfigs(ctx, store, running, next, f, t, log, getenv)
	if err != nil {
		return fail(err)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			return fail(err)
		}
		return 0
	}
	replay.Format(stdout, res)
	return 0
}

func loadReplayConfig(path string, getenv func(string) string) (*config.Config, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := applyRuntimeEnv(cfg, getenv); err != nil {
		return nil, err
	}
	return cfg, nil
}
