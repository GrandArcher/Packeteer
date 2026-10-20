package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// setupDoneFile marks the first-run setup as finished (#416). It sits next
// to the storage file, like the first-run password.
const setupDoneFile = "first-run-setup-done"

// firstRun is the persisted first-run state. Setup is pending until an
// admin saves a config through the editor or wizard, or skips setup. A
// storage plugin with no file has nowhere to keep it, so setup is pending
// on every start.
type firstRun struct {
	path string
	done atomic.Bool
}

func newFirstRun(plugins *pluginhost.Set) *firstRun {
	f := &firstRun{}
	if plugins == nil || plugins.Storage == nil {
		return f
	}
	if p, ok := plugins.Storage.Plugin.(interface{ Path() string }); ok {
		f.path = filepath.Join(filepath.Dir(p.Path()), setupDoneFile)
		if _, err := os.Stat(f.path); err == nil {
			f.done.Store(true)
		}
	}
	return f
}

func (f *firstRun) Pending() bool { return !f.done.Load() }

// Complete records the setup as finished, in memory first so the redirect
// stops even when the marker cannot be written.
func (f *firstRun) Complete() error {
	f.done.Store(true)
	if f.path == "" {
		return nil
	}
	return os.WriteFile(f.path, nil, 0o600)
}

// editorEnabled is the config editor decision. An explicit
// http.config_editor wins. Unset turns it on while setup is pending, and
// only with sign-in: it never opens an unauthenticated write.
func editorEnabled(cfg *config.Config, httpUser string, setupPending bool) bool {
	if cfg.HTTP.ConfigEditor != nil {
		return *cfg.HTTP.ConfigEditor
	}
	return setupPending && (cfg.AuthEnabled() || httpUser != "")
}

// setupEditor ends the first-run setup when a config is saved.
type setupEditor struct {
	httpapi.ConfigEditor
	state *firstRun
	log   *slog.Logger
}

func (e setupEditor) Save(data []byte, base string, confirmInject bool) (configedit.File, configedit.Result, error) {
	f, res, err := e.ConfigEditor.Save(data, base, confirmInject)
	if err == nil {
		if cerr := e.state.Complete(); cerr != nil {
			e.log.Warn("first-run setup: cannot write the marker file; setup shows again after a restart", "err", cerr)
		}
	}
	return f, res, err
}
