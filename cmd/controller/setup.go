package main

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// setupPendingFile marks the first-run setup as pending (#416). It sits next
// to the storage file, like the first-run password, and is created on the
// first start of a new install: one whose storage file does not exist yet.
// An install that already has its storage, such as one upgraded from an
// earlier release, never gets it and never becomes pending.
const setupPendingFile = "first-run-setup-pending"

// firstRun is the persisted first-run state. Setup is pending from the
// first start of a new install until an admin saves a config through the
// editor or wizard, or skips setup. A storage plugin with no file has
// nowhere to keep the state, so setup is never pending there.
type firstRun struct {
	path string
	// fresh is set when this start is the first one for the install and the
	// pending file is not written yet.
	fresh bool
	done  atomic.Bool
}

// newFirstRun reads the state and writes nothing; Persist records a new
// install. Call it before the storage plugin opens its file.
func newFirstRun(plugins *pluginhost.Set) *firstRun {
	f := &firstRun{path: besideStorage(plugins, setupPendingFile)}
	if f.path == "" {
		f.done.Store(true)
		return f
	}
	if _, err := os.Stat(f.path); err == nil {
		return f
	}
	if _, err := os.Stat(storageFile(plugins)); err == nil {
		f.done.Store(true)
		return f
	}
	f.fresh = true
	return f
}

func (f *firstRun) Pending() bool { return !f.done.Load() }

// Persist writes the pending file for a new install, so a restart before
// the setup is done keeps it pending.
func (f *firstRun) Persist() error {
	if !f.fresh {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(f.path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(f.path, nil, 0o600)
}

// Complete records the setup as finished, in memory first so the redirect
// stops even when the pending file cannot be removed.
func (f *firstRun) Complete() error {
	f.done.Store(true)
	if f.path == "" {
		return nil
	}
	if err := os.Remove(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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
			e.log.Warn("first-run setup: cannot remove the pending file; setup shows again after a restart", "err", cerr)
		}
	}
	return f, res, err
}
