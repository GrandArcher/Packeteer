package main

import (
	"errors"
	"log/slog"
	"net/netip"
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
// first start of a new install.
const setupPendingFile = "first-run-setup-pending"

// placeholderNet is the range of the provider source_ip values in
// config.example.yaml. A config whose providers all sit in it has not been
// set up for a real edge yet.
var placeholderNet = netip.MustParsePrefix("192.0.2.0/24")

// placeholderProviders reports whether the config still has only the
// shipped example providers.
func placeholderProviders(cfg *config.Config) bool {
	if len(cfg.Providers) == 0 {
		return false
	}
	for _, p := range cfg.Providers {
		ip, err := netip.ParseAddr(p.SourceIP)
		if err != nil || !placeholderNet.Contains(ip) {
			return false
		}
	}
	return true
}

// firstRun is the first-run state. Setup is pending on a start with no
// persisted state and only the shipped placeholder providers, until an
// admin saves a config through the editor or wizard, or skips setup. A
// config with a real provider is never pending, so a container re-created
// without the storage volume does not reopen the editor.
type firstRun struct {
	path string
	// fresh is set when this start is the first one for the install and the
	// pending file is not written yet.
	fresh bool
	done  atomic.Bool
}

// newFirstRun reads the state and writes nothing; Persist records a new
// install. Call it before the storage plugin opens its file. A storage
// plugin with no file has nowhere to keep the state, so there the
// placeholder check alone decides.
func newFirstRun(cfg *config.Config, plugins *pluginhost.Set) *firstRun {
	f := &firstRun{path: besideStorage(plugins, setupPendingFile)}
	if f.path != "" {
		if _, err := os.Stat(f.path); err == nil {
			return f
		}
		if _, err := os.Stat(storageFile(plugins)); err == nil {
			f.done.Store(true)
			return f
		}
	}
	if !placeholderProviders(cfg) {
		f.done.Store(true)
		return f
	}
	f.fresh = f.path != ""
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

// settingsPushEditor is the editor the federation settings-push receiver
// and sender write through, or nil when they stay closed. They write the
// file too, so they need the same gate as PUT /api/config, and more: a
// certificate alone must not open a write the operator has not turned on.
// Only an explicit http.config_editor: true counts, never the default that
// the pending first-run setup turns on.
func settingsPushEditor(cfg *config.Config, editor httpapi.ConfigEditor, signedIn bool) httpapi.ConfigEditor {
	if editor == nil || !signedIn || cfg.HTTP.ConfigEditor == nil || !*cfg.HTTP.ConfigEditor {
		return nil
	}
	return editor
}

// setupEditor ends the first-run setup when a config is saved, by the
// editor, the wizard, or an accepted federation push.
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
