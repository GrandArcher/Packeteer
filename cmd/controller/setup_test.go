package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fileStore is a storage plugin that has a file, which is all firstRun
// reads from it.
type fileStore struct {
	plugin.Storage
	path string
}

func (f fileStore) Path() string { return f.path }

func storageIn(dir string) *pluginhost.Set {
	return &pluginhost.Set{Storage: &pluginhost.Instance[plugin.Storage]{Name: "db", Type: "sqlite", Plugin: fileStore{path: filepath.Join(dir, "packeteer.db")}}}
}

func setupConfig(t *testing.T, httpExtra, authBlock string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(strings.Replace(uiBase, "  config_editor: true\n", httpExtra, 1) + authBlock))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func placeholderCfg(t *testing.T) *config.Config {
	t.Helper()
	return setupConfig(t, "", "")
}

// realCfg has providers outside the shipped 192.0.2.0/24 placeholders.
func realCfg(t *testing.T) *config.Config {
	t.Helper()
	text := strings.NewReplacer("source_ip: 192.0.2.11", "source_ip: 198.51.100.11", "source_ip: 192.0.2.12", "source_ip: 198.51.100.12").Replace(uiBase)
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// The editor decision for an unset http.config_editor follows the
// first-run state; an explicit value always wins; sign-in is required.
func TestEditorEnabled(t *testing.T) {
	const authOn, authOff = "auth:\n  enabled: true\nstorage:\n  type: sqlite\n", "auth:\n  enabled: false\n"
	for _, tc := range []struct {
		name     string
		http     string
		auth     string
		user     string
		pending  bool
		wantEdit bool
	}{
		{"unset and pending", "", authOn, "", true, true},
		{"unset and pending with basic auth", "", authOff, "ops", true, true},
		{"unset and completed", "", authOn, "", false, false},
		{"explicit false while pending", "  config_editor: false\n", authOn, "", true, false},
		{"explicit true when completed", "  config_editor: true\n", authOn, "", false, true},
		{"auth off while pending", "", authOff, "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := setupConfig(t, tc.http, tc.auth)
			if got := editorEnabled(cfg, tc.user, tc.pending); got != tc.wantEdit {
				t.Fatalf("editorEnabled = %v, want %v", got, tc.wantEdit)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(uiBase), 0o600); err != nil {
				t.Fatal(err)
			}
			ed, err := newConfigEditor(cfg, path, noEnv, tc.user, tc.pending)
			if err != nil || (ed != nil) != tc.wantEdit {
				t.Fatalf("newConfigEditor = %v, %v; want built %v", ed, err, tc.wantEdit)
			}
		})
	}
}

// A start with no persisted state and the placeholder providers is pending
// and keeps that across a restart until the setup ends. Existing storage
// without a pending file means setup is completed.
func TestFirstRunState(t *testing.T) {
	dir := t.TempDir()
	fr := newFirstRun(placeholderCfg(t), storageIn(dir))
	if !fr.Pending() {
		t.Fatal("a new install is not pending")
	}
	if _, err := os.Stat(filepath.Join(dir, setupPendingFile)); !os.IsNotExist(err) {
		t.Fatalf("newFirstRun wrote the pending file: %v", err)
	}
	if err := fr.Persist(); err != nil {
		t.Fatal(err)
	}
	// The storage plugin opens its file after the first start.
	if err := os.WriteFile(filepath.Join(dir, "packeteer.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := newFirstRun(placeholderCfg(t), storageIn(dir))
	if !restarted.Pending() {
		t.Fatal("setup is not pending after a restart before it ended")
	}
	if err := restarted.Complete(); err != nil || restarted.Pending() {
		t.Fatalf("complete: %v pending=%v", err, restarted.Pending())
	}
	if _, err := os.Stat(filepath.Join(dir, setupPendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending file after complete: %v", err)
	}
	if newFirstRun(placeholderCfg(t), storageIn(dir)).Pending() {
		t.Fatal("setup is pending again after a restart")
	}
	if err := restarted.Complete(); err != nil {
		t.Fatalf("second complete: %v", err)
	}
}

func TestFirstRunCompletedStateIsNotPending(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "packeteer.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fr := newFirstRun(placeholderCfg(t), storageIn(dir))
	if fr.Pending() {
		t.Fatal("an install with existing storage is pending")
	}
	if err := fr.Persist(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, setupPendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending file written for an existing install: %v", err)
	}
}

// A config with a real provider is never pending, whatever the storage
// holds: a container re-created without its volume must not reopen the
// editor. That covers a missing file, memory storage, and a new volume.
func TestFirstRunRealConfigIsNotPending(t *testing.T) {
	dir := t.TempDir()
	for name, set := range map[string]*pluginhost.Set{"new volume": storageIn(dir), "no storage": {}, "nil set": nil} {
		fr := newFirstRun(realCfg(t), set)
		if fr.Pending() {
			t.Fatalf("%s: a real config is pending", name)
		}
		if err := fr.Persist(); err != nil || fr.Complete() != nil {
			t.Fatalf("%s: persist/complete failed", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, setupPendingFile)); !os.IsNotExist(err) {
		t.Fatalf("pending file written for a real config: %v", err)
	}
}

// With nowhere to keep the state (memory storage), the shipped placeholder
// config is pending for this run and ending it works without a file.
func TestFirstRunPlaceholderWithoutFileIsPending(t *testing.T) {
	for name, set := range map[string]*pluginhost.Set{"no storage": {}, "nil set": nil} {
		fr := newFirstRun(placeholderCfg(t), set)
		if !fr.Pending() {
			t.Fatalf("%s: the placeholder config is not pending", name)
		}
		if err := fr.Persist(); err != nil {
			t.Fatalf("%s: persist: %v", name, err)
		}
		if err := fr.Complete(); err != nil || fr.Pending() {
			t.Fatalf("%s: complete: %v pending=%v", name, err, fr.Pending())
		}
	}
}

// A provider list that mixes a placeholder with a real address, or lists
// none, is not the shipped example.
func TestPlaceholderProviders(t *testing.T) {
	mixed := strings.Replace(uiBase, "source_ip: 192.0.2.12", "source_ip: 198.51.100.12", 1)
	cfg, err := config.Parse([]byte(mixed))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		cfg  *config.Config
		want bool
	}{"placeholders": {placeholderCfg(t), true}, "real": {realCfg(t), false}, "mixed": {cfg, false}, "none": {&config.Config{}, false}} {
		if got := placeholderProviders(tc.cfg); got != tc.want {
			t.Errorf("%s: placeholderProviders = %v, want %v", name, got, tc.want)
		}
	}
}

// A failed pending-file removal still ends the setup for this run, and says
// so.
func TestFirstRunCompleteFails(t *testing.T) {
	dir := t.TempDir()
	fr := newFirstRun(placeholderCfg(t), storageIn(dir))
	if err := fr.Persist(); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory in the file's place cannot be removed.
	if err := os.Remove(filepath.Join(dir, setupPendingFile)); err != nil {
		t.Fatal(err)
	}
	pend := filepath.Join(dir, setupPendingFile)
	if err := os.MkdirAll(filepath.Join(pend, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fr.Complete(); err == nil {
		t.Fatal("complete reported success while the pending file remains")
	}
	if fr.Pending() {
		t.Fatal("still pending in this run")
	}
}

// Saving a config through the editor ends the setup; a refused save does
// not.
func TestSetupEditorSaveEndsSetup(t *testing.T) {
	cfg := setupConfig(t, "", "auth:\n  enabled: true\nstorage:\n  type: sqlite\n")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(uiBase), 0o600); err != nil {
		t.Fatal(err)
	}
	ed, err := newConfigEditor(cfg, path, noEnv, "", true)
	if err != nil || ed == nil {
		t.Fatalf("editor: %v %v", ed, err)
	}
	dir := t.TempDir()
	fr := newFirstRun(placeholderCfg(t), storageIn(dir))
	if err := fr.Persist(); err != nil {
		t.Fatal(err)
	}
	wrapped := setupEditor{ConfigEditor: ed, state: fr, log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	if _, _, err := wrapped.Save([]byte(uiBase), "stale", false); !errors.Is(err, configedit.ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}
	if !fr.Pending() {
		t.Fatal("a refused save ended the setup")
	}
	file, err := wrapped.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrapped.Save([]byte(uiBase+"hold_time: 20m\n"), file.SHA256, false); err != nil {
		t.Fatalf("save: %v", err)
	}
	if fr.Pending() {
		t.Fatal("a saved config did not end the setup")
	}
	if err := os.WriteFile(filepath.Join(dir, "packeteer.db"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if newFirstRun(placeholderCfg(t), storageIn(dir)).Pending() {
		t.Fatal("the saved state did not reach the pending file")
	}
}

// The stock config.example.yaml, which has providers, opens the editor on
// a first start.
func TestCheckReportsFirstRunEditor(t *testing.T) {
	path := authConfig(t, "")
	var out bytes.Buffer
	if code := run(context.Background(), []string{"-check", "-config", path}, noEnv, &out, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "http config_editor: on until first-run setup is done") {
		t.Fatalf("first run: %s", out.String())
	}
}
