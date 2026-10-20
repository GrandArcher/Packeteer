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

// The state lives in a marker file next to the storage file, so it
// survives a restart; storage without a file keeps nothing.
func TestFirstRunState(t *testing.T) {
	dir := t.TempDir()
	fr := newFirstRun(storageIn(dir))
	if !fr.Pending() {
		t.Fatal("a new install is not pending")
	}
	if err := fr.Complete(); err != nil || fr.Pending() {
		t.Fatalf("complete: %v pending=%v", err, fr.Pending())
	}
	if _, err := os.Stat(filepath.Join(dir, setupDoneFile)); err != nil {
		t.Fatalf("marker file: %v", err)
	}
	if newFirstRun(storageIn(dir)).Pending() {
		t.Fatal("setup is pending again after a restart")
	}

	for name, set := range map[string]*pluginhost.Set{"no storage": {}, "nil set": nil} {
		fr := newFirstRun(set)
		if !fr.Pending() {
			t.Fatalf("%s: not pending", name)
		}
		if err := fr.Complete(); err != nil || fr.Pending() {
			t.Fatalf("%s: complete: %v pending=%v", name, err, fr.Pending())
		}
		if !newFirstRun(set).Pending() {
			t.Fatalf("%s: pending state survived a restart with nowhere to keep it", name)
		}
	}
}

// A failed marker write still ends the setup for this run, and says so.
func TestFirstRunMarkerWriteFails(t *testing.T) {
	fr := newFirstRun(storageIn(filepath.Join(t.TempDir(), "missing")))
	if err := fr.Complete(); err == nil {
		t.Fatal("complete reported success without a marker file")
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
	fr := newFirstRun(storageIn(dir))
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
	if newFirstRun(storageIn(dir)).Pending() {
		t.Fatal("the saved state did not reach the marker file")
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
