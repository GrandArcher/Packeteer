package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestBackupRestoreRoundTrip backs up a config and its sqlite history with
// -backup, restores both into new paths with -restore, and checks the
// guards: no overwrite without -force, flags that need -restore, and a
// file that is not a backup (#31).
func TestBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	db := filepath.Join(dir, "data", "packeteer.db")
	cfgText := fmt.Sprintf(`mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
storage:
  type: sqlite
  config: {path: %s}
`, db)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	// Some history, written the way the controller writes it.
	c, _ := plugin.ConfigFromYAML("path: " + db)
	st, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(ctx); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(-time.Hour)
	if err := st.Write(ctx, plugin.HistoryBatch{Improvements: []plugin.ImprovementRecord{{ID: "x", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-a", Native: "transit-a", Start: start}}}); err != nil {
		t.Fatal(err)
	}

	archive := filepath.Join(dir, "backup.tgz")
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"-config", cfgPath, "-backup", archive}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("backup exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "config and sqlite history") {
		t.Fatalf("backup output: %s", out.String())
	}
	if err := st.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"-config", cfgPath, "-backup", archive}, noEnv, &out, &errOut); code == 0 {
		t.Fatal("backup overwrote an existing archive")
	}

	// Existing history is not replaced without -force.
	errOut.Reset()
	if code := run(ctx, []string{"-restore", archive}, noEnv, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "-force") {
		t.Fatalf("restore over existing history: exit %d %s", code, errOut.String())
	}
	// Lose the data directory, then restore it and the config.
	if err := os.RemoveAll(filepath.Dir(db)); err != nil {
		t.Fatal(err)
	}
	restoredCfg := filepath.Join(dir, "restored", "config.yaml")
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"-restore", archive, "-restore-config", restoredCfg}, noEnv, &out, &errOut); code != 0 {
		t.Fatalf("restore exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"sqlite history restored", "config written to " + restoredCfg, "restore: ok"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("restore output lacks %q:\n%s", want, out.String())
		}
	}
	got, err := os.ReadFile(restoredCfg)
	if err != nil || string(got) != cfgText {
		t.Fatalf("restored config = %q (%v)", got, err)
	}
	st2, _ := sqlite.New(c, plugin.Env{})
	if err := st2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer st2.Stop(ctx)
	h, err := st2.Read(ctx, plugin.HistoryQuery{From: start.Add(-time.Hour), To: time.Now().Add(time.Hour)})
	if err != nil || len(h.Improvements) != 1 || h.Improvements[0].ID != "x" {
		t.Fatalf("restored history = %+v (%v)", h, err)
	}
	// The config file exists now.
	errOut.Reset()
	if code := run(ctx, []string{"-restore", archive, "-restore-config", restoredCfg}, noEnv, &out, &errOut); code == 0 {
		t.Fatal("restore replaced an existing config without -force")
	}

	errOut.Reset()
	if code := run(ctx, []string{"-config", cfgPath, "-force"}, noEnv, &out, &errOut); code != 2 {
		t.Fatalf("-force without -restore: exit %d", code)
	}
	if code := run(ctx, []string{"-restore", cfgPath}, noEnv, &out, &errOut); code == 0 {
		t.Fatal("restored from a file that is not a backup")
	}
}

// A config with no storage block runs with sign-in and the default sqlite
// store (#328). -backup and -restore resolve that store too, so users,
// tokens, and the audit log are not left out; with the HTTP server off
// there is no default store.
func TestBackupRestoreDefaultStorage(t *testing.T) {
	if _, err := os.Stat(sqlite.DefaultPath); !errors.Is(err, os.ErrNotExist) {
		t.Skipf("%s exists here", sqlite.DefaultPath)
	}
	ctx := context.Background()
	dir := t.TempDir()
	cfgText := "mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}\n"
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	httpOff := envOf(map[string]string{HTTPListenEnv: "off"})

	// Backup only reads: the default store has no file here, so the
	// attempt shows in the error.
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"-config", cfgPath, "-backup", filepath.Join(dir, "a.tgz")}, noEnv, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "no history at "+sqlite.DefaultPath) {
		t.Fatalf("backup did not read the default sqlite store: exit %d %s %s", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(ctx, []string{"-config", cfgPath, "-backup", filepath.Join(dir, "b.tgz")}, httpOff, &out, &errOut); code != 0 || !strings.Contains(out.String(), "(config)") {
		t.Fatalf("backup with the HTTP server off: exit %d %s %s", code, out.String(), errOut.String())
	}

	// The history type does not match the store the config resolves to,
	// so restore stops before it writes anything.
	archive := filepath.Join(dir, "other.tgz")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	man, _ := json.Marshal(manifest{Format: backupFormat, Storage: &manifestStorage{Name: "other", Type: "other"}})
	for _, e := range []struct {
		name string
		data []byte
	}{{backupManifest, man}, {backupConfig, []byte(cfgText)}, {backupHistory, []byte("x")}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := run(ctx, []string{"-restore", archive}, noEnv, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "config has sqlite") {
		t.Fatalf("restore did not resolve the default sqlite store: exit %d %s", code, errOut.String())
	}
	errOut.Reset()
	if code := run(ctx, []string{"-restore", archive}, httpOff, &out, &errOut); code == 0 || !strings.Contains(errOut.String(), "its config has no storage") {
		t.Fatalf("restore with the HTTP server off: exit %d %s", code, errOut.String())
	}
}
