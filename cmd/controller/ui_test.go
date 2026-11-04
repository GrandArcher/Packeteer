package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/upgrade"
)

const uiBase = `mode: observe
asn: 64512
router_id: 192.0.2.10
http:
  config_editor: true
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
`

func editorFor(t *testing.T, content string) (*configedit.Editor, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ed, err := newConfigEditor(cfg, path, func(string) string { return "" }, "ops", false)
	if err != nil || ed == nil {
		t.Fatalf("editor: %v %v", ed, err)
	}
	return ed, path
}

// The editor runs the controller's start checks, not only the parser:
// plugin configs and cross-checks refuse a file config.Parse accepts.
func TestConfigEditorRunsPreflight(t *testing.T) {
	ed, path := editorFor(t, uiBase)
	for name, tc := range map[string]struct{ yaml, want string }{
		"plugin config":  {uiBase + "scorer:\n  type: weighted\n  config:\n    improvement_weights: {volume: -1}\n", "improvement_weights.volume"},
		"unknown plugin": {uiBase + "scorer:\n  type: nope\n", "nope"},
		"subscription notifier": {uiBase + `storage:
  type: sqlite
  config: {path: /var/lib/packeteer/packeteer.db}
notifiers:
  - type: webhook
    name: hook
    config: {url: "https://hooks.example.net/packeteer"}
report_subscriptions:
  - {name: daily, report: summary, schedule: daily, notifier: hook}
`, "does not send reports"},
		"unknown report": {uiBase + `storage:
  type: sqlite
  config: {path: /var/lib/packeteer/packeteer.db}
notifiers:
  - type: smtp
    name: mail
    config: {host: smtp.example.net, from: packeteer@example.net, to: [noc@example.net]}
report_subscriptions:
  - {name: daily, report: nope, schedule: daily, notifier: mail}
`, `report "nope" is unknown`},
	} {
		if _, err := config.Parse([]byte(tc.yaml)); err != nil && name != "unknown plugin" {
			t.Fatalf("%s: parser should accept it: %v", name, err)
		}
		res := ed.Check([]byte(tc.yaml))
		if res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), tc.want) {
			t.Errorf("%s: %+v, want %q", name, res, tc.want)
		}
	}
	// A good edit: restart keys come from the SIGHUP reload's comparison.
	good := uiBase + "hold_time: 20m\nbgp:\n  neighbors:\n    - address: 192.0.2.254\n"
	_, res, err := ed.Save([]byte(good), configedit.Hash([]byte(uiBase)), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.RestartRequired || !res.ReloadOnline || strings.Join(res.Changed, ",") != "bgp.neighbors,hold_time" {
		t.Fatalf("result = %+v", res)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestConfigEditorExplicitFalse(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(uiBase, "  config_editor: true\n", "  config_editor: false\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if ed, err := newConfigEditor(cfg, "/nonexistent", nil, "", true); ed != nil || err != nil {
		t.Fatalf("editor built while off: %v %v", ed, err)
	}
}

// execMarkerScript writes an exec plugin script that leaves a marker file
// whenever it runs, and answers init.
func execMarkerScript(t *testing.T) (script, marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "ran")
	script = filepath.Join(dir, "probe.sh")
	body := "#!/bin/sh\necho x >> " + marker + "\necho '{\"result\":{}}'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, marker
}

// Checking or saving a candidate never runs a program (#34 review): the
// editor refuses exec plugins it did not start with, and builds the ones
// it did start with check-only.
func TestConfigEditorNeverRunsExec(t *testing.T) {
	script, marker := execMarkerScript(t)
	running := uiBase + "probers:\n  - type: exec\n    name: ext\n    config: {command: " + script + "}\n"
	ed, path := editorFor(t, running)
	ran := func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}
	shell := uiBase + `probers:
  - type: exec
    config: {command: /bin/sh, args: [-c, "echo x >> ` + marker + `; echo '{\"result\":{}}'"], env: {P: "${PACKETEER_HTTP_PASSWORD}"}}
`
	for name, tc := range map[string]struct{ yaml, want string }{
		"new exec prober": {shell, "exec plugins cannot be added or changed"},
		"changed args":    {strings.Replace(running, "{command: "+script+"}", "{command: "+script+", args: [x]}", 1), "exec plugins cannot be added or changed"},
		"new exec notifier": {running + "notifiers:\n  - type: exec\n    config: {command: " + script + "}\n",
			"notifiers (exec)"},
		"plugin_dir": {running + "plugin_dir: /tmp\n", "plugin_dir: cannot be changed"},
	} {
		res := ed.Check([]byte(tc.yaml))
		if res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), tc.want) {
			t.Errorf("%s: %+v, want %q", name, res, tc.want)
		}
		if _, _, err := ed.Save([]byte(tc.yaml), configedit.Hash([]byte(running)), false); err == nil {
			t.Errorf("%s: saved", name)
		}
		if ran() {
			t.Fatalf("%s: the editor ran a program", name)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != running {
		t.Fatal("a refused candidate changed the file")
	}
	// The exec plugin the controller runs with is kept, and still not run.
	same := running + "hold_time: 20m\n"
	if res := ed.Check([]byte(same)); !res.Valid {
		t.Fatalf("unchanged exec plugin refused: %+v", res)
	}
	if _, _, err := ed.Save([]byte(same), configedit.Hash([]byte(running)), false); err != nil {
		t.Fatal(err)
	}
	// Removing it is allowed.
	if res := ed.Check([]byte(uiBase)); !res.Valid {
		t.Fatalf("removing an exec plugin refused: %+v", res)
	}
	if ran() {
		t.Fatal("the editor ran the configured exec plugin")
	}
}

// A grpc plugin is a program too: the editor refuses to add or change one and
// builds the running one check-only, so no process starts (#286).
func TestConfigEditorNeverRunsGRPC(t *testing.T) {
	script, marker := execMarkerScript(t)
	running := uiBase + "probers:\n  - type: grpc\n    name: ext\n    config: {command: " + script + "}\n"
	ed, _ := editorFor(t, running)
	for name, tc := range map[string]string{
		"new grpc notifier": running + "notifiers:\n  - type: grpc\n    config: {command: " + script + "}\n",
		"changed args":      strings.Replace(running, "{command: "+script+"}", "{command: "+script+", args: [x]}", 1),
	} {
		res := ed.Check([]byte(tc))
		if res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), "grpc plugins cannot be added or changed") {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if res := ed.Check([]byte(running + "hold_time: 20m\n")); !res.Valid {
		t.Fatalf("unchanged grpc plugin refused: %+v", res)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the editor started a grpc plugin")
	}
}

// After a SIGHUP reload applies new bgp.neighbors, the editor diffs
// against them, not against the config from start.
func TestConfigEditorFollowsReload(t *testing.T) {
	ed, path := editorFor(t, uiBase)
	reloaded := uiBase + "bgp:\n  neighbors:\n    - address: 192.0.2.254\n"
	if res := ed.Check([]byte(reloaded)); !res.ReloadOnline {
		t.Fatalf("before reload: %+v", res)
	}
	if err := os.WriteFile(path, []byte(reloaded), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ed.SetRunning(cfg)
	if res := ed.Check([]byte(reloaded)); !res.Valid || res.ReloadOnline || res.RestartRequired || len(res.Changed) != 0 {
		t.Fatalf("after reload: %+v", res)
	}
}

// putConfig sends PUT /api/config as the basic-auth admin.
func putConfig(t *testing.T, h http.Handler, yaml, base string) (int, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"yaml": yaml, "base": base})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("ops", "ops-password")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// The upgrade block decides which binary an upgrade runs: its public_key
// verifies the release, repo and api_url say where it comes from. The
// editor refuses any change to it (FAB-01); only the mounted file sets it.
func TestConfigEditorRefusesUpgradeChange(t *testing.T) {
	pub, _, err := upgrade.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := upgrade.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	block := "upgrade:\n  enabled: true\n  public_key: " + pub + "\n  dir: " + dir + "\n"
	running := uiBase + block
	ed, path := editorFor(t, running)
	srv, err := httpapi.New(httpapi.Options{User: "ops", Password: "ops-password", ConfigEditor: ed})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	base := configedit.Hash([]byte(running))
	for name, yaml := range map[string]string{
		"public_key":     strings.Replace(running, pub, other, 1),
		"repo":           running + "  repo: example/fork\n",
		"api_url":        running + "  api_url: https://api.example.net\n",
		"dir":            strings.Replace(running, dir, dir+"/other", 1),
		"enabled":        strings.Replace(running, "enabled: true", "enabled: false", 1),
		"check_interval": running + "  check_interval: 24h\n",
		"removed":        uiBase,
	} {
		if _, err := config.Parse([]byte(yaml)); err != nil {
			t.Fatalf("%s: the parser should accept it: %v", name, err)
		}
		code, body := putConfig(t, h, yaml, base)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "upgrade: cannot be changed through the config editor") {
			t.Errorf("%s: PUT = %d %s", name, code, body)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != running {
		t.Fatal("a refused upgrade change was written")
	}
	// Adding the block is refused too.
	plain, plainPath := editorFor(t, uiBase)
	if res := plain.Check([]byte(running)); res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), "upgrade: cannot be changed") {
		t.Fatalf("adding the upgrade block: %+v", res)
	}
	if b, _ := os.ReadFile(plainPath); string(b) != uiBase {
		t.Fatal("the file changed on a check")
	}
	// Other keys still save with the upgrade block as it runs.
	if code, body := putConfig(t, h, running+"hold_time: 20m\n", base); code != http.StatusOK {
		t.Fatalf("unrelated change: PUT = %d %s", code, body)
	}
}

// After a reload removes an exec source, the editor compares with the
// config now running, so putting the same source back is refused
// (FAB-10). Before, it compared with the config the process started with.
func TestConfigEditorProgramCheckFollowsReload(t *testing.T) {
	script, _ := execMarkerScript(t)
	start := uiBase + "sources:\n  - type: static\n    name: one\n    config: {targets: [{prefix: 198.51.100.0/24}]}\n" +
		"  - type: exec\n    name: ext\n    config: {command: " + script + "}\n"
	removed := strings.Replace(start, "  - type: exec\n    name: ext\n    config: {command: "+script+"}\n", "", 1)
	ed, path := editorFor(t, start)
	if res := ed.Check([]byte(start + "hold_time: 20m\n")); !res.Valid {
		t.Fatalf("exec source the controller started with: %+v", res)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyRuntimeEnv(cfg, noEnv); err != nil {
		t.Fatal(err)
	}
	cfg.DefaultAuth(true)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	plugins, err := pluginhost.Build(cfg, pluginhost.Options{Logger: log, Getenv: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(cfg, plugins, log, nil, nil, nil, packetLimiter(cfg), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	decider, err := newDecider(cfg, plugins)
	if err != nil {
		t.Fatal(err)
	}
	rl := &reloader{path: path, getenv: noEnv, httpUser: "ops", log: log, cur: cfg, plugins: plugins, engine: engine, decider: decider,
		opts: pluginhost.Options{Logger: log, Getenv: noEnv}, applied: ed.SetRunning}
	if err := os.WriteFile(path, []byte(removed), 0o600); err != nil {
		t.Fatal(err)
	}
	if applied, refused, fatal := rl.reload(context.Background()); refused != nil || fatal != nil || !slices.Contains(applied, "sources") {
		t.Fatalf("reload: applied %v refused %v fatal %v", applied, refused, fatal)
	}
	res := ed.Check([]byte(start))
	if res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), "sources (ext): exec plugins cannot be added or changed") {
		t.Fatalf("re-adding the removed exec source: %+v", res)
	}
	if _, _, err := ed.Save([]byte(start), configedit.Hash([]byte(removed)), false); err == nil {
		t.Fatal("re-adding the removed exec source saved")
	}
}
