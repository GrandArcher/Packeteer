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
	"gopkg.in/yaml.v3"
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
// editor refuses any change to it, adding or removing it included (FAB-01);
// only the mounted file sets it. Other keys still save beside it.
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
	plain, plainPath := editorFor(t, uiBase)
	if res := plain.Check([]byte(running)); res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), "upgrade: cannot be changed") {
		t.Fatalf("adding the upgrade block: %+v", res)
	}
	if b, _ := os.ReadFile(plainPath); string(b) != uiBase {
		t.Fatal("the file changed on a check")
	}
	if code, body := putConfig(t, h, running+"hold_time: 20m\n", base); code != http.StatusOK {
		t.Fatalf("unrelated change: PUT = %d %s", code, body)
	}
}

// After a reload removes an exec source, the editor compares with the
// config now running, so putting the same source back is refused
// (FAB-10).
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

const uiSNMP = `telemetry:
  - type: snmp
    config:
      hosts:
        - name: edge
          address: 192.0.2.254
          version: 2c
          community_env: SNMP_COMMUNITY
      providers:
        - {name: transit-a, host: edge, interface: ether1}
`

// A *_env key names the variable whose value a plugin sends to its host.
// Through the editor it must start with the prefix of its plugin, so an
// admin cannot send the admin password over SNMPv2c to a host they name
// (#504). A name the running config already uses there still saves, so
// the mounted file is unaffected.
func TestConfigEditorRestrictsEnvNames(t *testing.T) {
	running := uiBase + uiSNMP
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(running), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SNMP_COMMUNITY": "lab-only-a", "PACKETEER_SNMP_EDGE": "lab-only-b", "PACKETEER_TRAP_COMMUNITY": "lab-only-c",
		"PACKETEER_ADMIN_PASSWORD": "lab-only-d"}
	ed, err := newConfigEditor(cfg, path, func(k string) string { return env[k] }, "ops", false)
	if err != nil || ed == nil {
		t.Fatalf("editor: %v %v", ed, err)
	}
	srv, err := httpapi.New(httpapi.Options{User: "ops", Password: "ops-password", ConfigEditor: ed})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	base := configedit.Hash([]byte(running))
	admin := strings.Replace(running, "community_env: SNMP_COMMUNITY", "community_env: PACKETEER_ADMIN_PASSWORD", 1)
	const want = `telemetry/snmp: community_env "PACKETEER_ADMIN_PASSWORD" cannot be set through the config editor; use a name that starts with PACKETEER_SNMP_`
	if res := ed.Check([]byte(admin)); res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), want) {
		t.Fatalf("check: %+v", res)
	}
	if code, body := putConfig(t, h, admin, base); code != http.StatusUnprocessableEntity || !strings.Contains(strings.ReplaceAll(body, `\"`, `"`), want) {
		t.Fatalf("PUT = %d %s", code, body)
	}
	if b, _ := os.ReadFile(path); string(b) != running {
		t.Fatal("a refused env name was written")
	}
	alias := strings.Replace(strings.Replace(running, "- name: edge\n", "- name: &a PACKETEER_ADMIN_PASSWORD\n", 1),
		"community_env: SNMP_COMMUNITY", "community_env: *a", 1)
	alias = strings.Replace(alias, "host: edge,", "host: PACKETEER_ADMIN_PASSWORD,", 1)
	if res := ed.Check([]byte(alias)); res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), want) {
		t.Fatalf("the name behind an alias: %+v", res)
	}
	trap := running + "notifiers:\n  - type: snmptrap\n    config: {address: 192.0.2.40, version: 2c, community_env: SNMP_COMMUNITY}\n"
	if res := ed.Check([]byte(trap)); res.Valid || !strings.Contains(strings.Join(res.Errors, "\n"), `notifiers/snmptrap: community_env "SNMP_COMMUNITY"`) {
		t.Fatalf("the running name at another place: %+v", res)
	}
	for name, yaml := range map[string]string{
		"unchanged name": running + "hold_time: 20m\n",
		"prefixed name":  strings.Replace(running, "community_env: SNMP_COMMUNITY", "community_env: PACKETEER_SNMP_EDGE", 1),
		"trap prefix":    running + "notifiers:\n  - type: snmptrap\n    config: {address: 192.0.2.40, version: 2c, community_env: PACKETEER_TRAP_COMMUNITY}\n",
	} {
		if res := ed.Check([]byte(yaml)); !res.Valid {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if code, body := putConfig(t, h, running+"hold_time: 20m\n", base); code != http.StatusOK {
		t.Fatalf("unrelated change beside a name from the mounted file: PUT = %d %s", code, body)
	}
}

// checkEnvNames reads typed *_env fields and plugin keys at any depth, the
// places match the ones configedit lists, and a place with no prefix list
// takes only names the running config uses.
func TestCheckEnvNamesPlaces(t *testing.T) {
	parse := func(s string) *config.Config {
		t.Helper()
		c, err := config.Parse([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	running := parse(uiBase)
	feed := "external_policy:\n  enabled: false\n  listen: 192.0.2.10:9443\n  cert_file: /etc/packeteer/tls/feed.crt\n  key_file: /etc/packeteer/tls/feed.key\n"
	for text, want := range map[string]string{
		uiBase + feed + "  token_env: PACKETEER_ADMIN_PASSWORD\n": `external_policy: token_env "PACKETEER_ADMIN_PASSWORD"`,
		uiBase + feed + "  token_env: PACKETEER_POLICY_FEED\n":    "",
		uiBase + feed: "",
		uiBase + "exporters:\n  - type: kafka\n    config: {brokers: [192.0.2.50:9093], sasl: {username_env: PACKETEER_KAFKA_USER, password_env: PACKETEER_HTTP_PASSWORD}}\n": `exporters/kafka: password_env "PACKETEER_HTTP_PASSWORD"`,
		uiBase + "notifiers:\n  - type: smtp\n    config:\n      x: &m {password_env: PACKETEER_ADMIN_PASSWORD}\n      <<: *m\n":                                              `notifiers/smtp: password_env "PACKETEER_ADMIN_PASSWORD"`,
		uiBase + "notifiers:\n  - type: smtp\n    config: {? &k password_env : PACKETEER_SMTP_PASSWORD, *k : PACKETEER_ADMIN_PASSWORD}\n":                                     `notifiers/smtp: password_env "PACKETEER_ADMIN_PASSWORD"`,
		uiBase + "notifiers:\n  - type: smtp\n    config: {password_env: !!binary UEFDS0VURUVSX0FETUlOX1BBU1NXT1JE}\n":                                                        `notifiers/smtp: password_env "PACKETEER_ADMIN_PASSWORD"`,
		uiBase + "storage: {type: sqlite}\nauth:\n  enabled: true\n  sso:\n    type: oidc\n    config: {client_secret_env: PACKETEER_ADMIN_PASSWORD}\n":                       `auth.sso/oidc: client_secret_env "PACKETEER_ADMIN_PASSWORD"`,
		uiBase + "storage: {type: sqlite}\nauth:\n  enabled: true\n  sso:\n    type: oidc\n    config: {client_secret_env: PACKETEER_OIDC_CLIENT_SECRET}\n":                   "",
		uiBase + "probers:\n  - type: icmp\n    config: {token_env: PACKETEER_PROBE_TOKEN}\n":                                                                                 `probers/icmp: token_env "PACKETEER_PROBE_TOKEN" cannot be set through the config editor; use a name the running config already uses there`,
	} {
		err := checkEnvNames(running, parse(text))
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", text, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: err = %v, want %q", text, err, want)
		}
	}
	// threat_feeds needs a whole mitigation block to load, so the feed is
	// set on a parsed config.
	for name, want := range map[string]string{"PACKETEER_ADMIN_PASSWORD": `threat_feeds.feeds/http: token_env "PACKETEER_ADMIN_PASSWORD"`, "PACKETEER_FEED_TOKEN": ""} {
		next := parse(uiBase)
		var node yaml.Node
		if err := yaml.Unmarshal([]byte("{token_env: "+name+"}"), &node); err != nil {
			t.Fatal(err)
		}
		next.ThreatFeeds = &config.ThreatFeeds{Feeds: []config.PluginSpec{{Type: "http", Config: *node.Content[0]}}}
		if err := checkEnvNames(running, next); (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("feed %s: err = %v, want %q", name, err, want)
		}
	}
	legacy := parse(uiBase + "probers:\n  - type: icmp\n    config: {token_env: LEGACY_TOKEN}\n")
	if err := checkEnvNames(legacy, legacy); err != nil {
		t.Fatalf("the running config against itself: %v", err)
	}
}
