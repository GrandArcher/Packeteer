package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
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
	ed, err := newConfigEditor(cfg, path, func(string) string { return "" }, "ops")
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
	if !res.RestartRequired || !res.ReloadOnline || strings.Join(res.Changed, ",") != "bgp.neighbors,hold_time" {
		t.Fatalf("result = %+v", res)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestConfigEditorOffByDefault(t *testing.T) {
	cfg, err := config.Parse([]byte(strings.Replace(uiBase, "  config_editor: true\n", "  config_editor: false\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if ed, err := newConfigEditor(cfg, "/nonexistent", nil, ""); ed != nil || err != nil {
		t.Fatalf("editor built while off: %v %v", ed, err)
	}
}
