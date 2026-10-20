package httpapi

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// nodeOrSkip finds Node. The CI test job installs it; a local run without it
// skips rather than failing make test.
func nodeOrSkip(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the settings form")
		}
		t.Skip("node not installed")
	}
	return node
}

// TestSettingsFormInputs runs the settings form in Node against settings.html.
// Those checks live in the page script.
func TestSettingsFormInputs(t *testing.T) {
	out, err := exec.Command(nodeOrSkip(t), "settings_form_test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("settings form: %v\n%s", err, out)
	}
}

const wizardSmokeYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
hold_time: 30m
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
  - name: transit-c
    source_ip: 192.0.2.13
    next_hop: 192.0.2.3
bgp:
  neighbors:
    - address: 192.0.2.254
auth:
  enabled: true
http:
  listen: 127.0.0.1:8080
  config_editor: true
storage:
  type: sqlite
  config:
    path: /data/history.db
`

// TestWizardUISmoke (#345) drives the real settings page in Node against the
// real handler: a three-provider config with sign-in on, the wizard run with
// one provider with an ASN, a type, and an IPv6 pair. The page must collapse the wizard, show the diff and the
// loss, leave the editor alone until the operator confirms, and keep auth
// on afterwards.
func TestWizardUISmoke(t *testing.T) {
	node := nodeOrSkip(t)
	e := newUI(t)
	if err := os.WriteFile(e.path, []byte(wizardSmokeYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	outFile := filepath.Join(t.TempDir(), "editor.yaml")
	cmd := exec.Command(node, "settings_form_test.js")
	cmd.Env = append(os.Environ(), "PACKETEER_URL="+srv.URL, "PACKETEER_TOKEN="+e.tokens[plugin.RoleAdmin], "PACKETEER_OUT="+outFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("wizard smoke: %v\n%s", err, out)
	}
	got, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(got)
	if err != nil {
		t.Fatalf("editor text after the wizard: %v\n%s", err, got)
	}
	if !cfg.AuthEnabled() || len(cfg.Providers) != 2 || cfg.Providers[0].ASN != 64496 || cfg.Providers[0].Type != "transit" || cfg.Providers[1].Name != "transit-a-v6" || cfg.Mode != config.ModeObserve {
		t.Fatalf("after the wizard: auth=%v providers=%+v mode=%s", cfg.AuthEnabled(), cfg.Providers, cfg.Mode)
	}
	if res := e.srv.editor.Check(got); !res.Valid {
		t.Fatalf("the editor refuses the result: %v", res.Errors)
	}
	if disk, _ := os.ReadFile(e.path); strings.TrimSpace(string(disk)) != strings.TrimSpace(wizardSmokeYAML) {
		t.Fatal("the wizard wrote the file")
	}
}

// TestWizardFreshUISmoke (#350) drives the real settings page against a
// config with no setup: the wizard is open, its fields and the provider row
// are empty with no placeholder, and the examples are in the help lines.
func TestWizardFreshUISmoke(t *testing.T) {
	node := nodeOrSkip(t)
	e := newUI(t)
	if err := os.WriteFile(e.path, []byte("mode: observe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	cmd := exec.Command(node, "settings_form_test.js")
	cmd.Env = append(os.Environ(), "PACKETEER_URL="+srv.URL, "PACKETEER_TOKEN="+e.tokens[plugin.RoleAdmin], "PACKETEER_CASE=fresh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh wizard smoke: %v\n%s", err, out)
	}
}
