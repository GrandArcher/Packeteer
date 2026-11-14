package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// The one-command demo (#586) ships observe with sign-in on and a prober
// that sends no packets, so a stranger's checkout never probes or announces.
func TestDemoConfigIsObserveWithSignIn(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "packeteer-demo.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "observe" || cfg.Announcer != nil {
		t.Fatalf("demo config: mode %q, announcer %v; want observe and none", cfg.Mode, cfg.Announcer)
	}
	if cfg.AuthOptedOut() {
		t.Fatal("demo config opts out of sign-in")
	}
	if len(cfg.Probers) != 1 || cfg.Probers[0].Type != "fixed" {
		t.Fatalf("demo probers %+v; want only the fixed prober", cfg.Probers)
	}
	if len(cfg.Providers) != 2 || len(cfg.BGP.Neighbors) != 1 {
		t.Fatalf("demo wants two providers and one iBGP neighbor, got %d and %d", len(cfg.Providers), len(cfg.BGP.Neighbors))
	}
	raw := repoFile(t, "lab/packeteer-demo.yaml")
	for _, bad := range []string{"mode: inject", "mode: suggest", "announcer:", "\nauth:"} {
		if strings.Contains(raw, bad) {
			t.Errorf("lab/packeteer-demo.yaml contains %q", bad)
		}
	}
}

func TestDemoComposeAndScripts(t *testing.T) {
	compose := repoFile(t, "lab/docker-compose-demo.yml")
	// The only admin password is the caller's variable: nothing committed.
	pw := regexp.MustCompile(`(?m)^\s*PACKETEER_ADMIN_PASSWORD:\s*(\S+)\s*$`).FindStringSubmatch(compose)
	if pw == nil || pw[1] != "${PACKETEER_DEMO_PASSWORD:-}" {
		t.Errorf("PACKETEER_ADMIN_PASSWORD must come from PACKETEER_DEMO_PASSWORD, got %v", pw)
	}
	if !strings.Contains(compose, `"127.0.0.1:18080:8080"`) {
		t.Error("the dashboard must be published on loopback only")
	}
	for _, want := range []string{
		"./packeteer-demo.yaml:/etc/packeteer/config.yaml:ro",
		"./frr-walkthrough:/etc/frr", "./frr-bmp-transit-a:/etc/frr", "./frr-bmp-transit-b:/etc/frr",
	} {
		if !strings.Contains(compose, want) {
			t.Errorf("compose lacks %q", want)
		}
	}
	if strings.Contains(compose, "mode: inject") || strings.Contains(compose, "network_mode: host") {
		t.Error("the demo compose file must not inject or use the host network")
	}
	for _, dir := range []string{"frr-walkthrough", "frr-bmp-transit-a", "frr-bmp-transit-b"} {
		if _, err := os.Stat(filepath.Join("..", dir, "frr.conf")); err != nil {
			t.Errorf("demo mounts %s: %v", dir, err)
		}
	}
	for _, s := range []string{"scripts/demo.sh", "lab/e2e-demo.sh"} {
		fi, err := os.Stat(filepath.Join("..", "..", s))
		if err != nil || fi.Mode()&0o111 == 0 {
			t.Errorf("%s must exist and be executable (%v)", s, err)
		}
	}
	if !strings.Contains(repoFile(t, ".github/workflows/ci.yml"), "bash lab/e2e-demo.sh") {
		t.Error("ci.yml does not run lab/e2e-demo.sh")
	}
	if !strings.Contains(repoFile(t, "lab/README.md"), "./scripts/demo.sh") {
		t.Error("lab/README.md does not point at ./scripts/demo.sh")
	}
	script := repoFile(t, "lab/e2e-demo.sh")
	for _, want := range []string{"/api/prefixes", "/api/improvements", `.mode == "observe"`, "neighbors 192.0.2.10 routes", "64512:666", "demo.sh stop"} {
		if !strings.Contains(script, want) {
			t.Errorf("lab/e2e-demo.sh does not check %q", want)
		}
	}
}

// The camera script (#590) runs the one-command demo and stays in observe:
// no mode change, no announcer, no committed or printed password, and only
// the clone is skipped in CI.
func TestDemoGuideStaysObserve(t *testing.T) {
	steps, err := Parse(strings.NewReader(repoFile(t, "docs/demo.md")))
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, s := range steps {
		if s.Skip != "" && !strings.Contains(s.Body, "git clone") {
			t.Errorf("demo step at line %d is skipped (%s); only the clone may be", s.Line, s.Skip)
		}
		all += s.Body + "\n"
	}
	for _, bad := range []string{"mode: inject", "mode: suggest", "sed ", "announcer", "echo \"$PACKETEER_DEMO_PASSWORD", "printenv", "admin:admin", "-u admin"} {
		if strings.Contains(all, bad) {
			t.Errorf("demo commands contain %q", bad)
		}
	}
	for _, want := range []string{"./scripts/demo.sh\n", "./scripts/demo.sh stop", "/api/overview", "/api/prefixes", "/api/improvements", "/api/blast", "neighbors 192.0.2.10 routes"} {
		if !strings.Contains(all, want) {
			t.Errorf("demo commands lack %q", want)
		}
	}
	var checks []string
	for _, s := range steps {
		checks = append(checks, s.Expect...)
		checks = append(checks, s.Absent...)
	}
	joined := strings.Join(checks, "\n")
	for _, want := range []string{`"mode":"observe"`, `"recommended":"transit-b"`, "64512:666", "198.51.100.0/24", `"code":"no_allowlist"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("demo checks lack %q", want)
		}
	}
}

// README points a clone at the demo, its script, the host install, and the
// inject walkthrough.
func TestReadmePointsAtDemo(t *testing.T) {
	readme := repoFile(t, "README.md")
	i := strings.Index(readme, "## Try the demo")
	j := strings.Index(readme, "## Install")
	if i < 0 || j < i {
		t.Fatal("README has no Try the demo section before Install")
	}
	section := readme[i:j]
	for _, want := range []string{"./scripts/demo.sh", "./scripts/demo.sh stop", "docs/demo.md", "docs/quickstart.md", "docs/walkthrough.md"} {
		if !strings.Contains(section, want) {
			t.Errorf("README demo section lacks %q", want)
		}
	}
	if strings.Contains(section, "mode: inject") {
		t.Error("README demo section shows inject")
	}
}
