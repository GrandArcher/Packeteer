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
