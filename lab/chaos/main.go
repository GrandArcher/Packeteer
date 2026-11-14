// Command chaos is the lab chaos soak (#585). Against the HA lab
// (lab/docker-compose-ha.yml: one FRR edge, pk-a and pk-b on one lease) it
// flaps the active instance's BGP session, fails transit-b's probe source,
// and stops the active instance with SIGTERM and SIGKILL, in the order
// the profile lists, until the profile's window is over. Every sample of
// the edge checks the safety invariants (check.go) on the router, not on
// Packeteer's view. It writes chaos-result.json and chaos-summary.md to
// -out and exits 1 when an invariant broke or the lab did not recover.
//
//	chaos -profile lab/chaos/short.yaml -lab-dir DIR -out chaos-out
//
// lab/e2e-chaos.sh brings the lab up and runs it from the repository
// root; DIR is the probe directory the lab mounts.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// example is the shipped example config, which must stay observe.
const example = "config.example.yaml"

func main() {
	log.SetFlags(log.Ltime)
	log.SetPrefix("chaos: ")
	profile := flag.String("profile", "lab/chaos/short.yaml", "chaos profile")
	labDir := flag.String("lab-dir", "", "probe directory the lab mounts (PACKETEER_LAB_DIR)")
	out := flag.String("out", "chaos-out", "directory for chaos-result.json and chaos-summary.md")
	flag.Parse()
	if *labDir == "" {
		log.Fatal("-lab-dir is required")
	}
	prof, err := loadProfile(*profile)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("profile %s: %v, faults %v", prof.Name, prof.Duration, prof.Faults)
	rep := newRunner(compose{labDir: *labDir}, wallClock{}, prof, example).run(ctx)
	if err := rep.write(*out); err != nil {
		log.Fatal(err)
	}
	fmt.Print(rep.markdown())
	if !rep.Pass {
		os.Exit(1)
	}
}

// compose drives the lab with docker compose. The compose files come from
// COMPOSE_FILE, which lab/e2e-chaos.sh sets.
type compose struct {
	labDir string
}

func (c compose) run(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return "", fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func vtyshArgs(cmds []string) []string {
	args := []string{"compose", "exec", "-T", "edge", "vtysh"}
	for _, c := range cmds {
		args = append(args, "-c", c)
	}
	return args
}

func (c compose) Edge(ctx context.Context) (string, error) {
	return c.run(ctx, 10*time.Second, vtyshArgs(edgeCommands)...)
}

func (c compose) Vtysh(ctx context.Context, cmds ...string) error {
	_, err := c.run(ctx, 10*time.Second, vtyshArgs(cmds)...)
	return err
}

func (c compose) Signal(ctx context.Context, svc, sig string) error {
	_, err := c.run(ctx, 10*time.Second, "compose", "kill", "-s", sig, svc)
	return err
}

func (c compose) Wait(ctx context.Context, svc string) (int, error) {
	id, err := c.run(ctx, 10*time.Second, "compose", "ps", "-a", "-q", svc)
	if err != nil {
		return 0, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, fmt.Errorf("%s has no container", svc)
	}
	// Packeteer's own shutdown is bounded at 10s; the rest is margin.
	code, err := c.run(ctx, time.Minute, "wait", id)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(code))
}

func (c compose) Start(ctx context.Context, svc string) error {
	_, err := c.run(ctx, time.Minute, "compose", "start", svc)
	return err
}

// Probes replaces state.yaml in the lab directory in one rename, so the
// fixed prober never reads half a file.
func (c compose) Probes(file string) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	tmp := filepath.Join(c.labDir, ".state.yaml.tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(c.labDir, "state.yaml"))
}

// The lab-only basic-auth account from lab/docker-compose-ha.yml.
const (
	labUser = "lab"
	labPass = "lab-only"
)

var httpClient = &http.Client{Timeout: 2 * time.Second}

func (c compose) HA(ctx context.Context, in instance) (HAStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+in.Addr+":8080/api/ha", nil)
	if err != nil {
		return HAStatus{}, err
	}
	req.SetBasicAuth(labUser, labPass)
	resp, err := httpClient.Do(req)
	if err != nil {
		return HAStatus{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return HAStatus{}, fmt.Errorf("%s /api/ha: %s", in.ID, resp.Status)
	}
	var st HAStatus
	err = json.NewDecoder(resp.Body).Decode(&st)
	return st, err
}
