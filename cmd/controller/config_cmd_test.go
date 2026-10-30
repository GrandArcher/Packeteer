package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const netboxProviders = `{"count": 2, "next": null, "results": [
 {"name": "Transit A", "slug": "transit-a", "asns": [{"asn": 64496}],
  "custom_fields": {"packeteer_type": "transit", "packeteer_next_hop": "192.0.2.9", "packeteer_communities": "64496:100,64496:200"}},
 {"name": "Peer B", "slug": "peer-b", "asns": [{"asn": 64497}],
  "custom_fields": {"packeteer_type": "peer", "packeteer_source_ip": "192.0.2.13", "packeteer_next_hop": "192.0.2.3"}}
]}`

const configBase = `# lab edge
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    communities: ["64496:100"]
`

// inventoryLab serves a NetBox-shaped provider list and returns a config
// file that reads it.
func inventoryLab(t *testing.T, extra string) (path string, getenv func(string) string, hits *int) {
	t.Helper()
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Token lab-token" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(netboxProviders))
	}))
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	path = filepath.Join(dir, "config.yaml")
	body := configBase + "inventory:\n  type: netbox\n  config:\n    base_url: " + srv.URL + "\n    tag: packeteer\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PACKETEER_NETBOX_TOKEN": "lab-token"}
	return path, func(k string) string { return env[k] }, &n
}

func runCfg(t *testing.T, getenv func(string) string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), append([]string{"config"}, args...), getenv, &out, &errb)
	return code, out.String(), errb.String()
}

func planID(t *testing.T, out string) string {
	t.Helper()
	_, id, ok := strings.Cut(out, "plan id: ")
	if !ok {
		t.Fatalf("no plan id in %q", out)
	}
	return strings.TrimSpace(strings.SplitN(id, "\n", 2)[0])
}

func TestConfigPlanAndDiffWriteNothing(t *testing.T) {
	path, getenv, hits := inventoryLab(t, "")
	before, _ := os.ReadFile(path)
	code, out, errs := runCfg(t, getenv, "plan", "-config", path)
	if code != 0 {
		t.Fatalf("plan %d: %s", code, errs)
	}
	for _, want := range []string{"~ transit-a", "next_hop: 192.0.2.1 -> 192.0.2.9", "communities: 64496:100 -> 64496:100,64496:200", "+ peer-b", "plan id: "} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	code, diff, errs := runCfg(t, getenv, "diff", "-config", path)
	if code != 0 || !strings.Contains(diff, "+     next_hop: 192.0.2.9") || !strings.Contains(diff, "-     next_hop: 192.0.2.1") {
		t.Fatalf("diff %d %q %s", code, diff, errs)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || *hits != 2 {
		t.Fatalf("file changed %v, requests %d", !bytes.Equal(before, after), *hits)
	}
}

// The applied file is the file the plan described, and a second plan has
// nothing left to do.
func TestConfigApplyWritesWhatThePlanShowed(t *testing.T) {
	dbDir := t.TempDir()
	db := filepath.Join(dbDir, "pk.db")
	path, getenv, _ := inventoryLab(t, "storage:\n  type: sqlite\n  config:\n    path: "+db+"\n")
	_, planOut, _ := runCfg(t, getenv, "plan", "-config", path)
	id := planID(t, planOut)
	code, out, errs := runCfg(t, getenv, "apply", "-config", path, "-plan", id)
	if code != 0 {
		t.Fatalf("apply %d: %s %s", code, out, errs)
	}
	if !strings.Contains(out, "applied plan "+id) || !strings.Contains(out, "not committed") {
		t.Fatalf("apply output %q", out)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 2 || cfg.Providers[0].NextHop != "192.0.2.9" || len(cfg.Providers[0].Communities) != 2 || cfg.Providers[1].Name != "peer-b" || cfg.Providers[1].ASN != 64497 {
		t.Fatalf("providers %+v", cfg.Providers)
	}
	if cfg.Mode != config.ModeObserve {
		t.Fatalf("mode %s", cfg.Mode)
	}
	if body, _ := os.ReadFile(path); !strings.Contains(string(body), "# lab edge") {
		t.Fatal("comment lost")
	}
	code, out, _ = runCfg(t, getenv, "plan", "-config", path)
	if code != 0 || !strings.Contains(out, "the config already matches the inventory") {
		t.Fatalf("second plan %d %q", code, out)
	}
	code, out, _ = runCfg(t, getenv, "apply", "-config", path, "-plan", id)
	if code != 0 || !strings.Contains(out, "nothing to apply") {
		t.Fatalf("second apply %d %q", code, out)
	}

	// The change is in the audit log.
	st, err := plugin.Storages.New("sqlite", mustConfig(t, "path: "+db+"\n"), plugin.Env{Name: "sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer st.Stop(context.Background())
	recs, err := st.(plugin.AuditStore).Audit(context.Background(), plugin.AuditQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Action != "CLI config apply" || recs[0].Method != "system" || recs[0].Result != "ok" || recs[0].Target != "config.yaml" ||
		!strings.Contains(recs[0].Detail, "plan "+id) || !strings.Contains(recs[0].Detail, "+peer-b(") || !strings.Contains(recs[0].Detail, "~transit-a(") {
		t.Fatalf("audit %+v", recs)
	}
}

func mustConfig(t *testing.T, y string) plugin.Config {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigApplyRefusals(t *testing.T) {
	path, getenv, _ := inventoryLab(t, "")
	before, _ := os.ReadFile(path)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"no plan id":     {[]string{"apply", "-config", path}, "apply needs -plan ID"},
		"stale plan id":  {[]string{"apply", "-config", path, "-plan", "000000000000"}, "run plan again"},
		"unknown":        {[]string{"nope"}, "usage:"},
		"none":           {nil, "usage:"},
		"plan flag only": {[]string{"plan", "-plan", "x"}, "flag provided but not defined"},
	} {
		code, _, errs := runCfg(t, getenv, tc.args...)
		if code == 0 || !strings.Contains(errs, tc.want) {
			t.Errorf("%s: code %d err %q, want %q", name, code, errs, tc.want)
		}
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("a refused apply changed the file")
	}
}

func TestConfigNeedsAnInventoryAndAToken(t *testing.T) {
	path, getenv, _ := inventoryLab(t, "")
	bare := filepath.Join(t.TempDir(), "bare.yaml")
	if err := os.WriteFile(bare, []byte(configBase), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := runCfg(t, getenv, "plan", "-config", bare); code == 0 || !strings.Contains(errs, "no inventory block") {
		t.Fatalf("no inventory: %d %q", code, errs)
	}
	if code, _, errs := runCfg(t, func(string) string { return "" }, "plan", "-config", path); code == 0 || !strings.Contains(errs, "PACKETEER_NETBOX_TOKEN") {
		t.Fatalf("no token: %d %q", code, errs)
	}
}

func gitRepo(t *testing.T, path string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := filepath.Dir(path)
	for _, args := range [][]string{{"init", "-q"}, {"add", "config.yaml"}, {"-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "base"}} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
}

func gitOut(t *testing.T, path string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", filepath.Dir(path)}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestConfigApplyGitCommitsTheChange(t *testing.T) {
	path, getenv, _ := inventoryLab(t, "")
	gitRepo(t, path)
	_, planOut, _ := runCfg(t, getenv, "plan", "-config", path)
	id := planID(t, planOut)

	code, out, errs := runCfg(t, getenv, "apply", "-config", path, "-plan", id, "-git")
	if code != 0 {
		t.Fatalf("apply %d: %s %s", code, out, errs)
	}
	if strings.Contains(out, "not committed") {
		t.Fatalf("output %q", out)
	}
	if n := gitOut(t, path, "rev-list", "--count", "HEAD"); n != "2" {
		t.Fatalf("commits %s", n)
	}
	msg := gitOut(t, path, "log", "-1", "--format=%B")
	if !strings.HasPrefix(msg, "Apply inventory plan "+id) || !strings.Contains(msg, "+ peer-b") {
		t.Fatalf("message %q", msg)
	}
	if st := gitOut(t, path, "status", "--porcelain"); st != "" {
		t.Fatalf("tree not clean: %q", st)
	}
	if shown := gitOut(t, path, "show", "HEAD:config.yaml"); !strings.Contains(shown, "192.0.2.9") {
		t.Fatalf("commit lacks the change:\n%s", shown)
	}
}

func TestConfigApplyGitRefusesUncommittedEditsAndUntrackedFiles(t *testing.T) {
	path, getenv, _ := inventoryLab(t, "")
	_, planOut, _ := runCfg(t, getenv, "plan", "-config", path)
	id := planID(t, planOut)
	if code, _, errs := runCfg(t, getenv, "apply", "-config", path, "-plan", id, "-git"); code == 0 || !strings.Contains(errs, "tracked in a git repository") {
		t.Fatalf("not a repo: %d %q", code, errs)
	}

	gitRepo(t, path)
	edited := append([]byte("# manual edit\n"), mustRead(t, path)...)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	_, planOut, _ = runCfg(t, getenv, "plan", "-config", path)
	id = planID(t, planOut)
	if code, _, errs := runCfg(t, getenv, "apply", "-config", path, "-plan", id, "-git"); code == 0 || !strings.Contains(errs, "uncommitted changes") {
		t.Fatalf("dirty tree: %d %q", code, errs)
	}
	if !bytes.Equal(mustRead(t, path), edited) {
		t.Fatal("a refused apply changed the file")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A rejected commit puts the old file back.
func TestConfigApplyGitRestoresTheFileWhenTheCommitFails(t *testing.T) {
	path, getenv, _ := inventoryLab(t, "")
	gitRepo(t, path)
	hook := filepath.Join(filepath.Dir(path), ".git", "hooks", "pre-commit")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, path)
	_, planOut, _ := runCfg(t, getenv, "plan", "-config", path)
	code, _, errs := runCfg(t, getenv, "apply", "-config", path, "-plan", planID(t, planOut), "-git")
	if code == 0 || !strings.Contains(errs, "git commit") {
		t.Fatalf("code %d err %q", code, errs)
	}
	if !bytes.Equal(mustRead(t, path), before) {
		t.Fatal("the old file was not restored")
	}
	if st := gitOut(t, path, "status", "--porcelain"); st != "" {
		t.Fatalf("tree not clean: %q", st)
	}
}
