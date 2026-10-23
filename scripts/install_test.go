package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The installer runs against stand-ins for docker and curl, so the test
// needs no daemon and no network. It checks what the script asks Docker to
// do, and that it stops where it must.

const fakeDocker = `#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
info) exit "${FAKE_INFO_RC:-0}" ;;
ps) [ -n "${FAKE_EXISTING:-}" ] && echo packeteer; exit 0 ;;
run)
	case "$*" in
	*" -check") exit "${FAKE_CHECK_RC:-0}" ;;
	esac
	echo 0123456789ab
	exit 0 ;;
logs) echo 'level=WARN msg="auth: first run: generated admin password; sign in with it, then choose a new one" user=admin password=fake-generated-password' ;;
esac
`

const fakeCurl = `#!/bin/sh
echo "curl $*" >> "$FAKE_LOG"
case "$*" in
*healthz*) exit "${FAKE_HEALTH_RC:-0}" ;;
esac
out=
for a in "$@"; do
	if [ "$prev" = "-fsSLo" ]; then out=$a; fi
	prev=$a
done
cp "$FAKE_EXAMPLE" "$out"
`

type env struct {
	bin, log, dir string
}

func newEnv(t *testing.T, tools ...string) *env {
	t.Helper()
	e := &env{bin: t.TempDir(), dir: filepath.Join(t.TempDir(), "pk")}
	e.log = filepath.Join(t.TempDir(), "log")
	for name, body := range map[string]string{"docker": fakeDocker, "curl": fakeCurl} {
		if err := os.WriteFile(filepath.Join(e.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"uname", "mkdir", "grep", "sleep", "cp", "cat"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(e.bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range tools {
		_ = os.Remove(filepath.Join(e.bin, name))
	}
	return e
}

func (e *env) run(t *testing.T, extra ...string) (string, string, error) {
	t.Helper()
	example, err := filepath.Abs("../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "install.sh")
	cmd.Env = append([]string{"PATH=" + e.bin, "HOME=" + t.TempDir(), "FAKE_LOG=" + e.log, "FAKE_EXAMPLE=" + example,
		"PACKETEER_DIR=" + e.dir}, extra...)
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func (e *env) calls(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(e.log)
	return string(b)
}

func TestInstallBringsUpObserveAndPointsAtTheWizard(t *testing.T) {
	e := newEnv(t)
	out, errOut, err := e.run(t)
	if err != nil {
		t.Fatalf("install: %v\n%s\n%s", err, out, errOut)
	}
	cfg, err := os.ReadFile(filepath.Join(e.dir, "config.yaml"))
	if err != nil || !strings.Contains(string(cfg), "mode: observe") || strings.Contains(string(cfg), "\nmode: inject") {
		t.Fatalf("config.yaml: %v\n%s", err, cfg)
	}
	if st, err := os.Stat(filepath.Join(e.dir, "plugins")); err != nil || !st.IsDir() {
		t.Fatalf("plugins dir: %v", err)
	}
	calls := e.calls(t)
	check := strings.Index(calls, "-check")
	start := strings.Index(calls, "docker run -d --name packeteer --network host --cap-add NET_RAW --cap-add NET_ADMIN --restart unless-stopped")
	if check < 0 || start < 0 || check > start {
		t.Fatalf("the config must pass -check before the container starts:\n%s", calls)
	}
	for _, want := range []string{
		"curl -fsSLo " + e.dir + "/config.yaml https://raw.githubusercontent.com/GrandArcher/Packeteer/main/config.example.yaml",
		"-v " + e.dir + "/config.yaml:/etc/packeteer/config.yaml -v ", // writable: the wizard saves
		"-v packeteer-data:/var/lib/packeteer ghcr.io/grandarcher/packeteer:edge",
		"docker logs packeteer",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("calls lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "config.yaml:/etc/packeteer/config.yaml:ro -v") {
		t.Errorf("the running container's config is read-only, so the wizard cannot save:\n%s", calls)
	}
	for _, want := range []string{"observe mode. It announces nothing.", "http://127.0.0.1:8080/settings.html#wizard", "fake-generated-password", "docker stop -t 30 packeteer"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestInstallPinsAReleaseAndPassesTheAdminPasswordByName(t *testing.T) {
	e := newEnv(t)
	out, errOut, err := e.run(t, "PACKETEER_VERSION=0.8.0", "PACKETEER_ADMIN_PASSWORD=chosen-by-the-operator")
	if err != nil {
		t.Fatalf("install: %v\n%s\n%s", err, out, errOut)
	}
	calls := e.calls(t)
	for _, want := range []string{"/Packeteer/v0.8.0/config.example.yaml", " -e PACKETEER_ADMIN_PASSWORD ghcr.io/grandarcher/packeteer:0.8.0"} {
		if !strings.Contains(calls, want) {
			t.Errorf("calls lack %q:\n%s", want, calls)
		}
	}
	if strings.Contains(calls, "chosen-by-the-operator") || strings.Contains(out, "chosen-by-the-operator") || strings.Contains(out, "fake-generated-password") {
		t.Errorf("the password is on a command line or in the output:\n%s\n%s", calls, out)
	}
}

func TestInstallKeepsAnExistingConfig(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mine := "mode: inject\n# mine\n"
	if err := os.WriteFile(filepath.Join(e.dir, "config.yaml"), []byte(mine), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, err := e.run(t)
	if err != nil {
		t.Fatalf("install: %v\n%s", err, errOut)
	}
	if strings.Contains(out, "announces nothing") || !strings.Contains(out, "your existing config") {
		t.Errorf("claims observe mode for a kept config:\n%s", out)
	}
	if got, _ := os.ReadFile(filepath.Join(e.dir, "config.yaml")); string(got) != mine {
		t.Fatalf("config.yaml was replaced:\n%s", got)
	}
	if strings.Contains(e.calls(t), "curl -fsSLo") {
		t.Error("downloaded a config over an existing one")
	}
}

func TestInstallStopsBeforeStartingWhenSomethingIsWrong(t *testing.T) {
	cases := []struct {
		name  string
		env   []string
		tools []string
		want  string
	}{
		{"no docker", nil, []string{"docker"}, "Docker is required"},
		{"no curl", nil, []string{"curl"}, "curl is required"},
		{"daemon down", []string{"FAKE_INFO_RC=1"}, nil, "cannot talk to the Docker daemon"},
		{"container exists", []string{"FAKE_EXISTING=1"}, nil, "a container named packeteer exists"},
		{"config fails check", []string{"FAKE_CHECK_RC=1"}, nil, "did not pass -check"},
		{"never answers", []string{"FAKE_HEALTH_RC=1"}, nil, "did not answer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, c.tools...)
			if c.name == "never answers" {
				// A sleep that returns at once keeps the wait loop quick.
				sleep := filepath.Join(e.bin, "sleep")
				if err := os.Remove(sleep); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(sleep, []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			_, errOut, err := e.run(t, c.env...)
			if err == nil || !strings.Contains(errOut, c.want) {
				t.Fatalf("err = %v, stderr = %q, want %q", err, errOut, c.want)
			}
			if c.name != "never answers" && strings.Contains(e.calls(t), "docker run -d") {
				t.Errorf("started the container anyway:\n%s", e.calls(t))
			}
		})
	}
}
