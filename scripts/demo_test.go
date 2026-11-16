package scripts

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// demo.sh runs against stand-ins for docker, uname and curl. The preflight
// must stop it with a one-line fix before "compose up" builds anything.

const demoFakeDocker = `#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
info)
	case "$3" in
	*OSType*) echo "${FAKE_OSTYPE:-linux}" ;;
	*OperatingSystem*) echo "${FAKE_OS:-Ubuntu 24.04 LTS}" ;;
	esac
	exit "${FAKE_INFO_RC:-0}" ;;
compose)
	case "$*" in
	"compose version") exit "${FAKE_COMPOSE_RC:-0}" ;;
	esac
	exit 0 ;;
ps) [ -n "${FAKE_RUNNING:-}" ] && echo 0123456789ab; exit 0 ;;
network)
	case "$2" in
	ls) [ -n "${FAKE_NETWORKS:-}" ] && echo net1; exit 0 ;;
	inspect) printf '%s\n' "${FAKE_NETWORKS:-}"; exit 0 ;;
	esac ;;
esac
`

const demoFakeUname = `#!/bin/sh
echo "${FAKE_UNAME:-Linux}"
`

func demoEnv(t *testing.T, skipDocker bool) (run func(extra ...string) (string, error), log func() string) {
	t.Helper()
	bin := t.TempDir()
	logf := filepath.Join(t.TempDir(), "log")
	for name, body := range map[string]string{"docker": demoFakeDocker, "uname": demoFakeUname, "curl": "#!/bin/sh\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"dirname", "head", "od", "tr", "seq", "sleep", "awk", "cat"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	if skipDocker {
		_ = os.Remove(filepath.Join(bin, "docker"))
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	run = func(extra ...string) (string, error) {
		cmd := exec.Command(bash, "demo.sh")
		cmd.Env = append([]string{"PATH=" + bin, "FAKE_LOG=" + logf}, extra...)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	log = func() string {
		b, _ := os.ReadFile(logf)
		return string(b)
	}
	return run, log
}

// port18080Free skips the test when something else already holds the demo
// port, because the free-port cases would then fail for the wrong reason.
func port18080Free(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Skipf("127.0.0.1:18080 is in use on this machine: %v", err)
	}
	_ = l.Close()
}

func TestDemoPreflightFailsFastWithOneLineFix(t *testing.T) {
	port18080Free(t)
	cases := []struct {
		name  string
		extra []string
		want  string
	}{
		{"git bash", []string{"FAKE_UNAME=MINGW64_NT-10.0-22631"}, "native Windows shell"},
		{"msys", []string{"FAKE_UNAME=MSYS_NT-10.0"}, "native Windows shell"},
		{"cygwin", []string{"FAKE_UNAME=CYGWIN_NT-10.0"}, "native Windows shell"},
		{"unknown os", []string{"FAKE_UNAME=FreeBSD"}, "FreeBSD is not supported"},
		{"windows containers", []string{"FAKE_OSTYPE=windows"}, "not running Linux containers"},
		{"daemon down", []string{"FAKE_INFO_RC=1"}, "cannot talk to the Docker daemon"},
		{"no compose plugin", []string{"FAKE_COMPOSE_RC=1"}, "Compose plugin is missing"},
		{"bridge in use", []string{"FAKE_NETWORKS=walkthrough_lab 192.0.2.0/24 "}, "walkthrough_lab already uses 192.0.2.0/24"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run, log := demoEnv(t, false)
			out, err := run(c.extra...)
			if err == nil {
				t.Fatalf("demo.sh succeeded; want a preflight failure\n%s", out)
			}
			if !strings.HasPrefix(out, "demo.sh: ") || !strings.Contains(out, c.want) || !strings.Contains(out, "Fix: ") {
				t.Errorf("output %q lacks %q or a Fix", out, c.want)
			}
			if n := strings.Count(strings.TrimSpace(out), "\n"); n != 0 {
				t.Errorf("want one line, got %d extra: %q", n, out)
			}
			if strings.Contains(log(), "up -d") {
				t.Errorf("compose up ran after a failed preflight:\n%s", log())
			}
		})
	}
}

func TestDemoPreflightNoDocker(t *testing.T) {
	run, _ := demoEnv(t, true)
	out, err := run()
	if err == nil || !strings.Contains(out, "docker is not installed") {
		t.Fatalf("err %v, output %q", err, out)
	}
}

func TestDemoPreflightPortInUse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		t.Skipf("127.0.0.1:18080 is in use on this machine: %v", err)
	}
	defer l.Close()
	run, log := demoEnv(t, false)
	out, err := run()
	if err == nil || !strings.Contains(out, "127.0.0.1:18080 is already in use. Fix: ") {
		t.Fatalf("err %v, output %q", err, out)
	}
	if strings.Contains(log(), "up -d") {
		t.Errorf("compose up ran with the port taken:\n%s", log())
	}
}

func TestDemoPreflightPassesOnACleanHost(t *testing.T) {
	port18080Free(t)
	run, log := demoEnv(t, false)
	out, err := run("FAKE_NETWORKS=bridge 172.17.0.0/16 ")
	if err != nil {
		t.Fatalf("demo.sh: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Packeteer demo is up (mode: observe; nothing is announced).") || !strings.Contains(log(), "up -d --build") {
		t.Errorf("the lab was not started:\n%s\n%s", out, log())
	}
	if strings.Contains(out, "note:") {
		t.Errorf("Docker Engine on Linux got a Docker Desktop note:\n%s", out)
	}
}

// Docker Desktop is allowed, on macOS and on Windows through WSL2 (where uname
// says Linux and the daemon says Docker Desktop), with a one-line note on
// stderr that it is not run in CI. The lab still starts.
func TestDemoPreflightAllowsDockerDesktopWithANote(t *testing.T) {
	port18080Free(t)
	cases := []struct {
		name  string
		extra []string
	}{
		{"macos", []string{"FAKE_UNAME=Darwin", "FAKE_OS=Docker Desktop"}},
		{"macos other daemon", []string{"FAKE_UNAME=Darwin"}},
		{"wsl2", []string{"FAKE_OS=Docker Desktop"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run, log := demoEnv(t, false)
			out, err := run(c.extra...)
			if err != nil {
				t.Fatalf("demo.sh: %v\n%s", err, out)
			}
			if n := strings.Count(out, "demo.sh: note: Docker Desktop and Docker on macOS are not run in CI"); n != 1 || !strings.Contains(out, "docs/demo.md#platforms") {
				t.Errorf("want one note naming docs/demo.md#platforms, got %d:\n%s", n, out)
			}
			if !strings.Contains(out, "Packeteer demo is up (mode: observe; nothing is announced).") || !strings.Contains(log(), "up -d --build") {
				t.Errorf("the lab was not started:\n%s\n%s", out, log())
			}
		})
	}
}

// A lab that is already up owns the port and the bridge; rerunning "up" is
// a no-op for compose and must not be reported as a clash.
func TestDemoPreflightAllowsARunningLab(t *testing.T) {
	run, log := demoEnv(t, false)
	out, err := run("FAKE_RUNNING=1", "FAKE_NETWORKS=lab_lab 192.0.2.0/24 ")
	if err != nil || !strings.Contains(log(), "up -d --build") {
		t.Fatalf("demo.sh: %v\n%s\n%s", err, out, log())
	}
}

// After a reboot or docker stop the demo's own network remains while its
// containers are gone; "up" restarts the lab and must not be called a clash.
func TestDemoPreflightAllowsItsOwnStoppedLab(t *testing.T) {
	port18080Free(t)
	run, log := demoEnv(t, false)
	out, err := run("FAKE_NETWORKS=packeteer-demo_lab 192.0.2.0/24 ")
	if err != nil || !strings.Contains(log(), "up -d --build") {
		t.Fatalf("demo.sh: %v\n%s\n%s", err, out, log())
	}
}
