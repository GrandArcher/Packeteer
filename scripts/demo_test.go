package scripts

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// demo.sh runs against stand-ins for docker, uname and curl. The preflight
// must stop it with a one-line fix before "compose up" builds anything.

const demoFakeDocker = `#!/bin/sh
echo "docker $*" >> "$FAKE_LOG"
case "$1" in
version)
	case "$3" in
	*Platform.Name*) echo "${FAKE_PLATFORM:-Docker Engine - Community}" ;;
	*Server.Version*) echo "27.2.0" ;;
	esac
	exit 0 ;;
info)
	case "$3" in
	*OSType*) echo "${FAKE_OSTYPE:-linux}" ;;
	*OperatingSystem*) echo "${FAKE_OS:-Ubuntu 24.04 LTS}" ;;
	esac
	exit "${FAKE_INFO_RC:-0}" ;;
compose)
	case "$*" in
	"compose version") exit "${FAKE_COMPOSE_RC:-0}" ;;
	"compose version --short") echo "2.29.2"; exit 0 ;;
	*" up "*) exit "${FAKE_UP_RC:-0}" ;;
	esac
	exit 0 ;;
ps)
	case "$2" in
	-aq) [ -n "${FAKE_LEFTOVER:-}" ] && echo 0123456789ab ;;
	*) [ -n "${FAKE_RUNNING:-}" ] && echo 0123456789ab ;;
	esac
	exit 0 ;;
port) echo "${FAKE_PORT:-127.0.0.1:18080}"; exit 0 ;;
exec)
	case "$*" in
	*"show bgp neighbors"*) [ -z "${FAKE_NO_IBGP:-}" ] && echo "  BGP state = Established, up for 00:01:02" ;;
	*"neighbors 192.0.2.10 routes"*) [ -n "${FAKE_EDGE_ROUTE:-}" ] && echo "*>i 198.51.100.0/24 192.0.2.10" ;;
	*"unicast 198.51.100.0/24"*) echo "  192.0.2.21 from 192.0.2.21 (192.0.2.21)" ;;
	esac
	exit 0 ;;
network)
	case "$2" in
	ls) [ -n "${FAKE_NETWORKS:-}" ] && echo net1; exit 0 ;;
	inspect) printf '%s\n' "${FAKE_NETWORKS:-}"; exit 0 ;;
	esac ;;
esac
`

const demoFakeUname = `#!/bin/sh
case "$1" in
-m) echo "${FAKE_ARCH:-x86_64}" ;;
-n) echo "secret-host.example.net" ;;
*) echo "${FAKE_UNAME:-Linux}" ;;
esac
`

// demoFakeCurl answers the dashboard API the way the demo lab does. It reads
// stdin when given -K, as curl does, so the script's printf never gets SIGPIPE.
const demoFakeCurl = `#!/bin/sh
url=""; w=""; o=""
while [ $# -gt 0 ]; do
	case "$1" in
	-K) cat >/dev/null ;;
	-w) w=1 ;;
	-o) o=1 ;;
	http*) url="$1" ;;
	esac
	shift
done
[ -n "$w" ] && { echo "${FAKE_UNAUTH_CODE:-401}"; exit 0; }
[ -n "$o" ] && exit 0
[ -n "${FAKE_AUTH_FAIL:-}" ] && exit 22
case "$url" in
*/api/overview) echo '{"mode":"observe"}' ;;
*/api/prefixes*) [ -z "${FAKE_NO_PREFIX:-}" ] && echo '{"prefixes":[{"prefix":"198.51.100.0/24","in_rib":true,"rib_provider":"transit-a","recommended":"transit-b"}]}' ;;
*/api/improvements) echo '{"improvements":[{"prefix":"198.51.100.0/24","provider":"transit-b"}]}' ;;
esac
exit 0
`

func demoEnv(t *testing.T, skipDocker bool) (run func(extra ...string) (string, error), log func() string) {
	run, _, log = demoEnvArgs(t, skipDocker)
	return run, log
}

// demoEnvArgs is demoEnv with a runner that takes arguments and keeps stdout
// apart from stderr.
func demoEnvArgs(t *testing.T, skipDocker bool) (run func(extra ...string) (string, error), runArgs func(args []string, extra ...string) (stdout, stderr string, err error), log func() string) {
	t.Helper()
	bin := t.TempDir()
	logf := filepath.Join(t.TempDir(), "log")
	for name, body := range map[string]string{"docker": demoFakeDocker, "uname": demoFakeUname, "curl": demoFakeCurl, "sleep": "#!/bin/sh\nexit 0\n", "sw_vers": "#!/bin/sh\necho \"${FAKE_MACOS:-14.6.1}\"\n"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"dirname", "head", "od", "tr", "seq", "awk", "cat", "sed", "cut", "grep"} {
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
	runArgs = func(args []string, extra ...string) (string, string, error) {
		cmd := exec.Command(bash, append([]string{"demo.sh"}, args...)...)
		cmd.Env = append([]string{"PATH=" + bin, "FAKE_LOG=" + logf}, extra...)
		var so, se strings.Builder
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		return so.String(), se.String(), err
	}
	log = func() string {
		b, _ := os.ReadFile(logf)
		return string(b)
	}
	return run, runArgs, log
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

func demoReport(t *testing.T, extra ...string) (stdout, stderr, dockerLog string, err error) {
	t.Helper()
	port18080Free(t)
	_, runArgs, log := demoEnvArgs(t, false)
	stdout, stderr, err = runArgs([]string{"--report"}, extra...)
	return stdout, stderr, log(), err
}

// A clean run prints every preflight and walkthrough check as passed, with the
// OS and Docker versions, and removes the lab at the end.
func TestDemoReportPassesOnACleanHost(t *testing.T) {
	out, errOut, log, err := demoReport(t, "FAKE_UNAME=Darwin", "FAKE_ARCH=arm64", "FAKE_PLATFORM=Docker Desktop 4.34.0 (165256)", "FAKE_OS=Docker Desktop")
	if err != nil {
		t.Fatalf("demo.sh --report: %v\n%s\n%s", err, out, errOut)
	}
	for _, want := range []string{
		"Packeteer demo report (scripts/demo.sh --report)\n",
		"OS: macOS 14.6.1 arm64\n",
		"Docker: Docker Desktop 4.34.0 (165256)\n",
		"Docker engine: 27.2.0\n",
		"Docker Compose: 2.29.2\n",
		"Docker Desktop: yes\n",
		"Result: passed (18 of 18 checks)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "  [pass] "); n != 18 || strings.Contains(out, "FAIL") || strings.Contains(out, "not run") {
		t.Errorf("want 18 passed checks and nothing else, got %d:\n%s", n, out)
	}
	if !strings.Contains(log, "up -d --build") || !strings.Contains(log, "down -v --remove-orphans") {
		t.Errorf("the lab was not started and removed:\n%s", log)
	}
}

func TestDemoReportOnLinuxEngineSaysNoDockerDesktop(t *testing.T) {
	out, _, _, err := demoReport(t)
	if err != nil || !strings.Contains(out, "Docker Desktop: no\n") || !strings.Contains(out, "Docker: Docker Engine - Community\n") {
		t.Fatalf("err %v:\n%s", err, out)
	}
}

// Each failure is named in the report, the later checks that cannot mean
// anything are "not run", and the exit status is not zero.
func TestDemoReportNamesEachFailure(t *testing.T) {
	cases := []struct {
		name  string
		extra []string
		fail  string
		up    bool
	}{
		{"windows shell", []string{"FAKE_UNAME=MINGW64_NT-10.0"}, "[FAIL] the shell is not a native Windows one", false},
		{"daemon down", []string{"FAKE_INFO_RC=1"}, "[FAIL] the Docker daemon answers", false},
		{"windows containers", []string{"FAKE_OSTYPE=windows"}, "[FAIL] Docker runs Linux containers", false},
		{"no compose", []string{"FAKE_COMPOSE_RC=1"}, "[FAIL] the Docker Compose plugin is present", false},
		{"lab already up", []string{"FAKE_RUNNING=1"}, "[FAIL] no demo lab is already running", false},
		{"bridge in use", []string{"FAKE_NETWORKS=other_lab 192.0.2.0/24 "}, "[FAIL] the lab bridge is free", false},
		{"build fails", []string{"FAKE_UP_RC=1"}, "[FAIL] the lab builds and starts", true},
		{"ibgp never comes up", []string{"FAKE_NO_IBGP=1"}, "[FAIL] the edge's iBGP session to Packeteer comes up", true},
		{"no prefix", []string{"FAKE_NO_PREFIX=1"}, "[FAIL] the learned prefix is in the RIB", true},
		{"api open without credentials", []string{"FAKE_UNAUTH_CODE=200"}, "[FAIL] the API refuses a request without credentials", true},
		{"sign-in refused", []string{"FAKE_AUTH_FAIL=1"}, "[FAIL] sign-in works and the mode is observe", true},
		{"route from packeteer", []string{"FAKE_EDGE_ROUTE=1"}, "[FAIL] the edge holds no route from Packeteer", true},
		{"published beyond loopback", []string{"FAKE_PORT=0.0.0.0:18080"}, "[FAIL] the dashboard is published on loopback only", true},
		{"leftover container", []string{"FAKE_LEFTOVER=1"}, "[FAIL] stop removes every container", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _, log, err := demoReport(t, c.extra...)
			if err == nil {
				t.Fatalf("demo.sh --report succeeded:\n%s", out)
			}
			if !strings.Contains(out, c.fail) || !strings.Contains(out, "Result: FAILED (") {
				t.Errorf("report lacks %q or a FAILED result:\n%s", c.fail, out)
			}
			if got := strings.Contains(log, "up -d --build"); got != c.up {
				t.Errorf("compose up ran = %v, want %v:\n%s", got, c.up, log)
			}
			if !c.up && !strings.Contains(out, "[not run] the lab builds and starts") {
				t.Errorf("the lab step is not marked not run:\n%s", out)
			}
			if c.up && !strings.Contains(log, "down -v --remove-orphans") {
				t.Errorf("a started lab was not removed:\n%s", log)
			}
		})
	}
}

// The block is pasted into a public issue. It holds no address, prefix, AS
// number, host name, or password, even when the host has them.
func TestDemoReportHasNoAddressesOrSecrets(t *testing.T) {
	const password = "fake-demo-pass-for-test"
	runs := map[string][]string{
		"pass":    {"PACKETEER_DEMO_PASSWORD=" + password},
		"fail":    {"PACKETEER_DEMO_PASSWORD=" + password, "FAKE_NO_PREFIX=1", "FAKE_EDGE_ROUTE=1", "FAKE_NETWORKS=other_lab 192.0.2.0/24 "},
		"verbose": {"PACKETEER_DEMO_PASSWORD=" + password, "FAKE_PLATFORM=Docker Desktop 4.34.0.12345 (165256) 10.1.2.3", "FAKE_MACOS=14.6.1.2"},
	}
	bad := []*regexp.Regexp{
		regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`),
		regexp.MustCompile(`/\d{1,3}\b`),
		regexp.MustCompile(`(?i)\bAS ?\d+`),
		regexp.MustCompile(`\b(64[45]\d\d|655\d\d|65[0-5]\d\d)\b`),
		regexp.MustCompile(`(?i)localhost|secret-host|example\.net|other_lab|[0-9a-f]{1,4}::`),
		regexp.MustCompile(`(?i)password|passwd|token|secret|` + regexp.QuoteMeta(password)),
	}
	for name, extra := range runs {
		t.Run(name, func(t *testing.T) {
			out, errOut, log, _ := demoReport(t, extra...)
			if strings.Contains(out+errOut+log, password) {
				t.Errorf("the password reached the output or the docker command lines")
			}
			for _, re := range bad {
				if m := re.FindString(out); m != "" {
					t.Errorf("report contains %q (%s):\n%s", m, re, out)
				}
			}
		})
	}
}

// A generated password is used for the run and never printed.
func TestDemoReportGeneratesAPasswordWithoutPrintingIt(t *testing.T) {
	out, errOut, _, err := demoReport(t)
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, errOut)
	}
	if strings.Contains(out+errOut, "password:") || regexp.MustCompile(`[0-9a-f]{36}`).MatchString(out+errOut) {
		t.Errorf("a password was printed:\n%s\n%s", out, errOut)
	}
}

func TestDemoReportRefusesAShortPassword(t *testing.T) {
	out, _, log, err := demoReport(t, "PACKETEER_DEMO_PASSWORD=short")
	if err == nil || out != "" || strings.Contains(log, "up -d") {
		t.Fatalf("err %v, stdout %q, log %q", err, out, log)
	}
}

func TestDemoUsageNamesReport(t *testing.T) {
	_, runArgs, _ := demoEnvArgs(t, false)
	_, errOut, err := runArgs([]string{"bogus"})
	if err == nil || !strings.Contains(errOut, "usage: scripts/demo.sh [up|stop|--report]") {
		t.Fatalf("err %v, stderr %q", err, errOut)
	}
}
