// Package failurematrix holds the tests that keep the failure-mode matrix
// (lab/e2e-failure-matrix.sh, #234) whole: every injection surface answers
// every failure, and the CI job runs every surface.
package failurematrix

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", path))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// failures is the FAILURES list of the harness.
func failures(t *testing.T) []string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^FAILURES=\(([^)]*)\)$`).FindStringSubmatch(read(t, "lab/e2e-failure-matrix.sh"))
	if m == nil {
		t.Fatal("harness has no FAILURES list")
	}
	return strings.Fields(m[1])
}

func surfaces(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.sh")
	if err != nil || len(files) == 0 {
		t.Fatalf("no surface files: %v", err)
	}
	var out []string
	for _, f := range files {
		out = append(out, strings.TrimSuffix(f, ".sh"))
	}
	return out
}

func has(src, pattern string) bool {
	return regexp.MustCompile(`(?m)` + pattern).MatchString(src)
}

func TestEverySurfaceAnswersEveryFailure(t *testing.T) {
	all := failures(t)
	if len(all) != 6 {
		t.Fatalf("FAILURES = %v; the issue asks for six", all)
	}
	for _, s := range surfaces(t) {
		src := read(t, "lab/failure-matrix/"+s+".sh")
		for _, f := range all {
			id := strings.ReplaceAll(f, "-", "_")
			isCase := has(src, `^case_`+id+`\(\) *\{`)
			isNA := has(src, `^na_`+id+`="[^"]{20,}"`)
			if isCase == isNA {
				t.Errorf("%s: %s must have exactly one of case_%s() and na_%s=\"why\" (case %v, n/a %v)", s, f, id, id, isCase, isNA)
			}
		}
		// The withdraw paths every surface has; none of them can be n/a.
		for _, f := range []string{"sigkill", "session_loss", "reload_observe"} {
			if !has(src, `^case_`+f+`\(\)`) {
				t.Errorf("%s: case_%s is required", s, f)
			}
		}
	}
}

func TestSurfaceFilesAreComplete(t *testing.T) {
	for _, s := range surfaces(t) {
		src := read(t, "lab/failure-matrix/"+s+".sh")
		for _, v := range []string{"COMPOSE", "ROUTERS", "SVCS", "ACTIVE", "ACTIVE_TAG", "HOLD_FILE", "EVER", "MAX_ROUTES"} {
			if !has(src, `^`+v+`=`) {
				t.Errorf("%s: %s is not set", s, v)
			}
		}
		for _, fn := range []string{"surface_routes", "surface_seed", "surface_baseline"} {
			if !has(src, `^`+fn+`\(\)`) {
				t.Errorf("%s: %s() is not defined", s, fn)
			}
		}
		compose := regexp.MustCompile(`(?m)^COMPOSE=\(([^)]*)\)`).FindStringSubmatch(src)
		if compose == nil {
			continue
		}
		files := strings.Fields(compose[1])
		files = append(files, regexp.MustCompile(`(?m)^HOLD_FILE=(\S+)`).FindStringSubmatch(src)[1])
		for _, f := range files {
			if _, err := os.Stat(filepath.Join("..", "..", f)); err != nil {
				t.Errorf("%s: %v", s, err)
			}
		}
	}
}

func TestScriptsParse(t *testing.T) {
	scripts := []string{"../e2e-failure-matrix.sh"}
	for _, s := range surfaces(t) {
		scripts = append(scripts, s+".sh")
	}
	for _, f := range scripts {
		if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
			t.Errorf("bash -n %s: %v\n%s", f, err, out)
		}
	}
}

func TestHarnessRefusesUnknownSurfaceAndFailure(t *testing.T) {
	out, err := exec.Command("bash", "../e2e-failure-matrix.sh", "no-such-surface").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "usage:") {
		t.Fatalf("unknown surface: err %v, output %q", err, out)
	}
	for _, s := range surfaces(t) {
		if !strings.Contains(string(out), s) {
			t.Errorf("usage does not list the %s surface: %q", s, out)
		}
	}
	out, err = exec.Command("bash", "../e2e-failure-matrix.sh", surfaces(t)[0], "no-such-failure").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "unknown failure") {
		t.Fatalf("unknown failure: err %v, output %q", err, out)
	}
}

// The CI job runs every surface, and the broken-withdraw-path step proves
// the matrix fails when a withdraw path does not fire.
func TestCIRunsEverySurface(t *testing.T) {
	var wf struct {
		Jobs map[string]struct {
			Strategy struct {
				Matrix struct {
					Surface []string `yaml:"surface"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(read(t, ".github/workflows/ci.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	job, ok := wf.Jobs["failure-matrix"]
	if !ok {
		t.Fatal("ci.yml has no failure-matrix job")
	}
	want := surfaces(t)
	got := slices.Clone(job.Strategy.Matrix.Surface)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("failure-matrix runs %v, the surface files are %v", got, want)
	}
	var runs, broken bool
	for _, s := range job.Steps {
		runs = runs || strings.Contains(s.Run, "lab/e2e-failure-matrix.sh ${{ matrix.surface }}")
		broken = broken || (strings.Contains(s.Run, "MATRIX_BREAK=") && strings.Contains(s.Run, "still on the router"))
	}
	if !runs || !broken {
		t.Fatalf("failure-matrix job: runs the matrix %v, checks a broken withdraw path fails %v", runs, broken)
	}
}
