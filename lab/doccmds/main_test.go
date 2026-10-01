package main

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func parse(t *testing.T, doc string) []Step {
	t.Helper()
	steps, err := Parse(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	return steps
}

func TestParse(t *testing.T) {
	doc := "# Guide\n\n```sh\necho one\n```\n<!-- ci-expect: one -->\n\n<!-- ci-absent: two -->\n<!-- not a directive -->\n\n" +
		"```yaml\nmode: observe\n```\n\n````bash\necho ```\n````\n<!-- ci-retry: 30 -->\n\nText.\n\n```\nplain\n```\n\n" +
		"```sh\nfalse\n```\n<!-- ci-fails -->\n\n```sh\nrm -rf /\n```\n<!-- ci-skip: never run -->\n"
	steps := parse(t, doc)
	if len(steps) != 4 {
		t.Fatalf("got %d steps, want 4: %+v", len(steps), steps)
	}
	if s := steps[0]; s.Body != "echo one" || len(s.Expect) != 1 || s.Expect[0] != "one" || len(s.Absent) != 1 || s.Absent[0] != "two" || s.Line != 3 {
		t.Fatalf("step 1: %+v", s)
	}
	if s := steps[1]; s.Body != "echo ```" || s.Retry != 30 {
		t.Fatalf("step 2: %+v", s)
	}
	if !steps[2].Fails || steps[3].Skip != "never run" {
		t.Fatalf("steps 3, 4: %+v %+v", steps[2], steps[3])
	}
}

func TestParseErrors(t *testing.T) {
	for name, doc := range map[string]string{
		"directive before any block": "<!-- ci-expect: x -->\n",
		"directive after text":       "```sh\ntrue\n```\nText.\n<!-- ci-expect: x -->\n",
		"directive after yaml":       "```sh\ntrue\n```\n```yaml\na: 1\n```\n<!-- ci-expect: x -->\n",
		"unknown directive":          "```sh\ntrue\n```\n<!-- ci-expcet: x -->\n",
		"empty expect":               "```sh\ntrue\n```\n<!-- ci-expect: -->\n",
		"skip without reason":        "```sh\ntrue\n```\n<!-- ci-skip -->\n",
		"bad retry":                  "```sh\ntrue\n```\n<!-- ci-retry: soon -->\n",
		"retry too long":             "```sh\ntrue\n```\n<!-- ci-retry: 3600 -->\n",
		"fails with retry":           "```sh\ntrue\n```\n<!-- ci-fails -->\n<!-- ci-retry: 5 -->\n",
		"unterminated":               "```sh\ntrue\n",
	} {
		if _, err := Parse(strings.NewReader(doc)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func runDoc(t *testing.T, doc string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	var script bytes.Buffer
	if err := Script(&script, "test.md", parse(t, doc)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "run.sh")
	if err := os.WriteFile(path, script.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", path)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestScriptRuns(t *testing.T) {
	// State carries across steps; a retried step passes on its second
	// run; a ci-fails step must fail; a skipped step never runs.
	doc := "```sh\nmkdir -p sub && cd sub\nGREETING='it''s ok'\n```\n\n" +
		"```sh\necho \"$GREETING in $(basename \"$PWD\")\"\n```\n<!-- ci-expect: its ok in sub -->\n<!-- ci-absent: error -->\n\n" +
		"```sh\nn=$(cat count 2>/dev/null || echo 0); echo $((n + 1)) > count\ntest \"$(cat count)\" -ge 2\necho tries=$(cat count)\n```\n<!-- ci-retry: 20 -->\n<!-- ci-expect: tries=2 -->\n\n" +
		"```sh\necho broken >&2\nexit 3\n```\n<!-- ci-fails -->\n<!-- ci-expect: broken -->\n\n" +
		"```sh\nexit 1\n```\n<!-- ci-skip: shows a failure -->\n"
	out, err := runDoc(t, doc)
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	for _, want := range []string{"its ok in sub", "tries=2", "skipped: shows a failure", "all steps passed"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestScriptFails(t *testing.T) {
	for name, doc := range map[string]string{
		"command fails":      "```sh\necho first\nfalse\necho after\n```\n",
		"expectation missed": "```sh\necho hello\n```\n<!-- ci-expect: goodbye -->\n",
		"absent present":     "```sh\necho secret\n```\n<!-- ci-absent: secret -->\n",
		"ci-fails passes":    "```sh\ntrue\n```\n<!-- ci-fails -->\n",
		"retry never passes": "```sh\necho no\n```\n<!-- ci-retry: 1 -->\n<!-- ci-expect: yes -->\n",
		"later step fails":   "```sh\ntrue\n```\n\n```sh\nexit 4\n```\n",
	} {
		out, err := runDoc(t, doc)
		if err == nil {
			t.Errorf("%s: script passed:\n%s", name, out)
			continue
		}
		if !strings.Contains(out, "failed") || strings.Contains(out, "all steps passed") {
			t.Errorf("%s: output does not report the failure:\n%s", name, out)
		}
	}
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// guides are the pages CI runs, and where (workflow job) it runs them.
var guides = []string{"docs/quickstart.md", "docs/walkthrough.md", "docs/troubleshooting.md"}

func TestGuidesParseAndRunInCI(t *testing.T) {
	ci := repoFile(t, ".github/workflows/ci.yml")
	for _, g := range guides {
		steps, err := Parse(strings.NewReader(repoFile(t, g)))
		if err != nil {
			t.Fatalf("%s: %v", g, err)
		}
		if len(steps) < 5 {
			t.Errorf("%s: only %d shell steps", g, len(steps))
		}
		if !strings.Contains(ci, "lab/e2e-docs.sh "+g) {
			t.Errorf("%s: not run by .github/workflows/ci.yml", g)
		}
	}
}

func TestQuickstartRunsEveryCommandInObserve(t *testing.T) {
	steps, err := Parse(strings.NewReader(repoFile(t, "docs/quickstart.md")))
	if err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, s := range steps {
		if s.Skip != "" {
			t.Errorf("quickstart step at line %d is skipped (%s); every quickstart command runs in CI", s.Line, s.Skip)
		}
		all += s.Body + "\n"
	}
	for _, bad := range []string{"mode: inject", "mode: suggest", "docker kill", "docker pull", ":latest"} {
		if strings.Contains(all, bad) {
			t.Errorf("quickstart commands contain %q", bad)
		}
	}
	for _, want := range []string{"-check", "--network host", "--cap-add NET_RAW", "--cap-add NET_ADMIN", "docker stop -t 30", "docker compose stop -t 30"} {
		if !strings.Contains(all, want) {
			t.Errorf("quickstart commands lack %q", want)
		}
	}
}

// The FRR guide shows the lab edge's file verbatim, so CI runs the guide.
func TestFRRGuideIsTheLabConfig(t *testing.T) {
	doc := repoFile(t, "docs/frr.md")
	const marker = "<!-- lab-file: lab/frr-walkthrough/frr.conf -->\n```\n"
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatal("docs/frr.md has no lab-file block")
	}
	rest := doc[i+len(marker):]
	j := strings.Index(rest, "```\n")
	if j < 0 {
		t.Fatal("unterminated lab-file block")
	}
	if got, want := rest[:j], repoFile(t, "lab/frr-walkthrough/frr.conf"); got != want {
		t.Fatalf("docs/frr.md differs from lab/frr-walkthrough/frr.conf:\n--- guide\n%s\n--- lab\n%s", got, want)
	}
	compose := repoFile(t, "lab/docker-compose-walkthrough.yml")
	if !strings.Contains(compose, "./frr-walkthrough:/etc/frr") {
		t.Fatal("the walkthrough lab does not mount lab/frr-walkthrough")
	}
}

// The MikroTik guide's iBGP block is what the CHR lab (#52) applies.
func TestMikroTikGuideIsTheCHRLabConfig(t *testing.T) {
	doc := repoFile(t, "docs/mikrotik.md")
	const marker = "<!-- lab-file: lab/chr/edge.rsc (the block between its docs/mikrotik.md markers) -->\n```routeros\n"
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatal("docs/mikrotik.md has no lab-file block")
	}
	rest := doc[i+len(marker):]
	j := strings.Index(rest, "```\n")
	if j < 0 {
		t.Fatal("unterminated lab-file block")
	}
	rsc := repoFile(t, "lab/chr/edge.rsc")
	const begin, end = "# ---- begin docs/mikrotik.md (kept identical by lab/doccmds tests) ----\n", "# ---- end docs/mikrotik.md ----\n"
	b, e := strings.Index(rsc, begin), strings.Index(rsc, end)
	if b < 0 || e < b {
		t.Fatal("lab/chr/edge.rsc has no docs/mikrotik.md markers")
	}
	if got, want := rest[:j], rsc[b+len(begin):e]; got != want {
		t.Fatalf("docs/mikrotik.md differs from lab/chr/edge.rsc:\n--- guide\n%s\n--- lab\n%s", got, want)
	}
	if !strings.Contains(repoFile(t, "lab/e2e-chr.sh"), "lab/chr/edge.rsc") {
		t.Fatal("lab/e2e-chr.sh does not apply lab/chr/edge.rsc")
	}
}

// Shipped example configs stay observe.
func TestWalkthroughStartsInObserve(t *testing.T) {
	cfg := repoFile(t, "lab/packeteer-walkthrough.yaml")
	if !strings.Contains(cfg, "\nmode: observe\n") || strings.Contains(cfg, "mode: inject") || strings.Contains(cfg, "announcer:") {
		t.Fatal("lab/packeteer-walkthrough.yaml must start in observe with no announcer; the guide adds inject")
	}
}

var (
	ipv4Re = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Re = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`)
	asnRe  = regexp.MustCompile(`(?i)(?:remote-as|remote\.as=|peer-as|autonomous-system|router bgp|asn:|\bAS)\s*(\d+)`)
)

var docPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/32"),
	netip.MustParsePrefix("255.255.255.0/24"), // netmasks
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/128"),
}

func docASN(n uint64) bool {
	return (n >= 64496 && n <= 64511) || (n >= 64512 && n <= 65534) || (n >= 65536 && n <= 65551)
}

// The guides and lab files this issue added use documentation addresses
// and documentation or private ASNs only.
func TestGuidesUseDocumentationNumbers(t *testing.T) {
	files := []string{
		"docs/quickstart.md", "docs/walkthrough.md", "docs/troubleshooting.md",
		"docs/frr.md", "docs/junos.md", "docs/cisco.md", "docs/routers.md", "docs/mikrotik.md",
		"lab/frr-walkthrough/frr.conf", "lab/packeteer-walkthrough.yaml", "lab/docker-compose-walkthrough.yml",
		"lab/chr/edge.rsc", "lab/chr/packeteer.yaml", "lab/e2e-chr.sh",
	}
	for _, f := range files {
		sc := bufio.NewScanner(strings.NewReader(repoFile(t, f)))
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			for _, m := range ipv4Re.FindAllString(line, -1) {
				a, err := netip.ParseAddr(m)
				if err != nil {
					continue
				}
				if !allowed(a) {
					t.Errorf("%s:%d: %s is not a documentation or loopback address", f, n, m)
				}
			}
			for _, m := range ipv6Re.FindAllString(line, -1) {
				a, err := netip.ParseAddr(m)
				if err != nil || !a.Is6() {
					continue
				}
				if !allowed(a) {
					t.Errorf("%s:%d: %s is not a documentation or loopback address", f, n, m)
				}
			}
			for _, m := range asnRe.FindAllStringSubmatch(line, -1) {
				v, err := strconv.ParseUint(m[1], 10, 32)
				if err == nil && !docASN(v) {
					t.Errorf("%s:%d: AS %d is not a documentation or private ASN", f, n, v)
				}
			}
		}
	}
}

func allowed(a netip.Addr) bool {
	for _, p := range docPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
