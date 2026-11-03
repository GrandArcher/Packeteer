// Package doccheck holds tests that keep release-facing documents agreeing
// with each other: the feature counts and the pinned image version.
package doccheck

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func read(t *testing.T, rel ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", ".."}, rel...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type count struct{ rows, done int }

var milestoneCell = regexp.MustCompile(`^v0\.\d+(, v0\.\d+)*$`)

// tableCounts counts the capability rows of docs/FEATURES.md by the first
// milestone of each row, the rule the Summary section states.
func tableCounts(t *testing.T, features string) map[string]count {
	t.Helper()
	got := map[string]count{}
	for _, line := range strings.Split(features, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 7 || strings.TrimSpace(cells[0]) != "" {
			continue
		}
		status := strings.TrimSpace(cells[2])
		ms := strings.TrimSpace(cells[3])
		key := ""
		switch {
		case strings.HasPrefix(status, "won't do"):
			key = "won't do"
		case milestoneCell.MatchString(ms):
			key = strings.Split(ms, ",")[0]
		default:
			continue
		}
		c := got[key]
		c.rows++
		if strings.HasPrefix(status, "done") {
			c.done++
		}
		got[key] = c
	}
	return got
}

// summaryCounts reads "| v0.N | rows | done |" lines from one section of a
// document, from the heading to the next "## " heading.
func summaryCounts(t *testing.T, doc, heading string) map[string]count {
	t.Helper()
	i := strings.Index(doc, heading)
	if i < 0 {
		t.Fatalf("heading %q not found", heading)
	}
	section := doc[i+len(heading):]
	if j := strings.Index(section, "\n## "); j >= 0 {
		section = section[:j]
	}
	row := regexp.MustCompile(`(?m)^\| (v0\.\d+|won't do) \| (\d+) \| (\d+|-) \|$`)
	got := map[string]count{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		var c count
		c.rows = atoi(t, m[2])
		if m[3] != "-" {
			c.done = atoi(t, m[3])
		}
		got[m[1]] = c
	}
	if len(got) == 0 {
		t.Fatalf("no count rows under %q", heading)
	}
	return got
}

func atoi(t *testing.T, s string) int {
	t.Helper()
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

func TestFeatureCountsMatchTable(t *testing.T) {
	features := read(t, "docs", "FEATURES.md")
	table := tableCounts(t, features)
	if table["v0.9"].rows == 0 {
		t.Fatalf("no v0.9 rows parsed: %v", table)
	}
	for name, doc := range map[string]map[string]count{
		"docs/FEATURES.md Summary": summaryCounts(t, features, "## Summary"),
		"README.md Features":       summaryCounts(t, read(t, "README.md"), "## Features"),
	} {
		for ms, want := range table {
			if doc[ms] != want {
				t.Errorf("%s: %s is %+v, the table has %+v", name, ms, doc[ms], want)
			}
		}
		for ms := range doc {
			if _, ok := table[ms]; !ok && ms != "total" {
				t.Errorf("%s: %s has no rows in the table", name, ms)
			}
		}
	}
}

var imagePin = regexp.MustCompile(`ghcr\.io/grandarcher/packeteer:(\d+\.\d+\.\d+)`)

// TestImagePinsAreLastRelease keeps every documented pin on the newest dated
// CHANGELOG release, so a pin never names a tag that does not exist yet.
func TestImagePinsAreLastRelease(t *testing.T) {
	m := regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$`).FindStringSubmatch(read(t, "CHANGELOG.md"))
	if m == nil {
		t.Fatal("no dated release in CHANGELOG.md")
	}
	last := m[1]
	for _, f := range []string{"README.md", "docker-compose.yml", filepath.Join("docs", "quickstart.md")} {
		pins := imagePin.FindAllStringSubmatch(read(t, f), -1)
		if len(pins) == 0 {
			t.Errorf("%s has no pinned image", f)
		}
		for _, p := range pins {
			if p[1] != last {
				t.Errorf("%s pins %s, the last release is %s", f, p[1], last)
			}
		}
	}
}

var relLink = regexp.MustCompile(`\]\(([^)\s#:]+)(#[^)\s]*)?\)`)

// TestReadmeLinksExist fails on a README link or screenshot whose file is
// gone, so a renamed doc or image cannot ship as a dead link.
func TestReadmeLinksExist(t *testing.T) {
	links := relLink.FindAllStringSubmatch(read(t, "README.md"), -1)
	if len(links) < 20 {
		t.Fatalf("only %d relative links found", len(links))
	}
	for _, m := range links {
		if _, err := os.Stat(filepath.Join("..", "..", m[1])); err != nil {
			t.Errorf("README.md links %s: %v", m[1], err)
		}
	}
}
