// Package doccheck holds tests that keep release-facing documents agreeing
// with each other: the feature counts and the pinned image version.
package doccheck

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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

var milestoneCell = regexp.MustCompile(`^v\d+\.\d+(, v\d+\.\d+)*$`)

// tableCounts counts the capability rows of docs/FEATURES.md by the first
// milestone of each row, the rule the Summary section states. It also counts
// rows by status. A row it cannot place fails the test, so a malformed row
// cannot drop out of the counts.
func tableCounts(t *testing.T, features string) (map[string]count, map[string]int) {
	t.Helper()
	byMilestone := map[string]count{}
	byStatus := map[string]int{}
	for _, line := range strings.Split(features, "\n") {
		// A literal pipe inside a cell is written \| and is not a separator.
		cells := strings.Split(strings.ReplaceAll(line, `\|`, "\x00"), "|")
		if len(cells) < 7 || strings.TrimSpace(cells[0]) != "" {
			continue
		}
		name := strings.TrimSpace(cells[1])
		if name == "Feature" || strings.HasPrefix(name, "---") {
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
			t.Fatalf("FEATURES.md row %q: milestone %q is not vN.N", name, ms)
		}
		word := strings.Fields(strings.NewReplacer(":", " ", "(", " ", ",", " ", ";", " ").Replace(status))[0]
		if word == "in" {
			word = "in progress"
		}
		switch word {
		case "done", "partial", "in progress", "planned", "won't":
		default:
			t.Fatalf("FEATURES.md row %q: unknown status %q", name, status)
		}
		c := byMilestone[key]
		c.rows++
		if word == "done" {
			c.done++
		}
		byMilestone[key] = c
		if word == "won't" {
			word = "won't do"
		}
		byStatus[word]++
	}
	return byMilestone, byStatus
}

// summaryCounts reads "| vN.N | rows | done |" lines (and the bold total
// row) from one section of a document, from the heading to the next "## ".
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
	row := regexp.MustCompile(`(?m)^\| (?:\*\*)?(v\d+\.\d+|won't do|[Tt]otal)(?:\*\*)? \| (?:\*\*)?(\d+)(?:\*\*)? \| (?:\*\*)?(\d+|-)(?:\*\*)? \|$`)
	got := map[string]count{}
	for _, m := range row.FindAllStringSubmatch(section, -1) {
		var c count
		var err error
		if c.rows, err = strconv.Atoi(m[2]); err != nil {
			t.Fatal(err)
		}
		if m[3] != "-" {
			if c.done, err = strconv.Atoi(m[3]); err != nil {
				t.Fatal(err)
			}
		}
		got[strings.ToLower(m[1])] = c
	}
	if len(got) == 0 {
		t.Fatalf("no count rows under %q", heading)
	}
	return got
}

func TestFeatureCountsMatchTable(t *testing.T) {
	features := read(t, "docs", "FEATURES.md")
	table, status := tableCounts(t, features)
	if table["v0.9"].rows == 0 {
		t.Fatalf("no v0.9 rows parsed: %v", table)
	}
	want := map[string]count{}
	var total count
	for ms, c := range table {
		want[ms] = c
		total.rows += c.rows
		total.done += c.done
	}
	want["total"] = total
	for name, doc := range map[string]map[string]count{
		"docs/FEATURES.md Summary": summaryCounts(t, features, "## Summary"),
		"README.md Features":       summaryCounts(t, read(t, "README.md"), "## Features"),
	} {
		for ms, w := range want {
			if doc[ms] != w {
				t.Errorf("%s: %s is %+v, the table has %+v", name, ms, doc[ms], w)
			}
		}
		for ms := range doc {
			if _, ok := want[ms]; !ok {
				t.Errorf("%s: %s has no rows in the table", name, ms)
			}
		}
	}
	for st, n := range status {
		row := fmt.Sprintf("| %s | %d |", st, n)
		if !strings.Contains(features, "\n"+row+"\n") {
			t.Errorf("FEATURES.md status table lacks %q", row)
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
