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

	"gopkg.in/yaml.v3"
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

// TestChangelogSummariesStayShort keeps the one-sentence summary under each
// 1.x release heading short. Pre-1.0 summaries are longer and are not checked.
func TestChangelogSummariesStayShort(t *testing.T) {
	const limit = 260
	lines := strings.Split(read(t, "CHANGELOG.md"), "\n")
	head := regexp.MustCompile(`^## \[(1\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$`)
	seen := 0
	for i, l := range lines {
		m := head.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		seen++
		if i+3 >= len(lines) || lines[i+1] != "" || lines[i+2] == "" || lines[i+3] != "" {
			t.Errorf("%s: want one summary paragraph of one line after the heading", m[1])
			continue
		}
		if n := len(lines[i+2]); n > limit {
			t.Errorf("%s: summary is %d characters, limit %d", m[1], n, limit)
		}
		if !strings.Contains(lines[i+2], "`mode: observe`") {
			t.Errorf("%s: summary does not state the default mode: observe", m[1])
		}
	}
	if seen < 10 {
		t.Fatalf("only %d 1.x releases found in CHANGELOG.md", seen)
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

// TestIssueFormsAreValid keeps the issue forms loadable by GitHub: a name, a
// description, and a body of known element types with unique ids, a label on
// every input, and options on every dropdown and checkbox group. Both forms
// that ask for the field-report summary (#625) must warn against real data.
func TestIssueFormsAreValid(t *testing.T) {
	type element struct {
		Type       string `yaml:"type"`
		ID         string `yaml:"id"`
		Attributes struct {
			Label   string `yaml:"label"`
			Value   string `yaml:"value"`
			Options []any  `yaml:"options"`
		} `yaml:"attributes"`
	}
	for _, name := range []string{"field-report.yml", "bug.yml"} {
		var form struct {
			Name        string    `yaml:"name"`
			Description string    `yaml:"description"`
			Body        []element `yaml:"body"`
		}
		if err := yaml.Unmarshal([]byte(read(t, ".github", "ISSUE_TEMPLATE", name)), &form); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if form.Name == "" || form.Description == "" || len(form.Body) == 0 {
			t.Errorf("%s: name, description, and body are required: %+v", name, form)
		}
		ids := map[string]bool{}
		var summary, warned bool
		for i, e := range form.Body {
			switch e.Type {
			case "markdown":
				warned = warned || strings.Contains(e.Attributes.Value, "Do not paste real")
				if !strings.Contains(e.Attributes.Value, "packeteer report --share") && i == 0 {
					t.Errorf("%s: the first block does not name the report command", name)
				}
			case "textarea", "input", "dropdown", "checkboxes":
				if e.Attributes.Label == "" {
					t.Errorf("%s: element %d (%s) has no label", name, i, e.Type)
				}
				if (e.Type == "dropdown" || e.Type == "checkboxes") && len(e.Attributes.Options) == 0 {
					t.Errorf("%s: element %d (%s) has no options", name, i, e.Type)
				}
				if e.ID == "" || ids[e.ID] {
					t.Errorf("%s: element %d has a missing or repeated id %q", name, i, e.ID)
				}
				ids[e.ID] = true
				summary = summary || e.ID == "summary"
			default:
				t.Errorf("%s: element %d has unknown type %q", name, i, e.Type)
			}
		}
		if !summary || !warned {
			t.Errorf("%s: needs a summary field and the warning against real data (summary %v, warning %v)", name, summary, warned)
		}
	}
}
