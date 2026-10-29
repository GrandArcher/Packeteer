package plugins_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var spdx = regexp.MustCompile(`^[A-Za-z0-9.+-]+( (AND|OR|WITH) [A-Za-z0-9.+-]+)*$`)

// checkRow applies the checklist at the top of docs/COMMUNITY_PLUGINS.md to
// one table row: name, kind, delivery, affects routing, license, link.
func checkRow(c []string) error {
	if len(c) != 6 {
		return fmt.Errorf("%d columns, want 6", len(c))
	}
	name, kind, delivery, routing, license, link := c[0], c[1], c[2], c[3], c[4], c[5]
	if name == "" || kind == "" {
		return fmt.Errorf("name and kind are required")
	}
	if !slices.Contains([]string{"exec", "grpc", "compiled-in"}, delivery) {
		return fmt.Errorf("delivery %q is not exec, grpc, or compiled-in", delivery)
	}
	if routing != "yes" && routing != "no" {
		return fmt.Errorf("affects routing %q is not yes or no", routing)
	}
	if delivery != "compiled-in" {
		if !slices.Contains([]string{"prober", "source", "notifier"}, kind) {
			return fmt.Errorf("an %s plugin cannot be a %s", delivery, kind)
		}
		if routing != "no" {
			return fmt.Errorf("an %s plugin cannot affect routing", delivery)
		}
	}
	if !spdx.MatchString(license) {
		return fmt.Errorf("license %q is not an SPDX identifier", license)
	}
	if !strings.HasPrefix(link, "https://") {
		return fmt.Errorf("link %q is not https", link)
	}
	return nil
}

func cells(line string) []string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func TestCommunityListRows(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "COMMUNITY_PLUGINS.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, table, ok := strings.Cut(string(data), "\n## Plugins\n")
	if !ok {
		t.Fatal("no Plugins section")
	}
	lines := strings.Split(strings.TrimSpace(table), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "| Name | Kind | Delivery | Affects routing | License | Link |") ||
		!strings.HasPrefix(lines[1], "|---") {
		t.Fatalf("table header = %q", lines)
	}
	var names []string
	for _, l := range lines[2:] {
		c := cells(l)
		if err := checkRow(c); err != nil {
			t.Errorf("row %q: %v", l, err)
			continue
		}
		names = append(names, strings.ToLower(c[0]))
	}
	if !slices.IsSorted(names) {
		t.Errorf("rows are not in alphabetical order: %v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			t.Errorf("duplicate name %q", names[i])
		}
	}
}

func TestCheckRow(t *testing.T) {
	good := []string{"cmdb-source", "source", "exec", "no", "Apache-2.0", "https://example.invalid/cmdb-source"}
	if err := checkRow(good); err != nil {
		t.Fatalf("good row: %v", err)
	}
	with := func(i int, v string) []string {
		c := slices.Clone(good)
		c[i] = v
		return c
	}
	for name, tc := range map[string]struct {
		row  []string
		want string
	}{
		"short row":           {good[:5], "5 columns"},
		"bad delivery":        {with(2, "plugin"), "delivery"},
		"bad routing":         {with(3, "maybe"), "yes or no"},
		"exec announcer":      {with(1, "announcer"), "cannot be a announcer"},
		"exec affects routes": {with(3, "yes"), "cannot affect routing"},
		"grpc affects routes": {append(with(2, "grpc")[:3:3], "yes", "MIT", good[5]), "cannot affect routing"},
		"no license":          {with(4, ""), "SPDX"},
		"http link":           {with(5, "http://example.invalid/x"), "https"},
	} {
		if err := checkRow(tc.row); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
	fork := []string{"my-announcer", "announcer", "compiled-in", "yes", "MIT", "https://example.invalid/x"}
	if err := checkRow(fork); err != nil {
		t.Errorf("compiled-in announcer: %v", err)
	}
}
