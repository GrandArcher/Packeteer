package httpapi

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// searchHints are the only placeholders a page may carry: short words that
// say what a search box takes, never something that reads as an entered value
// (#350).
var searchHints = map[string]bool{
	"Prefix, AS, or name":              true,
	"Event, message, provider, prefix": true,
	"Search countries":                 true,
}

var (
	inputTag       = regexp.MustCompile(`<input\b[^>]*>`)
	placeholderAtt = regexp.MustCompile(`\bplaceholder="([^"]*)"`)
	placeholderJS  = regexp.MustCompile(`\.placeholder\s*=\s*([^;]*);`)
)

// TestFormsShowNoExampleValues (#350): no input in any page, and no input a
// script builds, shows a grey example or default.
func TestFormsShowNoExampleValues(t *testing.T) {
	entries, err := fs.ReadDir(webFS, "web")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".html"):
			body := mustWeb(t, "web/"+name)
			for _, tag := range inputTag.FindAllString(body, -1) {
				if m := placeholderAtt.FindStringSubmatch(tag); m != nil && !searchHints[m[1]] {
					t.Errorf("%s: %s shows the placeholder %q; put the example in the help text", name, tag, m[1])
				}
			}
		case strings.HasSuffix(name, ".js"):
			for _, m := range placeholderJS.FindAllStringSubmatch(mustWeb(t, "web/"+name), -1) {
				if v := strings.Trim(m[1], `"`); !searchHints[v] {
					t.Errorf("%s sets the placeholder %q", name, v)
				}
			}
		}
	}
}

// TestFormsExamplesInHelp (#350): the Reports filters, the Prefixes filters,
// and the wizard start empty and say what empty means and what an example
// looks like in the help line next to them. Documentation prefixes and AS
// numbers only.
func TestFormsExamplesInHelp(t *testing.T) {
	help := func(page, id string) string {
		t.Helper()
		body := mustWeb(t, "web/"+page)
		m := regexp.MustCompile(`<input id="` + id + `"[^>]*>(<span class="field-help">[^<]*</span>)`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("%s: input %s has no help line after it", page, id)
		}
		return m[1]
	}
	for _, tc := range []struct{ page, id, want string }{
		{"reports.html", "rf-provider", "Empty shows all providers."},
		{"reports.html", "rf-asn", "For example 64500."},
		{"reports.html", "rf-prefix", "For example 192.0.2.0/24."},
		{"prefixes.html", "prefix-filter", "198.51.100.0/24"},
		{"prefixes.html", "prefix-asn", "For example 64500."},
		{"settings.html", "wz-prefix", "For example 198.51.100.0/24."},
		{"settings.html", "wz-host", "For example 198.51.100.10."},
	} {
		if got := help(tc.page, tc.id); !strings.Contains(got, tc.want) {
			t.Errorf("%s %s help = %q, want %q", tc.page, tc.id, got, tc.want)
		}
	}
	body := mustWeb(t, "web/settings.html")
	for _, id := range []string{"wz-asn", "wz-router", "wz-edge", "wz-flow-addr", "wz-flow-port"} {
		m := regexp.MustCompile(`<input id="` + id + `"[^>]*>`).FindString(body)
		if m == "" || strings.Contains(m, "placeholder") || strings.Contains(m, "value=") {
			t.Errorf("wizard field %s = %q", id, m)
		}
	}
	for _, want := range []string{"for example 64512", "for example 192.0.2.10", "for example 192.0.2.254", "for example 2055"} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard help lacks %q", want)
		}
	}
	// A default is text beside the field, not a value inside it.
	for _, want := range []string{"Default: 50", "Default: 1"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings help lacks %q", want)
		}
	}
}
