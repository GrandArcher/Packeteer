package httpapi

import (
	"encoding/json"
	"io/fs"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustWeb(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(webFS, name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestModeChipContrast checks the header mode chips (#171). The header
// text is white; each chip sets its own colors and must meet WCAG AA
// (4.5:1) for normal-size text.
func TestModeChipContrast(t *testing.T) {
	css := mustWeb(t, "web/app.css")
	for _, class := range []string{"mode-observe", "mode-suggest", "mode-inject", "mode-unknown"} {
		fg, bg := chipColors(t, css, class)
		ratio := contrastHex(t, fg, bg)
		if ratio < 4.5 {
			t.Errorf("%s contrast %.2f (fg %s bg %s) is below WCAG AA 4.5", class, ratio, fg, bg)
		}
	}
	fg, bg := chipColors(t, css, "mode-observe")
	if strings.EqualFold(fg, "#ffffff") {
		t.Errorf("observe chip text is white on %s", bg)
	}
	js := mustWeb(t, "web/app.js")
	for _, want := range []string{
		`mode === "observe" || mode === "suggest" || mode === "inject"`,
		`"badge mode-" + name`,
		"function modeBadge(mode)",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js missing %q", want)
		}
	}
	if !strings.Contains(mustWeb(t, "web/index.html"), `id="banner"`) {
		t.Fatal("mode banner was removed from the dashboard")
	}
}

func chipColors(t *testing.T, css, class string) (fg, bg string) {
	t.Helper()
	re := regexp.MustCompile(`\.badge\.` + regexp.QuoteMeta(class) + `\s*\{([^}]*)\}`)
	m := re.FindStringSubmatch(css)
	if m == nil {
		t.Fatalf("css missing .badge.%s", class)
	}
	body := m[1]
	fg = mustHexProp(t, body, `color:\s*(#[0-9a-fA-F]{6})`)
	bg = mustHexProp(t, body, `background:\s*(#[0-9a-fA-F]{6})`)
	return fg, bg
}

func mustHexProp(t *testing.T, body, expr string) string {
	t.Helper()
	m := regexp.MustCompile(expr).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("missing %s in %q", expr, body)
	}
	return strings.ToLower(m[1])
}

func contrastHex(t *testing.T, fg, bg string) float64 {
	t.Helper()
	l1, l2 := relLuminance(t, fg), relLuminance(t, bg)
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05)
}

func relLuminance(t *testing.T, hex string) float64 {
	t.Helper()
	n, err := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	if err != nil || len(hex) != 7 {
		t.Fatalf("bad color %q", hex)
	}
	ch := func(v byte) float64 {
		s := float64(v) / 255
		if s <= 0.03928 {
			return s / 12.92
		}
		return math.Pow((s+0.055)/1.055, 2.4)
	}
	r, g, b := byte(n>>16), byte(n>>8), byte(n)
	return 0.2126*ch(r) + 0.7152*ch(g) + 0.0722*ch(b)
}

// TestWidgetDisplay checks the custom-dashboard title and the shared
// local-time formatter (#171).
func TestWidgetDisplay(t *testing.T) {
	dash := mustWeb(t, "web/dashboards.js")
	ui := mustWeb(t, "web/ui.js")
	app := mustWeb(t, "web/app.js")
	if !strings.Contains(dash, `return mode === "inject" ? "Active improvements" : "Recommended improvements"`) {
		t.Fatal("improvements widget title is not mode-aware")
	}
	if !strings.Contains(dash, "improvementsTitle(dashMode)") {
		t.Fatal("widget heading does not use the mode-aware title")
	}
	appFn := extractFunc(t, app, "fmtTime")
	uiFn := extractFunc(t, ui, "fmtTime")
	if appFn != uiFn {
		t.Fatalf("fmtTime drifted:\napp.js:\n%s\nui.js:\n%s", appFn, uiFn)
	}
	if !strings.Contains(ui, "isoTime.test(s)") || !strings.Contains(ui, "fmtTime(s)") {
		t.Fatal("widget cells do not format ISO timestamps with fmtTime")
	}
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	samples := []time.Time{
		time.Date(2026, 10, 7, 20, 19, 27, 894478988, time.FixedZone("EDT", -4*3600)),
		time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		time.Now().UTC(),
	}
	for _, ts := range samples {
		raw, err := json.Marshal(ts)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.Trim(string(raw), `"`)
		if !re.MatchString(s) {
			t.Errorf("widget ISO check would miss Go time %s", s)
		}
	}
	for _, skip := range []string{"198.51.100.0/24", "2026-10-07", "not-a-time"} {
		if re.MatchString(skip) {
			t.Errorf("ISO check matched %q", skip)
		}
	}
}

func extractFunc(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "function "+name+"(s) {")
	if start < 0 {
		t.Fatalf("missing function %s", name)
	}
	rest := src[start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("unterminated function %s", name)
	}
	return rest[:end+2]
}

// TestProviderFieldLabels checks each settings-form provider field has a
// visible label (#171). The label wraps the input, so it is the
// accessible name.
func TestProviderFieldLabels(t *testing.T) {
	js := mustWeb(t, "web/settings.js")
	css := mustWeb(t, "web/app.css")
	for _, label := range []string{"Name", "Probe source", "Next hop", "Cost", "Commit"} {
		if !strings.Contains(js, `labeled("`+label+`"`) {
			t.Errorf("settings form missing label %q", label)
		}
	}
	if !strings.Contains(js, `el("label", "field")`) || !strings.Contains(js, `el("span", "field-label", text)`) {
		t.Fatal("provider label is not a visible label element")
	}
	if !regexp.MustCompile(`\.field-label\s*\{[^}]*color:\s*var\(--ink\)`).MatchString(css) {
		t.Fatal("field label is not visibly colored")
	}
	// The wizard rows use the same labels for the three fields it has.
	if strings.Count(js, `labeled("Probe source"`) < 2 || strings.Count(js, `labeled("Next hop"`) < 2 {
		t.Fatal("wizard provider rows are unlabeled")
	}
}
