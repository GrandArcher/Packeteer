package httpapi

import (
	"fmt"
	"strings"
	"testing"
)

// TestDashboardsPageAssets checks the wiring of the widget grid (#182): every
// element the script looks up is on the page, the grid constants in the
// script and the size classes in the CSS cover every width and height the
// server accepts, and moving and resizing work from the keyboard. The page
// itself is exercised in headless Chrome by the UI smoke test in CI.
func TestDashboardsPageAssets(t *testing.T) {
	html := mustWeb(t, "web/dashboards.html")
	js := mustWeb(t, "web/dashboards.js")
	css := mustWeb(t, "web/app.css")

	for _, id := range jsIDs(js) {
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("dashboards.js looks up #%s, which dashboards.html lacks", id)
		}
	}
	for _, s := range []string{
		fmt.Sprintf("var GRID_COLUMNS = %d;", GridColumns),
		fmt.Sprintf("var MAX_ROWS = %d;", MaxWidgetRows),
		fmt.Sprintf("var REFRESHES = [%s];", strings.Trim(strings.ReplaceAll(fmt.Sprint(WidgetRefreshes), " ", ", "), "[]")),
	} {
		if !strings.Contains(js, s) {
			t.Errorf("dashboards.js lacks %q", s)
		}
	}
	for n := 1; n <= GridColumns; n++ {
		if !strings.Contains(css, fmt.Sprintf(".widget.w-%d { grid-column: span %d; }", n, n)) {
			t.Errorf("app.css lacks the class for width %d", n)
		}
	}
	for n := 1; n <= MaxWidgetRows; n++ {
		if !strings.Contains(css, fmt.Sprintf(".widget.h-%d { height: %dpx; }", n, n*144)) {
			t.Errorf("app.css lacks the class for height %d", n)
		}
	}
	if !strings.Contains(js, "var GRID_ROW_PX = 144;") {
		t.Error("GRID_ROW_PX does not match the CSS row height")
	}
	// Keyboard: the move grip takes the arrow keys, Home, and End; the size
	// grip takes the arrow keys; the list under the form has the same
	// actions as buttons and menus.
	for _, s := range []string{
		`ArrowLeft: i - 1`, `ArrowUp: i - 1`, `ArrowRight: i + 1`, `ArrowDown: i + 1`, `Home: 0`, `End: current.widgets.length - 1`,
		`{ArrowLeft: -1, ArrowRight: 1}`, `{ArrowUp: -1, ArrowDown: 1}`,
		`"Move " + t + " earlier"`, `"Move " + t + " later"`, `"Width of " + t`, `"Height of " + t`, `"Refresh of " + t`, `"Time window of " + t`,
		`move.draggable = true`, `"drop"`, `"pointerdown"`, `announce(`,
		`var seq = ++c.seq;`, `if (seq !== c.seq) return;`,
	} {
		if !strings.Contains(js, s) {
			t.Errorf("dashboards.js lacks %q", s)
		}
	}
	// Reading only: the page saves through the dashboards API and nothing else.
	for _, bad := range []string{"innerHTML", `"POST"`, "eval("} {
		if strings.Contains(js, bad) {
			t.Errorf("dashboards.js uses %q", bad)
		}
	}
	if !strings.Contains(html, `id="db-live" class="tag" role="status" aria-live="polite"`) {
		t.Error("dashboards.html #db-live is not a polite live region")
	}
}
