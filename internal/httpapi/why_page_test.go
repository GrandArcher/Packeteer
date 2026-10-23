package httpapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWhyPage runs the prefix page "Why?" panel in Node (#201). Like the
// events page test, it is skipped without Node locally and required in CI.
func TestWhyPage(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the why page test")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "why_page_test.js").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("why page: %v\n%s", err, out)
	}
}

// The prefix page has the panel, reads the endpoint the server serves, and
// writes nothing.
func TestWhyPageAssets(t *testing.T) {
	html, js := mustWeb(t, "web/prefix.html"), mustWeb(t, "web/prefix.js")
	for _, s := range []string{`id="why-panel"`, `id="why-body"`} {
		if !strings.Contains(html, s) {
			t.Errorf("prefix.html missing %s", s)
		}
	}
	for _, s := range []string{`getJSON("/api/decisions/" + encodeURIComponent(thisPrefix))`, `loadWhy();`} {
		if !strings.Contains(js, s) {
			t.Errorf("prefix.js missing %s", s)
		}
	}
}
