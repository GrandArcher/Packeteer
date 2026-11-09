package httpapi

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TestOnlyInvalidPages runs the RPKI-invalid only path UI (#401) in Node
// on the JSON the API serves for a fixture case: the read-only prefix
// page panel and the propose, approve, and remove controls on the Registry
// page. Like the other page tests, it is skipped without Node locally and
// required in CI.
func TestOnlyInvalidPages(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the only-invalid page test")
		}
		t.Skip("node not installed")
	}
	e, _ := onlyInvalidEnv(t)
	rec := e.do("GET", "/api/rpki/only-invalid", e.tokens[plugin.RoleViewer], "")
	if rec.Code != 200 {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}
	file := filepath.Join(t.TempDir(), "only-invalid.json")
	if err := os.WriteFile(file, rec.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "only_invalid_page_test.js", file).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("only-invalid pages: %v\n%s", err, out)
	}
}
