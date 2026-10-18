package httpapi

import (
	"os"
	"os/exec"
	"testing"
)

// TestSettingsFormInputs runs the settings form in Node against settings.html.
// Those checks live in the page script. The CI test job installs Node; a
// local run without it skips rather than failing make test.
func TestSettingsFormInputs(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the settings form")
		}
		t.Skip("node not installed")
	}
	out, err := exec.Command(node, "settings_form_test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("settings form: %v\n%s", err, out)
	}
}
