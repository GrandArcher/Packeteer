package httpapi

import (
	"os/exec"
	"testing"
)

// TestSettingsFormInputs runs the settings form in Node against settings.html.
// Those checks live in the page script. The unit job has Node and does not run Chrome.
func TestSettingsFormInputs(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required to run the settings form")
	}
	out, err := exec.Command(node, "settings_form_test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("settings form: %v\n%s", err, out)
	}
}
