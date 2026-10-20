package configedit

import (
	"strings"
	"testing"
)

const sectionsFile = `# edge config
mode: observe
thresholds:
  min_loss_delta_pct: 2   # keep
  min_rtt_delta_ms: 10
policies:
  - type: rules
    config: &r
      rules: []
allowlist:
  prefixes: [192.0.2.0/24]
`

func TestReadSectionsIsCanonical(t *testing.T) {
	got, err := ReadSections([]byte(sectionsFile), []string{"thresholds", "policies", "federation"})
	if err != nil {
		t.Fatal(err)
	}
	if got["thresholds"] != "min_loss_delta_pct: 2\nmin_rtt_delta_ms: 10\n" {
		t.Fatalf("thresholds = %q", got["thresholds"])
	}
	if !strings.Contains(got["policies"], "type: rules") || strings.Contains(got["policies"], "&r") {
		t.Fatalf("policies = %q", got["policies"])
	}
	if got["federation"] != "" {
		t.Fatalf("absent key = %q, want empty", got["federation"])
	}
	// The same settings written another way read the same.
	other, err := CanonicalSection("{min_rtt_delta_ms: 10, min_loss_delta_pct: 2}")
	if err != nil || other != got["thresholds"] {
		t.Fatalf("canonical = %q (%v)", other, err)
	}
}

func TestReplaceSectionsKeepsTheRest(t *testing.T) {
	out, err := ReplaceSections([]byte(sectionsFile), map[string]string{
		"thresholds": "min_loss_delta_pct: 5\n",
		"policies":   "",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, keep := range []string{"# edge config", "mode: observe", "192.0.2.0/24"} {
		if !strings.Contains(s, keep) {
			t.Errorf("lost %q:\n%s", keep, s)
		}
	}
	if strings.Contains(s, "min_rtt_delta_ms") || strings.Contains(s, "policies") {
		t.Errorf("old sections remain:\n%s", s)
	}
	got, err := ReadSections(out, []string{"thresholds", "policies"})
	if err != nil || got["thresholds"] != "min_loss_delta_pct: 5\n" || got["policies"] != "" {
		t.Fatalf("after replace: %v %v", got, err)
	}

	// A section that was not there is added.
	out, err = ReplaceSections([]byte("mode: observe\n"), map[string]string{"thresholds": "min_loss_delta_pct: 1\n"})
	if err != nil || !strings.Contains(string(out), "min_loss_delta_pct: 1") {
		t.Fatalf("add: %q %v", out, err)
	}
	if _, err := ReplaceSections([]byte("mode: observe\n"), map[string]string{"thresholds": "a: [\n"}); err == nil {
		t.Fatal("accepted unparseable section text")
	}
}
