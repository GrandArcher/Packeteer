package configedit

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// configuredYAML is a working box: three providers, sign-in on, the
// editor on, history, and a probe block the wizard does not write.
const configuredYAML = `# lab box
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: 64512:666
max_improvements: 20
hold_time: 30m
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
  - name: lab-c
    source_ip: 192.0.2.13
    next_hop: 192.0.2.3
bgp:
  neighbors:
    - address: 192.0.2.254
sources:
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
auth:
  enabled: true
  session_ttl: 6h
http:
  listen: 127.0.0.1:9090
  config_editor: true
storage:
  type: sqlite
  config:
    path: /data/history.db
probe:
  degraded_loss_pct: 4
`

func oneProvider() WizardInput {
	return WizardInput{ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"}}}
}

func parseOver(t *testing.T, in WizardInput, cur string) (WizardPlan, *config.Config) {
	t.Helper()
	plan, err := WizardOver(in, []byte(cur))
	if err != nil {
		t.Fatalf("WizardOver: %v", err)
	}
	cfg, err := config.Parse([]byte(plan.YAML))
	if err != nil {
		t.Fatalf("result does not parse: %v\n%s", err, plan.YAML)
	}
	return plan, cfg
}

func TestWizardOverKeepsAuthHTTPStorageAndUnknown(t *testing.T) {
	plan, cfg := parseOver(t, oneProvider(), configuredYAML)
	if !plan.Existing {
		t.Fatal("not marked as over an existing config")
	}
	if !cfg.AuthEnabled() || cfg.Auth.SessionTTL.Hours() != 6 {
		t.Fatalf("auth after the wizard: %+v", cfg.Auth)
	}
	if cfg.HTTP.Listen == nil || *cfg.HTTP.Listen != "127.0.0.1:9090" || !cfg.HTTP.ConfigEditor {
		t.Fatalf("http after the wizard: %+v", cfg.HTTP)
	}
	if cfg.Storage == nil || cfg.Storage.Type != "sqlite" {
		t.Fatalf("storage after the wizard: %+v", cfg.Storage)
	}
	if !strings.Contains(plan.YAML, "path: /data/history.db") || !strings.Contains(plan.YAML, "probe:\n  degraded_loss_pct: 4") {
		t.Fatalf("the probe block was dropped:\n%s", plan.YAML)
	}
	if len(cfg.Providers) != 1 || cfg.Providers[0].Name != "transit-a" {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
	if cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 {
		t.Fatalf("not observe: %q %v", cfg.Mode, cfg.Allowlist.Prefixes)
	}
}

func TestWizardOverNeverTurnsAuthOffUnlessAsked(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   func() WizardInput
		on   bool
	}{
		{"default", oneProvider, true},
		{"explicit off", func() WizardInput { in := oneProvider(); in.DisableAuth = true; return in }, false},
	} {
		plan, cfg := parseOver(t, tc.in(), configuredYAML)
		if cfg.AuthEnabled() != tc.on {
			t.Fatalf("%s: auth enabled = %v, want %v\n%s", tc.name, cfg.AuthEnabled(), tc.on, plan.YAML)
		}
		if cfg.Auth == nil {
			t.Fatalf("%s: the auth block was removed", tc.name)
		}
		off := strings.Contains(strings.Join(plan.Removes, "|"), "Turns off sign-in")
		if off == tc.on {
			t.Fatalf("%s: removes = %v", tc.name, plan.Removes)
		}
	}
}

// With no auth block sign-in is on by default (#328), so the flag writes
// the opt-out; without the flag the file gets no auth block.
func TestWizardOverTurnsDefaultAuthOff(t *testing.T) {
	const noAuth = "mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: x\n    source_ip: 192.0.2.11\n    next_hop: 192.0.2.1\n"
	plan, cfg := parseOver(t, oneProvider(), noAuth)
	if cfg.Auth != nil || strings.Contains(plan.YAML, "auth") {
		t.Fatalf("an auth block appeared:\n%s", plan.YAML)
	}
	in := oneProvider()
	in.DisableAuth = true
	for _, cur := range []string{noAuth, noAuth + "auth:\n", noAuth + "auth:\n  enabled: ~\n  session_ttl: 1h\n"} {
		plan, cfg := parseOver(t, in, cur)
		if !cfg.AuthOptedOut() {
			t.Fatalf("sign-in not turned off over %q:\n%s", cur, plan.YAML)
		}
		if !strings.Contains(strings.Join(plan.Removes, "|"), "Turns off sign-in") {
			t.Fatalf("over %q: removes = %v", cur, plan.Removes)
		}
	}
	// Already off: nothing to report.
	plan, cfg = parseOver(t, in, noAuth+"auth:\n  enabled: false\n")
	if !cfg.AuthOptedOut() || strings.Contains(strings.Join(plan.Removes, "|"), "sign-in") {
		t.Fatalf("explicit off: removes = %v\n%s", plan.Removes, plan.YAML)
	}
}

func TestWizardOverNamesWhatIsLost(t *testing.T) {
	plan, _ := parseOver(t, oneProvider(), configuredYAML)
	got := strings.Join(plan.Removes, "|")
	for _, want := range []string{"Removes 2 providers (transit-b, lab-c)", "Removes 1 source"} {
		if !strings.Contains(got, want) {
			t.Fatalf("removes = %q, want %q", got, want)
		}
	}
	if strings.Contains(got, "BGP neighbor") {
		t.Fatalf("the edge neighbor is unchanged but removes = %q", got)
	}
	// The diff shows the removed provider and keeps the auth block out of it.
	for _, want := range []string{"- hold_time: 30m", "+ hold_time: 15m", "-   - name: transit-b"} {
		if !strings.Contains(plan.Diff, want) {
			t.Fatalf("diff lacks %q:\n%s", want, plan.Diff)
		}
	}
	for _, l := range strings.Split(plan.Diff, "\n") {
		if (strings.HasPrefix(l, "- ") || strings.HasPrefix(l, "+ ")) && (strings.Contains(l, "auth") || strings.Contains(l, "enabled") || strings.Contains(l, "storage") || strings.Contains(l, "listen: 127")) {
			t.Fatalf("diff changes a kept block: %q\n%s", l, plan.Diff)
		}
	}
	for _, r := range plan.Diff {
		if r > 0x7e || (r < 0x20 && r != '\n') {
			t.Fatalf("non-ASCII %q in the diff:\n%s", r, plan.Diff)
		}
	}
}

func TestWizardOverAsciiOnlyDiff(t *testing.T) {
	cur := strings.Replace(configuredYAML, `lab-c`, "caf\u00e9-c \U0001F600", 1)
	plan, _ := parseOver(t, oneProvider(), cur)
	for _, s := range append(plan.Removes, plan.Diff) {
		for _, r := range s {
			if r > 0x7e || (r < 0x20 && r != '\n') {
				t.Fatalf("non-ASCII %q in %q", r, s)
			}
		}
	}
	if !strings.Contains(plan.Diff, `caf\u00e9-c \U0001f600`) {
		t.Fatalf("diff did not escape the name:\n%s", plan.Diff)
	}
}

// The wizard is observe only: over an inject config it ends in observe with
// an empty allowlist, and says so.
func TestWizardOverInjectBecomesObserve(t *testing.T) {
	plan, cfg := parseOver(t, oneProvider(), injectYAML)
	if cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 {
		t.Fatalf("result: %q %v", cfg.Mode, cfg.Allowlist.Prefixes)
	}
	got := strings.Join(plan.Removes, "|")
	if !strings.Contains(got, "Changes mode from inject to observe") || !strings.Contains(got, "Removes 1 allowlist prefix (198.51.100.0/24)") {
		t.Fatalf("removes = %q", got)
	}
}

// A kept announcer block stays in the file; with mode observe it does not
// announce, and the page says the wizard leaves such blocks alone.
func TestWizardOverKeepsAnnouncerInObserve(t *testing.T) {
	_, cfg := parseOver(t, oneProvider(), injectYAML)
	if cfg.Announcer == nil || cfg.Announcer.Type != "gobgp" {
		t.Fatalf("announcer = %+v", cfg.Announcer)
	}
	if cfg.Mode != config.ModeObserve {
		t.Fatalf("mode = %q", cfg.Mode)
	}
}

// Fields the wizard does not write are dropped with the block it replaces;
// the confirm list names them.
func TestWizardOverNamesDroppedFields(t *testing.T) {
	cur := strings.Replace(configuredYAML, "    next_hop: 192.0.2.1\n", "    next_hop: 192.0.2.1\n    fwmark: 101\n", 1)
	cur = strings.Replace(cur, "    - address: 192.0.2.254\n", "    - address: 192.0.2.254\n      hold_time: 90\n", 1)
	cur = strings.Replace(cur, "bgp:\n", "bgp:\n  as_path: true\n", 1)
	cur = strings.Replace(cur, "        - prefix: 198.51.100.0/24\n", "        - prefix: 198.51.100.0/24\n        - prefix: 203.0.113.0/24\n", 1)
	in := oneProvider()
	in.Prefix = "198.51.100.0/24"
	plan, _ := parseOver(t, in, cur)
	got := strings.Join(plan.Removes, "|")
	for _, want := range []string{"Resets provider transit-a: drops fwmark", "Resets BGP neighbor 192.0.2.254: drops hold_time", "Resets bgp: drops as_path", "Removes 1 static target (203.0.113.0/24)"} {
		if !strings.Contains(got, want) {
			t.Errorf("removes lack %q: %q", want, got)
		}
	}
}

func TestAuthOnAnyBoolSpelling(t *testing.T) {
	for text, want := range map[string]bool{"true": true, "True": true, "TRUE": true, "false": false, "False": false, "": true, "~": true} {
		root, err := mappingRoot([]byte("auth:\n  enabled: " + text + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		a, _ := mappingChild(root, "auth")
		if got := authOn(a); got != want {
			t.Errorf("authOn(%q) = %v", text, got)
		}
	}
	if !authOn(nil) {
		t.Error("a missing auth block is not on")
	}
}

func TestWizardOverRefusesBrokenCurrent(t *testing.T) {
	for _, cur := range []string{"mode: [observe\n", "- a\n- b\n"} {
		if _, err := WizardOver(oneProvider(), []byte(cur)); err == nil || !strings.Contains(err.Error(), "cannot be kept") {
			t.Fatalf("current %q: %v", cur, err)
		}
	}
	// A bad wizard input is still refused first, over any current config.
	in := oneProvider()
	in.Mode = "inject"
	if _, err := WizardOver(in, []byte(configuredYAML)); err == nil || !strings.Contains(err.Error(), "inject is not a step") {
		t.Fatalf("inject: %v", err)
	}
}

func TestWizardOverEmptyIsWizard(t *testing.T) {
	want, err := Wizard(oneProvider())
	if err != nil {
		t.Fatal(err)
	}
	for _, cur := range []string{"", "  \n\n"} {
		plan, err := WizardOver(oneProvider(), []byte(cur))
		if err != nil || plan.YAML != string(want) || plan.Existing || plan.Diff != "" || len(plan.Removes) != 0 {
			t.Fatalf("empty current %q: %+v %v", cur, plan, err)
		}
	}
}

func TestWizardOverSameInputHasNoDiff(t *testing.T) {
	fresh, err := Wizard(oneProvider())
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := parseOver(t, oneProvider(), string(fresh))
	if plan.Diff != "" || len(plan.Removes) != 0 {
		t.Fatalf("re-running the same wizard shows changes: %q %v", plan.Diff, plan.Removes)
	}
}

func TestConfigured(t *testing.T) {
	fresh, _ := Wizard(oneProvider())
	for _, tc := range []struct {
		yaml string
		want bool
	}{
		{string(fresh), true},
		{configuredYAML, true},
		{"mode: observe\nbgp:\n  neighbors:\n    - address: 192.0.2.254\n", true},
		{"mode: observe\nixp:\n  fabric: {}\n", true},
		{"mode: observe\n", false},
		{"", false},
		{"mode: [", false},
	} {
		if got := Configured([]byte(tc.yaml)); got != tc.want {
			t.Errorf("Configured(%q) = %v", tc.yaml, got)
		}
	}
}

func TestLineDiff(t *testing.T) {
	got := lineDiff("a\nb\nc\nd\ne\nf\ng\nh\n", "a\nb\nc\nX\ne\nf\ng\nh\n")
	if got != "  b\n  c\n- d\n+ X\n  e\n  f\n" {
		t.Fatalf("diff = %q", got)
	}
	if lineDiff("a\n", "a\n") != "" {
		t.Fatal("equal text has a diff")
	}
	far := lineDiff("1\n2\n3\n4\n5\n6\n7\n8\n9\n", "x\n2\n3\n4\n5\n6\n7\n8\ny\n")
	if !strings.Contains(far, "...") || strings.Contains(far, "  5") {
		t.Fatalf("far changes: %q", far)
	}
}
