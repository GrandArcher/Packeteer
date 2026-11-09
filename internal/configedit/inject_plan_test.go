package configedit

import (
	"strconv"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

const observeWizardYAML = `# kept comment
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: 64512:666
max_improvements: 50
hold_time: 15m
thresholds:
  min_loss_delta_pct: 1
  min_rtt_delta_ms: 15
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: []
bgp:
  neighbors:
    - address: 192.0.2.254
auth:
  enabled: true
storage:
  type: sqlite
  config:
    path: /var/lib/packeteer/packeteer.db
`

func TestEnableInjectBuildsASmallInjectConfig(t *testing.T) {
	cur := strings.Replace(observeWizardYAML, "max_improvements: 50\n", "max_improvements: 50\nannouncer:\n  type: gobgp\n", 1)
	plan, err := EnableInject(InjectInput{Allowlist: []string{"198.51.100.0/24", " 203.0.113.7/24 ", "198.51.100.0/24"}}, []byte(cur))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(plan.YAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != config.ModeInject || *cfg.MaxImprovements != DefaultInjectCap || cfg.LocalPref != DefaultInjectLocalPref || cfg.Announcer == nil || cfg.Announcer.Type != "gobgp" {
		t.Fatalf("config = mode %s cap %d local_pref %d announcer %+v", cfg.Mode, *cfg.MaxImprovements, cfg.LocalPref, cfg.Announcer)
	}
	if got := strings.Join(cfg.Allowlist.Prefixes, ","); got != "198.51.100.0/24,203.0.113.0/24" {
		t.Fatalf("allowlist = %s (masked and de-duplicated)", got)
	}
	if !strings.Contains(plan.YAML, "# kept comment") || !strings.Contains(plan.YAML, "enabled: true") {
		t.Errorf("the rest of the file was not kept:\n%s", plan.YAML)
	}
	if !strings.Contains(plan.Diff, "- mode: observe") || !strings.Contains(plan.Diff, "+ mode: inject") {
		t.Errorf("diff:\n%s", plan.Diff)
	}
	text := strings.Join(plan.Explain, "\n")
	for _, want := range []string{"from observe to inject", "198.51.100.0/24, 203.0.113.0/24", "At most 5 routes", "64512:666 and NO_EXPORT", "withdrawn when Packeteer stops", "local_pref 250 is added"} {
		if !strings.Contains(text, want) {
			t.Errorf("explanation lacks %q:\n%s", want, text)
		}
	}
}

func TestEnableInjectKeepsWhatIsSet(t *testing.T) {
	cur := strings.Replace(observeWizardYAML, "max_improvements: 50\n", "max_improvements: 50\nlocal_pref: 300\nannouncer:\n  type: gobgp\n", 1)
	plan, err := EnableInject(InjectInput{Allowlist: []string{"198.51.100.0/24"}, MaxImprovements: 2}, []byte(cur))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := config.Parse([]byte(plan.YAML))
	if cfg.LocalPref != 300 || *cfg.MaxImprovements != 2 {
		t.Fatalf("local_pref %d cap %d", cfg.LocalPref, *cfg.MaxImprovements)
	}
	if text := strings.Join(plan.Explain, "\n"); strings.Contains(text, "is added") {
		t.Errorf("explains a change that was not made:\n%s", text)
	}
}

func TestEnableInjectRefusals(t *testing.T) {
	cases := []struct {
		name    string
		in      InjectInput
		current string
		want    string
	}{
		{"no prefix", InjectInput{}, observeWizardYAML, "at least one prefix"},
		{"bad prefix", InjectInput{Allowlist: []string{"198.51.100.1"}}, observeWizardYAML, "not a prefix"},
		{"default route", InjectInput{Allowlist: []string{"0.0.0.0/0"}}, observeWizardYAML, "covers everything"},
		{"too many", InjectInput{Allowlist: manyPrefixes(11)}, observeWizardYAML, "at most 10"},
		{"cap too big", InjectInput{Allowlist: []string{"198.51.100.0/24"}, MaxImprovements: 51}, observeWizardYAML, "1 to 50"},
		{"no community", InjectInput{Allowlist: []string{"198.51.100.0/24"}}, strings.Replace(observeWizardYAML, "packeteer_community: 64512:666\n", "", 1), "packeteer_community"},
		{"no neighbor", InjectInput{Allowlist: []string{"198.51.100.0/24"}}, strings.Replace(observeWizardYAML, "bgp:\n  neighbors:\n    - address: 192.0.2.254\n", "", 1), "bgp.neighbors"},
		{"no announcer", InjectInput{Allowlist: []string{"198.51.100.0/24"}}, observeWizardYAML, "announcer"},
		{"not yaml", InjectInput{Allowlist: []string{"198.51.100.0/24"}}, "mode: [", "does not load"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := EnableInject(c.in, []byte(c.current)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	already := strings.Replace(observeWizardYAML, "mode: observe", "mode: inject", 1)
	already = strings.Replace(already, "prefixes: []", "prefixes: [198.51.100.0/24]", 1) + "local_pref: 250\nannouncer:\n  type: gobgp\n"
	if _, err := EnableInject(InjectInput{Allowlist: []string{"198.51.100.0/24"}}, []byte(already)); err == nil || !strings.Contains(err.Error(), "already in inject mode") {
		t.Fatalf("already inject: %v", err)
	}
}

func manyPrefixes(n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, "198.51."+strconv.Itoa(i)+".0/24")
	}
	return out
}
