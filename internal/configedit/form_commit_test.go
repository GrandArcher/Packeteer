package configedit

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

const commitBaseYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    cost: 5
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
    cost: 9
scorer:
  type: weighted
  config: {loss_weight: 100, rtt_weight: 1}
allowlist:
  prefixes: [198.51.100.0/24]
`

func scorerKeys(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := cfg.Scorer.Config.Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func commitRow(f *Form, name string) *FormCommitProvider {
	for i := range f.Commit.Providers {
		if f.Commit.Providers[i].Name == name {
			return &f.Commit.Providers[i]
		}
	}
	return nil
}

func setupCommit(t *testing.T, yaml string) Form {
	t.Helper()
	f, err := ParseForm([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	f.Providers[0].CommitMbps = "1000"
	f.Providers[1].CommitMbps = "500"
	f.Commit.Scorer = "commit"
	f.Commit.Balance = "equal"
	f.Commit.Hosts = append(f.Commit.Hosts, FormCommitHost{Name: "edge", Address: "192.0.2.254", CommunityEnv: "PACKETEER_SNMP_COMMUNITY"})
	for _, name := range []string{"transit-a", "transit-b"} {
		r := commitRow(&f, name)
		r.Host, r.Interface, r.BillingDay, r.Percentile, r.Group = "edge", "ether-"+name, "1", "greater", "edge"
	}
	commitRow(&f, "transit-b").Precedence = "200"
	commitRow(&f, "transit-b").CCDisable = true
	return f
}

func TestCommitSetupRoundTripsThroughLoad(t *testing.T) {
	out, err := ApplyForm([]byte(commitBaseYAML), setupCommit(t, commitBaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if cfg.Mode != config.ModeObserve || cfg.Scorer == nil || cfg.Scorer.Type != "commit" {
		t.Fatalf("mode %s scorer %+v", cfg.Mode, cfg.Scorer)
	}
	keys := scorerKeys(t, cfg)
	if keys["balance"] != "equal" || keys["loss_weight"] == nil {
		t.Fatalf("scorer config = %v", keys)
	}
	a, b := cfg.Providers[0], cfg.Providers[1]
	if a.Group != "edge" || b.Group != "edge" || b.Precedence != 200 || !b.CCDisable || a.CCDisable || a.Precedence != 0 {
		t.Fatalf("providers %+v %+v", a, b)
	}
	if len(cfg.Telemetry) != 1 || cfg.Telemetry[0].Type != "snmp" {
		t.Fatalf("telemetry = %+v", cfg.Telemetry)
	}
	text := string(out)
	for _, want := range []string{"community_env: PACKETEER_SNMP_COMMUNITY", "version: 2c", "commit_mbps: 1000", "commit_mbps: 500", "interface: ether-transit-a", "billing_day: 1", "percentile: greater"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "mode: inject") || strings.Contains(text, "graceful") {
		t.Fatalf("setup changed safety settings:\n%s", text)
	}
	back, err := ParseForm(out)
	if err != nil {
		t.Fatal(err)
	}
	if r := commitRow(&back, "transit-b"); r == nil || r.Host != "edge" || r.Precedence != "200" || !r.CCDisable || r.Percentile != "greater" {
		t.Fatalf("round trip row = %+v", r)
	}
	if back.Commit.Balance != "equal" || back.ScorerType != "commit" || len(back.Commit.Hosts) != 1 || back.Commit.Hosts[0].Key != "edge" {
		t.Fatalf("round trip = %+v scorer %s", back.Commit, back.ScorerType)
	}
	if back.Providers[0].CommitMbps != "1000" || !back.Providers[0].CommitBound {
		t.Fatalf("commit = %+v", back.Providers[0])
	}
}

func TestCommitSetupRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(f *Form)
		want string
	}{
		{"commit without a binding", func(f *Form) {
			*f.Commit = FormCommit{Hosts: f.Commit.Hosts, Providers: f.Commit.Providers}
			for i := range f.Commit.Providers {
				f.Commit.Providers[i].Host, f.Commit.Providers[i].Interface = "", ""
				f.Commit.Providers[i].BillingDay, f.Commit.Providers[i].Percentile = "", ""
			}
		}, "telemetry binding"},
		{"binding without commit", func(f *Form) { f.Providers[0].CommitMbps = "" }, "commit_mbps"},
		{"secret instead of an env var name", func(f *Form) { f.Commit.Hosts[0].CommunityEnv = "s3cret-community" }, "environment variable"},
		{"host not in the form", func(f *Form) { commitRow(f, "transit-a").Host = "other" }, "not an SNMP host"},
		{"billing day 29", func(f *Form) { commitRow(f, "transit-a").BillingDay = "29" }, "billing_day"},
		{"percentile", func(f *Form) { commitRow(f, "transit-a").Percentile = "average" }, "percentile"},
		{"binding fields without a host", func(f *Form) { commitRow(f, "transit-a").Host = "" }, "needs a host"},
		{"precedence", func(f *Form) { commitRow(f, "transit-a").Precedence = "-1" }, "precedence"},
		{"group", func(f *Form) { commitRow(f, "transit-a").Group = "a b" }, "group"},
		{"unknown provider row", func(f *Form) { f.Commit.Providers = append(f.Commit.Providers, FormCommitProvider{Name: "ghost"}) }, "not a provider"},
		{"balance under cost", func(f *Form) { f.Commit.Scorer = "cost" }, "commit scorer's"},
		{"scorer", func(f *Form) { f.Commit.Scorer = "magic" }, "commit.scorer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := setupCommit(t, commitBaseYAML)
			c.edit(&f)
			_, err := ApplyForm([]byte(commitBaseYAML), f)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestCommitWithoutBindingStillRefused(t *testing.T) {
	f, err := ParseForm([]byte(commitBaseYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.Providers[0].CommitMbps = "1000"
	if _, err := ApplyForm([]byte(commitBaseYAML), f); err == nil || !strings.Contains(err.Error(), "telemetry binding") {
		t.Fatalf("err = %v", err)
	}
}

func TestCommitSetupEditsExistingBindingAndLeavesHosts(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	r := commitRow(&f, "transit-a")
	if r.Host != "edge" || r.Interface != "eth0" {
		t.Fatalf("row = %+v", r)
	}
	r.Interface, r.BillingDay, r.Percentile = "eth1", "15", "separate"
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "interface: eth1") || !strings.Contains(text, "billing_day: 15") || !strings.Contains(text, "percentile: separate") ||
		!strings.Contains(text, "commit_mbps: 1000") || strings.Contains(text, "eth0") {
		t.Fatalf("binding not edited in place:\n%s", text)
	}
	if cfg.Scorer.Type != "cost" || strings.Count(text, "- name: edge") != 1 {
		t.Fatalf("scorer %s or hosts changed:\n%s", cfg.Scorer.Type, text)
	}

	f, _ = ParseForm([]byte(formYAML))
	f.Commit.Hosts = append(f.Commit.Hosts, FormCommitHost{Name: "edge", Address: "192.0.2.98", CommunityEnv: "OTHER_ENV"})
	if _, err := ApplyForm([]byte(formYAML), f); err == nil || !strings.Contains(err.Error(), "already in the file") {
		t.Fatalf("duplicate host: %v", err)
	}
	f, _ = ParseForm([]byte(formYAML))
	f.Commit.Hosts = []FormCommitHost{}
	if _, err := ApplyForm([]byte(formYAML), f); err == nil || !strings.Contains(err.Error(), "still used by provider transit-a") {
		t.Fatalf("dropped host that a binding uses: %v", err)
	}
}

// TestCommitSetupEditsHostsAndUntracks (#330): an existing SNMP host can be
// edited and switched to version 3, and a provider can be untracked, after
// which its host can go. Comments and unrelated keys stay.
func TestCommitSetupEditsHostsAndUntracks(t *testing.T) {
	f, _ := ParseForm([]byte(formYAML))
	h := &f.Commit.Hosts[0]
	h.Address, h.Port = "192.0.2.99", "1161"
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "address: 192.0.2.99") || !strings.Contains(text, "port: 1161") ||
		!strings.Contains(text, "# keep this comment") || !strings.Contains(text, "password_env: PACKETEER_SMTP_PASSWORD") {
		t.Fatalf("host edit:\n%s", text)
	}
	if _, err := config.Parse(out); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}

	f, _ = ParseForm([]byte(formYAML))
	f.Commit.Hosts[0] = FormCommitHost{Key: "edge", Name: "edge", Address: "192.0.2.254", Version: "3", UsernameEnv: "PACKETEER_SNMP_USER",
		SecurityLevel: "authPriv", AuthProtocol: "SHA256", AuthEnv: "PACKETEER_SNMP_AUTH", PrivProtocol: "AES", PrivEnv: "PACKETEER_SNMP_PRIV", ContextName: "ctx"}
	out, err = ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	text = string(out)
	if strings.Contains(text, "community_env") || !strings.Contains(text, "version: \"3\"") && !strings.Contains(text, "version: '3'") && !strings.Contains(text, "version: 3") {
		t.Fatalf("version switch kept the v2c key or lost the version:\n%s", text)
	}
	if _, err := config.Parse(out); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	back, _ := ParseForm(out)
	if got := back.Commit.Hosts[0]; got.Version != "3" || got.SecurityLevel != "authPriv" || got.AuthEnv != "PACKETEER_SNMP_AUTH" || got.ContextName != "ctx" {
		t.Fatalf("round trip = %+v", got)
	}

	f, _ = ParseForm([]byte(formYAML))
	row := commitRow(&f, "transit-a")
	*row = FormCommitProvider{Name: "transit-a"}
	f.Providers[0].CommitMbps = ""
	f.Commit.Hosts = []FormCommitHost{}
	out, err = ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatalf("untrack and drop the host: %v", err)
	}
	if strings.Contains(string(out), "telemetry:") || !strings.Contains(string(out), "name: transit-a") {
		t.Fatalf("telemetry should be gone and the provider kept:\n%s", out)
	}
	if _, err := config.Parse(out); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
}

func TestCommitSetupHostRefusals(t *testing.T) {
	good := FormCommitHost{Key: "edge", Name: "edge", Address: "192.0.2.254", Version: "3", UsernameEnv: "U_ENV", SecurityLevel: "authPriv",
		AuthProtocol: "SHA", AuthEnv: "A_ENV", PrivProtocol: "AES", PrivEnv: "P_ENV"}
	cases := []struct {
		name string
		edit func(h *FormCommitHost)
		want string
	}{
		{"auth passphrase typed in", func(h *FormCommitHost) { h.AuthEnv = "my secret pass" }, "auth_env"},
		{"user typed in", func(h *FormCommitHost) { h.UsernameEnv = "admin user" }, "username_env"},
		{"v3 with a community", func(h *FormCommitHost) { h.CommunityEnv = "C_ENV" }, "community_env does not apply"},
		{"no auth, but a protocol", func(h *FormCommitHost) { h.SecurityLevel, h.PrivProtocol, h.PrivEnv = "noAuthNoPriv", "", "" }, "auth_protocol does not apply"},
		{"authNoPriv with privacy", func(h *FormCommitHost) { h.SecurityLevel = "authNoPriv" }, "priv_protocol does not apply"},
		{"unknown auth protocol", func(h *FormCommitHost) { h.AuthProtocol = "CRC" }, "auth_protocol"},
		{"missing priv env", func(h *FormCommitHost) { h.PrivEnv = "" }, "priv_env"},
		{"bad security level", func(h *FormCommitHost) { h.SecurityLevel = "auth" }, "security_level"},
		{"v2c with a user", func(h *FormCommitHost) {
			*h = FormCommitHost{Key: "edge", Name: "edge", Address: "192.0.2.254", Version: "2c", CommunityEnv: "C_ENV", UsernameEnv: "U_ENV"}
		}, "username_env does not apply"},
		{"bad version", func(h *FormCommitHost) { h.Version = "1" }, "version"},
		{"bad port", func(h *FormCommitHost) { h.Port = "70000" }, "port"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, _ := ParseForm([]byte(formYAML))
			h := good
			c.edit(&h)
			f.Commit.Hosts[0] = h
			_, err := ApplyForm([]byte(formYAML), f)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	f, _ := ParseForm([]byte(formYAML))
	f.Commit.Hosts[0] = good
	if _, err := ApplyForm([]byte(formYAML), f); err != nil {
		t.Fatalf("a complete v3 host was refused: %v", err)
	}
}

func TestCommitScorerSwitchFromCostToCommit(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	if f.ScorerType != "cost" || f.Precedence == "" {
		t.Fatalf("fixture scorer %q precedence %q", f.ScorerType, f.Precedence)
	}
	// What the Commit setup posts: the cost knobs are cleared with the switch.
	commitRow(&f, "transit-a").BillingDay, commitRow(&f, "transit-a").Percentile = "1", "greater"
	f.Commit.Scorer, f.Commit.Balance = "commit", "equal"
	f.Precedence, f.FloorLossPct, f.FloorRTT = "", "", ""
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	keys := scorerKeys(t, cfg)
	if cfg.Scorer.Type != "commit" || keys["balance"] != "equal" {
		t.Fatalf("scorer = %s %v", cfg.Scorer.Type, keys)
	}
	for _, k := range []string{"precedence", "floor_max_loss_pct", "floor_max_rtt"} {
		if _, left := keys[k]; left {
			t.Fatalf("cost-only key %s survived: %v", k, keys)
		}
	}
}

func TestCommitScorerSwitchDropsOtherScorersKeys(t *testing.T) {
	const yaml = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    cost: 5
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
    cost: 9
scorer:
  type: commit
  config:
    loss_weight: 100
    balance: proportional
    loss_override: true
`
	f, err := ParseForm([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if f.Commit.Balance != "proportional" || f.Commit.Scorer != "" {
		t.Fatalf("commit = %+v", f.Commit)
	}
	f.Commit.Scorer, f.Commit.Balance = "cost", ""
	f.Precedence = "cost"
	out, err := ApplyForm([]byte(yaml), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	keys := scorerKeys(t, cfg)
	if cfg.Scorer.Type != "cost" || keys["precedence"] != "cost" || keys["loss_weight"] == nil {
		t.Fatalf("scorer = %s %v", cfg.Scorer.Type, keys)
	}
	if _, left := keys["balance"]; left {
		t.Fatalf("commit-only key survived: %v", keys)
	}
	if _, left := keys["loss_override"]; left {
		t.Fatalf("commit-only key survived: %v", keys)
	}

	// Back to weighted: the cost knobs are cleared with it, and the form's
	// own precedence field, still "cost" in the form, is no error.
	f, err = ParseForm(out)
	if err != nil {
		t.Fatal(err)
	}
	f.Commit.Scorer, f.Precedence = "weighted", ""
	out, err = ApplyForm(out, f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if keys := scorerKeys(t, cfg); cfg.Scorer.Type != "weighted" || keys["precedence"] != nil {
		t.Fatalf("scorer = %s %v", cfg.Scorer.Type, keys)
	}
}

func TestCommitSectionOmittedLeavesFileAlone(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.Commit = nil
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != formYAML {
		t.Fatalf("file changed:\n%s", out)
	}
}

func TestCommitSetupRefusesACustomScorer(t *testing.T) {
	const yaml = commitBaseYAML + "announcer: {type: gobgp}\n"
	custom := strings.Replace(yaml, "type: weighted", "type: exec", 1)
	f, err := ParseForm([]byte(custom))
	if err != nil {
		t.Fatal(err)
	}
	f.Commit.Scorer = "commit"
	if _, err := ApplyForm([]byte(custom), f); err == nil || !strings.Contains(err.Error(), "scorer type exec") {
		t.Fatalf("err = %v", err)
	}
}

// The loader takes cc_disable as any YAML boolean and percentile in any case,
// so the form must read both the same way. Reading True as false would turn
// commit control back on for that provider on the next Apply.
func TestCommitSetupKeepsFileCase(t *testing.T) {
	src := strings.Replace(formYAML, "    group: edge\n", "    group: edge\n    cc_disable: True\n", 1)
	src = strings.Replace(src, "          commit_mbps: 1000\n", "          commit_mbps: 1000\n          billing_day: 3\n          percentile: Separate\n", 1)
	if src == formYAML || !strings.Contains(src, "cc_disable: True") || !strings.Contains(src, "percentile: Separate") {
		t.Fatal("test file does not carry the mixed-case values")
	}
	if _, err := config.Parse([]byte(src)); err != nil {
		t.Fatalf("loader refuses the file: %v", err)
	}
	f, err := ParseForm([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	r := commitRow(&f, "transit-a")
	if !r.CCDisable || r.Percentile != "separate" {
		t.Fatalf("row = %+v", r)
	}

	r.Group = "core"
	out, err := ApplyForm([]byte(src), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !cfg.Providers[0].CCDisable || cfg.Providers[0].Group != "core" {
		t.Fatalf("provider = %+v\n%s", cfg.Providers[0], out)
	}

	f, _ = ParseForm([]byte(src))
	commitRow(&f, "transit-a").Percentile = "Greater"
	out, err = ApplyForm([]byte(src), f)
	if err != nil {
		t.Fatalf("mixed-case percentile from the form: %v", err)
	}
	if !strings.Contains(string(out), "percentile: greater") {
		t.Fatalf("percentile not stored lower case:\n%s", out)
	}
	if _, err := config.Parse(out); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
}
