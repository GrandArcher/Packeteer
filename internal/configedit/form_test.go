package configedit

import (
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

const formYAML = `# keep this comment
mode: observe
asn: 64512
router_id: 192.0.2.10
hold_time: 15m
max_improvements: 50
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    cost: 5
    group: edge
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
    cost: 9
scorer:
  type: cost
  config:
    loss_weight: 100
    precedence: performance
    floor:
      max_loss_pct: 0
      max_rtt: 10ms
sources:
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
          host: 198.51.100.1
          mbps: 10
allowlist:
  prefixes: [198.51.100.0/24]
telemetry:
  - type: snmp
    config:
      hosts:
        - name: edge
          address: 192.0.2.254
          community_env: PACKETEER_SNMP_COMMUNITY
      providers:
        - name: transit-a
          host: edge
          interface: eth0
          commit_mbps: 1000
notifiers:
  - type: smtp
    config:
      password_env: PACKETEER_SMTP_PASSWORD
`

func TestParseFormReadsDecisionFields(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	if f.Mode != "observe" || f.HoldTime != "15m" || f.MaxImprovements != "50" ||
		f.MinLossDeltaPct != "1" || f.MinRTTDeltaMs != "15" || f.Precedence != "performance" ||
		f.ScorerType != "cost" || f.FloorLossPct != "0" || f.FloorRTT != "10ms" {
		t.Fatalf("knobs = %+v", f)
	}
	if len(f.Providers) != 2 || f.Providers[0].Key != "transit-a" || f.Providers[0].Cost != "5" ||
		f.Providers[0].CommitMbps != "1000" || !f.Providers[0].CommitBound || f.Providers[1].CommitBound {
		t.Fatalf("providers = %+v", f.Providers)
	}
	if len(f.Targets) != 1 || f.Targets[0].Prefix != "198.51.100.0/24" || f.Targets[0].Host != "198.51.100.1" {
		t.Fatalf("targets = %+v", f.Targets)
	}
	if len(f.Allowlist) != 1 || f.Allowlist[0] != "198.51.100.0/24" {
		t.Fatalf("allowlist = %+v", f.Allowlist)
	}
	// The form does not carry secrets or env values.
	raw := f.Mode + f.HoldTime + f.Providers[0].Name + f.Providers[0].CommitMbps
	for _, secret := range []string{"PACKETEER_SNMP_COMMUNITY", "PACKETEER_SMTP_PASSWORD", "password", "community"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("form contains %s", secret)
		}
	}
}

func TestApplyUnchangedKeepsBytes(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	// A suggestion's AS and draft flag are not a change.
	f.Providers[0].ASN = "64496"
	f.Providers[0].Draft = true
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != formYAML {
		t.Fatalf("unchanged form rewrote the file:\n%s", out)
	}
}

func TestApplyEditsRowsAndKeepsTheRest(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.HoldTime = "20m"
	f.MaxImprovements = "40"
	f.MinLossDeltaPct = "2"
	f.Precedence = "cost"
	f.FloorLossPct = "1"
	f.FloorRTT = "20ms"
	f.Providers[0].Name = "transit-a"
	f.Providers[0].Cost = "4"
	f.Providers[0].CommitMbps = "2000"
	f.Providers[0].ASN = "64496" // seen on the session; not a provider field
	f.Providers = append(f.Providers, FormProvider{
		Name: "transit-c", SourceIP: "192.0.2.13", NextHop: "192.0.2.3", Draft: true, ASN: "64500",
	})
	f.Targets = append(f.Targets, FormTarget{Prefix: "203.0.113.0/24", Host: "203.0.113.1"})
	f.Allowlist = append(f.Allowlist, "203.0.113.0/24")
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "asn: 64496") || strings.Contains(text, "\nasn:") && strings.Contains(text, "64496") {
		// top-level asn is the operator's ASN, 64512. A suggestion AS must not be written.
	}
	if strings.Contains(text, "64496") || strings.Contains(text, "64500") || strings.Contains(text, "draft") {
		t.Fatalf("suggestion AS or draft was written:\n%s", text)
	}
	if !strings.Contains(text, "keep this comment") {
		t.Fatalf("comment dropped:\n%s", text)
	}
	if !strings.Contains(text, "group: edge") || !strings.Contains(text, "mbps: 10") || !strings.Contains(text, "loss_weight: 100") {
		t.Fatalf("unrelated fields dropped:\n%s", text)
	}
	if !strings.Contains(text, "community_env: PACKETEER_SNMP_COMMUNITY") || !strings.Contains(text, "password_env: PACKETEER_SMTP_PASSWORD") {
		t.Fatalf("env var names dropped:\n%s", text)
	}
	if strings.Contains(text, "graceful") {
		t.Fatalf("apply invented graceful restart:\n%s", text)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, text)
	}
	if cfg.Mode != config.ModeObserve {
		t.Fatalf("mode = %s", cfg.Mode)
	}
	if cfg.HoldTime.String() != "20m0s" || *cfg.MaxImprovements != 40 || cfg.Thresholds.MinLossDeltaPct != 2 {
		t.Fatalf("knobs hold=%s max=%d loss=%v", cfg.HoldTime, *cfg.MaxImprovements, cfg.Thresholds.MinLossDeltaPct)
	}
	if len(cfg.Providers) != 3 || cfg.Providers[0].Name != "transit-a" || cfg.Providers[0].Group != "edge" ||
		cfg.Providers[0].Cost == nil || *cfg.Providers[0].Cost != 4 || cfg.Providers[2].NextHop != "192.0.2.3" {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
	if cfg.Providers[2].SourceIP != "192.0.2.13" {
		t.Fatalf("new provider source = %s", cfg.Providers[2].SourceIP)
	}
	// The new row has no cost and no commit: nothing starts probing it
	// until the operator saves and the process restarts, and it is not announced.
	if cfg.Providers[2].Cost != nil {
		t.Fatalf("draft gained a cost: %v", *cfg.Providers[2].Cost)
	}
	if !strings.Contains(text, "commit_mbps: 2000") || strings.Contains(text, "commit_mbps: 1000") {
		t.Fatalf("commit not updated:\n%s", text)
	}
	if cfg.Scorer == nil || cfg.Scorer.Type != "cost" {
		t.Fatalf("scorer = %+v", cfg.Scorer)
	}
}

func TestApplyRemovesProviderAndRefusesCommitWithoutBinding(t *testing.T) {
	f, err := ParseForm([]byte(formYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.Providers = f.Providers[:1]
	f.Providers[0].CommitMbps = ""
	if _, err := ApplyForm([]byte(formYAML), f); err == nil || !strings.Contains(err.Error(), "commit stays") {
		t.Fatalf("clear commit: %v", err)
	}
	f.Providers[0].CommitMbps = "1000"
	f.Providers = append(f.Providers, FormProvider{Name: "transit-c", SourceIP: "192.0.2.13", NextHop: "192.0.2.3", CommitMbps: "500"})
	if _, err := ApplyForm([]byte(formYAML), f); err == nil || !strings.Contains(err.Error(), "telemetry binding") {
		t.Fatalf("commit without binding: %v", err)
	}
	// Removing transit-b keeps transit-a's exclude and does not announce.
	f.Providers = f.Providers[:1]
	out, err := ApplyForm([]byte(formYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "transit-b") || !strings.Contains(text, "group: edge") || !strings.Contains(text, "mode: observe") {
		t.Fatalf("remove:\n%s", text)
	}
	if strings.Contains(text, "announcer:") || strings.Contains(text, "graceful") {
		t.Fatalf("remove invented announce config: %s", text)
	}
}

func TestApplySwitchesWeightedToCostOnlyWhenAsked(t *testing.T) {
	in := `mode: observe
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
  config:
    loss_weight: 100
`
	f, err := ParseForm([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if f.ScorerType != "weighted" || f.Precedence != "" {
		t.Fatalf("parsed %+v", f)
	}
	out, err := ApplyForm([]byte(in), f)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != in {
		t.Fatalf("untouched weighted scorer changed:\n%s", out)
	}
	f.Precedence = "cost"
	f.FloorLossPct = "1"
	f.FloorRTT = "20ms"
	out, err = ApplyForm([]byte(in), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if cfg.Scorer == nil || cfg.Scorer.Type != "cost" || cfg.Mode != "observe" {
		t.Fatalf("scorer %+v mode %s", cfg.Scorer, cfg.Mode)
	}
	if !strings.Contains(string(out), "loss_weight: 100") || !strings.Contains(string(out), "precedence: cost") {
		t.Fatalf("scorer block:\n%s", out)
	}
}

func TestApplyRefusesReplacingCommitScorer(t *testing.T) {
	in := strings.Replace(formYAML, "type: cost", "type: commit", 1)
	f, err := ParseForm([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	f.Precedence = "cost"
	if _, err := ApplyForm([]byte(in), f); err == nil || !strings.Contains(err.Error(), "commit") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplySuggestModeStaysSuggest(t *testing.T) {
	in := strings.Replace(formYAML, "mode: observe", "mode: suggest", 1)
	f, err := ParseForm([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	f.Providers[1].NextHop = "192.0.2.9"
	out, err := ApplyForm([]byte(in), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != config.ModeSuggest {
		t.Fatalf("mode = %s", cfg.Mode)
	}
}
