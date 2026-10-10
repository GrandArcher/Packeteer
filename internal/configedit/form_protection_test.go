package configedit

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// protectionYAML is an observe file with a flow source, a mitigation
// block, an anomaly detector with one rule, and inbound in suggest.
const protectionYAML = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
bgp:
  neighbors:
    - address: 192.0.2.254
sources:
  - type: flow
    config:
      listen: "192.0.2.10:2055"
mitigation:
  mode: observe
  allowlist: [203.0.113.0/24]
  max_rules: 10
anomaly:
  detector:
    type: baseline
    config:
      sensitivity: 3
  rules:
    - name: udp-flood
      prefixes: [203.0.113.0/24]
      protocols: [udp]
      min_mbps: 100
      action: flowspec_drop
      ttl: 30m
inbound:
  mode: suggest
  prefixes: [198.51.100.0/24]
  performance: {latency_ms: 50}
`

func TestFormInboundRoundTrip(t *testing.T) {
	// The values the form read are the values in the file.
	f, err := ParseForm([]byte(protectionYAML))
	if err != nil {
		t.Fatal(err)
	}
	in := f.Inbound
	if !in.Enabled || in.Mode != "suggest" || !reflect.DeepEqual(in.Prefixes, []string{"198.51.100.0/24"}) ||
		!in.Performance.Enabled || in.Performance.LatencyMs != "50" || in.HasAnnouncer {
		t.Fatalf("inbound read as %+v", in)
	}

	// An unchanged form does not reformat the file.
	same, err := ApplyForm([]byte(protectionYAML), f)
	if err != nil || string(same) != protectionYAML {
		t.Fatalf("unchanged form rewrote the file: %v\n%s", err, same)
	}

	out, cfg := applyAndLoad(t, protectionYAML, func(f *Form) {
		f.Inbound.Mode = "observe"
		f.Inbound.Prefixes = []string{"198.51.100.0/24", "192.0.2.0/25"}
		f.Inbound.LocalPref = "5"
		f.Inbound.ReleasePct = "80"
		f.Inbound.Moderated = []string{"performance"}
		f.Inbound.Performance = FormInboundPerformance{Enabled: true, LossPct: "-1", LatencyMs: "40", MinPrefixes: "4", ReleasePct: "60"}
		f.Inbound.Damping = FormInboundDamping{Confirm: "2m", Backoff: "3", MaxHold: "3h"}
	})
	in2 := cfg.Inbound
	if in2 == nil || in2.Mode != config.ModeObserve || len(in2.Prefixes) != 2 || in2.LocalPref != 5 || in2.ReleasePct != 80 ||
		!reflect.DeepEqual(in2.Moderated, []string{"performance"}) || in2.Performance == nil || in2.Performance.LossPct != -1 ||
		in2.Performance.LatencyMs != 40 || in2.Performance.MinPrefixes != 4 || in2.Damping.Backoff != 3 {
		t.Fatalf("inbound after round trip: %+v\n%s", in2, out)
	}
	if cfg.Mode != config.ModeObserve || cfg.Announcer != nil || len(cfg.Allowlist.Prefixes) != 0 {
		t.Fatalf("inbound edit changed the safety fields: %+v", cfg)
	}
	back, err := ParseForm([]byte(out))
	if err != nil || back.Inbound.Damping.MaxHold != "3h" || back.Inbound.Performance.LossPct != "-1" {
		t.Fatalf("read back = %+v, %v", back.Inbound, err)
	}

	// Damping back to the defaults and no moderated triggers removes both
	// keys; performance stays, because inbound needs it or telemetry.
	out, _ = applyAndLoad(t, out, func(f *Form) {
		f.Inbound.Moderated = []string{}
		f.Inbound.Damping = FormInboundDamping{}
	})
	if strings.Contains(out, "damping") || strings.Contains(out, "moderated") || !strings.Contains(out, "performance") {
		t.Fatalf("keys not removed:\n%s", out)
	}
}

// Removing inbound removes the block, announcer and all. An inbound block
// can also be added to a file that has none.
func TestFormInboundAddAndRemove(t *testing.T) {
	_, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Inbound.Enabled = true
		f.Inbound.Prefixes = []string{"198.51.100.0/24"}
		f.Inbound.Performance = FormInboundPerformance{Enabled: true}
	})
	if cfg.Inbound == nil || cfg.Inbound.Mode != config.ModeObserve || cfg.Inbound.Performance == nil {
		t.Fatalf("inbound not added: %+v", cfg.Inbound)
	}

	withAnn := protectionYAML + "  announcer:\n    type: gobgp\n    config:\n      marker: \"64512:667\"\n"
	f, _ := ParseForm([]byte(withAnn))
	if !f.Inbound.HasAnnouncer {
		t.Fatal("announcer not seen")
	}
	// A form that sends has_announcer false cannot drop it.
	f.Inbound.HasAnnouncer = false
	f.Inbound.ReleasePct = "70"
	out, err := ApplyForm([]byte(withAnn), f)
	if err != nil || !strings.Contains(string(out), "marker:") {
		t.Fatalf("announcer lost: %v\n%s", err, out)
	}
	f.Inbound.Enabled = false
	out, err = ApplyForm([]byte(withAnn), f)
	if err != nil || strings.Contains(string(out), "inbound:") || strings.Contains(string(out), "marker") {
		t.Fatalf("inbound not removed: %v\n%s", err, out)
	}
}

func TestFormAnomalyRulesRoundTrip(t *testing.T) {
	f, err := ParseForm([]byte(protectionYAML))
	if err != nil {
		t.Fatal(err)
	}
	an := f.Anomaly
	if !an.Enabled || an.MitigationMode != "observe" || !reflect.DeepEqual(an.MitigationAllowlist, []string{"203.0.113.0/24"}) || len(an.Rules) != 1 {
		t.Fatalf("anomaly read as %+v", an)
	}
	if r := an.Rules[0]; r.Key != "0" || r.Name != "udp-flood" || r.Action != "flowspec_drop" || r.TTL != "30m" ||
		!reflect.DeepEqual(r.Protocols, []string{"udp"}) || r.MinMbps != "100" {
		t.Fatalf("rule read as %+v", r)
	}
	same, err := ApplyForm([]byte(protectionYAML), f)
	if err != nil || string(same) != protectionYAML {
		t.Fatalf("unchanged form rewrote the file: %v\n%s", err, same)
	}

	out, cfg := applyAndLoad(t, protectionYAML, func(f *Form) {
		f.Anomaly.Rules[0].MinMbps = "250"
		f.Anomaly.Rules = append(f.Anomaly.Rules,
			FormAnomalyRule{Name: "syn", Prefixes: []string{"203.0.113.0/25"}, Protocols: []string{"tcp"}, Action: "flowspec_rate_limit", RateMbps: "50", TTL: "10m"},
			FormAnomalyRule{Name: "rtbh", Prefixes: []string{"203.0.113.128/25"}, Action: "blackhole"})
	})
	rules := cfg.Anomaly.Rules
	if len(rules) != 3 || rules[0].MinMbps != 250 || rules[1].RateMbps != 50 || rules[1].Action != "flowspec_rate_limit" || rules[2].Action != "blackhole" {
		t.Fatalf("rules after round trip: %+v\n%s", rules, out)
	}
	// The detector, mitigation block and the rest are untouched.
	if cfg.Anomaly.Detector == nil || cfg.Anomaly.Detector.Type != "baseline" || cfg.Mitigation.Mode != config.ModeObserve {
		t.Fatalf("anomaly edit changed other blocks: %+v", cfg.Anomaly)
	}

	// Reorder and remove.
	_, cfg = applyAndLoad(t, out, func(f *Form) {
		f.Anomaly.Rules = []FormAnomalyRule{f.Anomaly.Rules[2], f.Anomaly.Rules[0]}
	})
	if r := cfg.Anomaly.Rules; len(r) != 2 || r[0].Name != "rtbh" || r[1].Name != "udp-flood" || r[1].MinMbps != 250 {
		t.Fatalf("reordered rules: %+v", r)
	}
	out2, cfg := applyAndLoad(t, out, func(f *Form) { f.Anomaly.Rules = []FormAnomalyRule{} })
	if len(cfg.Anomaly.Rules) != 0 || strings.Contains(out2, "udp-flood") || cfg.Anomaly.Detector == nil {
		t.Fatalf("rules not removed: %+v\n%s", cfg.Anomaly, out2)
	}
}

func TestFormProtectionErrors(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Form)
		want string
	}{
		{"inbound no prefix", func(f *Form) { f.Inbound.Prefixes = nil }, "at least one prefix"},
		{"inbound host bits", func(f *Form) { f.Inbound.Prefixes = []string{"198.51.100.1/24"} }, "inbound.prefixes"},
		{"inbound inject", func(f *Form) { f.Inbound.Mode = "inject" }, "inbound.mode inject is not a form choice"},
		{"inbound mode", func(f *Form) { f.Inbound.Mode = "turbo" }, "inbound.mode"},
		{"inbound pct", func(f *Form) { f.Inbound.ReleasePct = "150" }, "inbound.release_pct"},
		{"inbound trigger", func(f *Form) { f.Inbound.Moderated = []string{"cost"} }, "inbound.moderated"},
		{"inbound both off", func(f *Form) {
			f.Inbound.Performance = FormInboundPerformance{Enabled: true, LossPct: "-1", LatencyMs: "-1"}
		}, "cannot both be off"},
		{"inbound backoff", func(f *Form) { f.Inbound.Damping.Backoff = "0.5" }, "backoff"},
		{"anomaly no name", func(f *Form) { f.Anomaly.Rules[0].Name = "" }, "name is required"},
		{"anomaly dup", func(f *Form) { f.Anomaly.Rules = append(f.Anomaly.Rules, f.Anomaly.Rules[0]) }, "duplicate name"},
		{"anomaly outside allowlist", func(f *Form) { f.Anomaly.Rules[0].Prefixes = []string{"198.51.100.0/24"} }, "not inside mitigation.allowlist"},
		{"anomaly default route", func(f *Form) { f.Anomaly.Rules[0].Prefixes = []string{"0.0.0.0/0"} }, "every prefix"},
		{"anomaly action", func(f *Form) { f.Anomaly.Rules[0].Action = "nuke" }, "action"},
		{"anomaly drop with rate", func(f *Form) { f.Anomaly.Rules[0].RateMbps = "5" }, "takes no target or rate_mbps"},
		{"anomaly redirect no target", func(f *Form) { f.Anomaly.Rules[0].Action = "redirect" }, "needs a target"},
		{"anomaly protocol", func(f *Form) { f.Anomaly.Rules[0].Protocols = []string{"quic"} }, "protocol"},
		{"anomaly ttl", func(f *Form) { f.Anomaly.Rules[0].TTL = "forever" }, "ttl"},
		{"anomaly stale key", func(f *Form) { f.Anomaly.Rules[0].Key = "7" }, "reload the form"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseForm([]byte(protectionYAML))
			if err != nil {
				t.Fatal(err)
			}
			c.edit(&f)
			_, err = ApplyForm([]byte(protectionYAML), f)
			if !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}

	// Rules need the anomaly block; the form does not create a detector.
	f, _ := ParseForm([]byte(observeYAML))
	if f.Anomaly.Enabled {
		t.Fatal("anomaly reads as enabled")
	}
	f.Anomaly.Rules = []FormAnomalyRule{{Name: "x", Prefixes: []string{"203.0.113.0/24"}, Action: "blackhole"}}
	if _, err := ApplyForm([]byte(observeYAML), f); !errors.Is(err, ErrForm) || !strings.Contains(err.Error(), "anomaly block") {
		t.Fatalf("rules without a detector: %v", err)
	}
	// The display-only fields cannot be forged.
	f, _ = ParseForm([]byte(observeYAML))
	f.Anomaly.Enabled = true
	if out, err := ApplyForm([]byte(observeYAML), f); err != nil || string(out) != observeYAML {
		t.Fatalf("forged enabled changed the file: %v\n%s", err, out)
	}
}

// A form that does not carry the new sections leaves them alone.
func TestFormOmittedProtectionSectionsAreUntouched(t *testing.T) {
	f, _ := ParseForm([]byte(protectionYAML))
	f.Inbound, f.Anomaly = nil, nil
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(protectionYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil || cfg.Inbound == nil || len(cfg.Anomaly.Rules) != 1 || cfg.HoldTime.String() != "20m0s" {
		t.Fatalf("omitted sections lost: %v %+v", err, cfg)
	}
}

// A section the operator did not change is not checked, so a file the
// form does not fully model still lets other fields apply.
func TestFormUnchangedProtectionNotChecked(t *testing.T) {
	odd := strings.Replace(protectionYAML, "prefixes: [203.0.113.0/24]\n      protocols", "prefixes: [198.51.100.0/24]\n      protocols", 1)
	f, err := ParseForm([]byte(odd))
	if err != nil {
		t.Fatal(err)
	}
	f.HoldTime = "20m"
	if _, err := ApplyForm([]byte(odd), f); err != nil {
		t.Fatalf("unchanged section was checked: %v", err)
	}
}

// A save that turns inbound or mitigation inject on needs confirm_inject
// even when the top-level mode was already inject (#131).
func TestInjectOnCoversBlocks(t *testing.T) {
	inj := func(top string, in, mit string) *config.Config {
		c := &config.Config{Mode: top}
		if in != "" {
			c.Inbound = &config.Inbound{Mode: in}
		}
		if mit != "" {
			c.Mitigation = &config.Mitigation{Mode: mit}
		}
		return c
	}
	cases := []struct {
		name      string
		next, cur *config.Config
		want      bool
	}{
		{"observe to observe", inj("observe", "suggest", "observe"), inj("observe", "suggest", "observe"), false},
		{"top-level on", inj("inject", "", ""), inj("observe", "", ""), true},
		{"top-level stays on", inj("inject", "", ""), inj("inject", "", ""), false},
		{"inbound on under inject", inj("inject", "inject", ""), inj("inject", "suggest", ""), true},
		{"inbound stays on", inj("inject", "inject", ""), inj("inject", "inject", ""), false},
		{"mitigation on under inject", inj("inject", "", "inject"), inj("inject", "", "observe"), true},
		{"mitigation block new", inj("inject", "", "inject"), inj("inject", "", ""), true},
		{"unreadable disk", inj("observe", "", "inject"), nil, true},
		{"inject turned off", inj("observe", "observe", "observe"), inj("inject", "inject", "inject"), false},
	}
	for _, c := range cases {
		if got := injectOn(c.next, c.cur); got != c.want {
			t.Errorf("%s: injectOn = %v, want %v", c.name, got, c.want)
		}
	}
}

// Under a file that is already mode inject, a save that turns the inbound
// block's inject on still needs confirm_inject; one that leaves it alone
// does not (#131).
func TestSaveInboundInjectNeedsConfirmation(t *testing.T) {
	const withSuggest = injectYAML + `inbound:
  mode: suggest
  prefixes: [198.51.100.0/24]
  performance: {latency_ms: 50}
  announcer: {type: gobgp}
`
	e, path := editor(t, withSuggest)
	base := Hash([]byte(withSuggest))
	inject := strings.Replace(withSuggest, "mode: suggest", "mode: inject", 1)
	res := e.Check([]byte(inject))
	if !res.Valid || !res.EnablesInject {
		t.Fatalf("check = %+v", res)
	}
	if _, _, err := e.Save([]byte(inject), base, false); !errors.Is(err, ErrConfirmInject) {
		t.Fatalf("unconfirmed inbound inject: %v", err)
	}
	if disk, _ := os.ReadFile(path); string(disk) != withSuggest {
		t.Fatal("file changed")
	}
	// An unrelated edit of the same file does not ask.
	tweak := strings.Replace(withSuggest, "hold_time: 5m", "hold_time: 6m", 1)
	if res := e.Check([]byte(tweak)); !res.Valid || res.EnablesInject {
		t.Fatalf("unrelated edit = %+v", res)
	}
	if _, _, err := e.Save([]byte(inject), base, true); err != nil {
		t.Fatalf("confirmed: %v", err)
	}
}
