package configedit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
)

// applyAndLoad applies edit to the form read from yaml, requires the
// merged text to load with config.Load (the controller's loader), and
// returns the text and the config. The mode must not change: the form
// sections cannot turn inject on.
func applyAndLoad(t *testing.T, yaml string, edit func(*Form)) (string, *config.Config) {
	t.Helper()
	f, err := ParseForm([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	before := f.Mode
	edit(&f)
	out, err := ApplyForm([]byte(yaml), f)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, out)
	}
	if got, _ := ParseForm(out); got.Mode != before {
		t.Fatalf("mode changed from %q to %q", before, got.Mode)
	}
	return string(out), cfg
}

func sourceTypes(cfg *config.Config) []string {
	var out []string
	for _, s := range cfg.Sources {
		out = append(out, s.Type)
	}
	return out
}

func TestFormFlowRoundTrip(t *testing.T) {
	// Add a flow source to a file with none.
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Flows = []FormFlow{{
			Listen: []string{"192.0.2.10:2055"}, Window: "10m", TopN: "50", MaxTargets: "200", TailInterval: "2m",
			MinBytes: "1000000", MinPct: "0.5", AggregateV4: "22", AggregateV6: "56",
			Exclude: []string{"192.0.2.0/25", "2001:db8::/32"},
		}}
	})
	if got := sourceTypes(cfg); len(got) != 1 || got[0] != "flow" {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	back, err := ParseForm([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Flows) != 1 {
		t.Fatalf("flows = %+v\n%s", back.Flows, out)
	}
	fl := back.Flows[0]
	if len(fl.Listen) != 1 || fl.Listen[0] != "192.0.2.10:2055" || fl.Window != "10m" || fl.TopN != "50" ||
		fl.MaxTargets != "200" || fl.TailInterval != "2m" || fl.MinBytes != "1000000" || fl.MinPct != "0.5" ||
		fl.AggregateV4 != "22" || fl.AggregateV6 != "56" || len(fl.Exclude) != 2 {
		t.Fatalf("flow = %+v\n%s", fl, out)
	}
	if strings.Contains(out, "mode: inject") {
		t.Fatalf("inject appeared:\n%s", out)
	}

	// Edit it: two listen addresses (one IPv6), a lower floor, no exclude.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		fl := &f.Flows[0]
		fl.Listen = []string{"192.0.2.10:2055", "[2001:db8::10]:6343"}
		fl.MaxTargets = ""
		fl.TailInterval = ""
		fl.MinPct = "0"
		fl.AggregateV4 = ""
		fl.Exclude = nil
	})
	back, _ = ParseForm([]byte(out2))
	fl = back.Flows[0]
	if len(fl.Listen) != 2 || fl.Listen[1] != "[2001:db8::10]:6343" || fl.MaxTargets != "" ||
		len(fl.Exclude) != 0 || fl.MinPct != "0" || fl.AggregateV4 != "" || fl.AggregateV6 != "56" {
		t.Fatalf("flow after edit = %+v\n%s", fl, out2)
	}

	// Remove it.
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.Flows = []FormFlow{} })
	if len(cfg3.Sources) != 0 || strings.Contains(out3, "type: flow") || strings.Contains(out3, "sources:") {
		t.Fatalf("flow not removed:\n%s", out3)
	}
}

func TestFormFlowKeepsBlocksTheFormDoesNotShow(t *testing.T) {
	in := observeYAML + `sources:
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
  - type: flow
    config:
      listen: 192.0.2.10:2055
      aggregate_v4: 22
      transit:
        customers: [198.51.100.0/24]
        share_pct: 40
`
	out, cfg := applyAndLoad(t, in, func(f *Form) { f.Flows[0].TopN = "25" })
	if !strings.Contains(out, "aggregate_v4: 22") || !strings.Contains(out, "share_pct: 40") || !strings.Contains(out, "top_n: 25") {
		t.Fatalf("hidden keys lost:\n%s", out)
	}
	if got := sourceTypes(cfg); len(got) != 2 || got[0] != "static" || got[1] != "flow" {
		t.Fatalf("sources = %v", got)
	}
	// An unrelated edit leaves the flow source byte-for-byte alone.
	out2, _ := applyAndLoad(t, in, func(f *Form) { f.HoldTime = "20m" })
	if !strings.Contains(out2, "listen: 192.0.2.10:2055") || !strings.Contains(out2, "customers:") {
		t.Fatalf("flow changed:\n%s", out2)
	}
}

const twoFlowsYAML = observeYAML + `sources:
  - type: flow
    name: edge-a
    config:
      listen: 192.0.2.10:2055
      top_n: 10
      transit:
        customers: [198.51.100.0/24]
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
  - type: flow
    name: edge-b
    config:
      listen: 192.0.2.10:2056
      top_n: 20
`

// Every flow source is listed and edited on its own: an edit to the second
// leaves the first, and the source between them, as they were.
func TestFormEditsEverySourceOfAType(t *testing.T) {
	f, err := ParseForm([]byte(twoFlowsYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Flows) != 2 || f.Flows[0].TopN != "10" || f.Flows[1].TopN != "20" || f.Flows[1].Listen[0] != "192.0.2.10:2056" {
		t.Fatalf("flows = %+v", f.Flows)
	}
	out, cfg := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows[1].TopN = "30" })
	if got := sourceTypes(cfg); len(got) != 3 || got[0] != "flow" || got[1] != "static" || got[2] != "flow" {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	back, _ := ParseForm([]byte(out))
	if back.Flows[0].TopN != "10" || back.Flows[1].TopN != "30" || !strings.Contains(out, "customers:") || !strings.Contains(out, "name: edge-b") {
		t.Fatalf("flows after edit = %+v\n%s", back.Flows, out)
	}

	// Remove the first: the second takes its place and keeps its name.
	out2, cfg2 := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows = f.Flows[1:] })
	if got := sourceTypes(cfg2); len(got) != 2 || got[0] != "flow" || got[1] != "static" ||
		strings.Contains(out2, "edge-a") || !strings.Contains(out2, "name: edge-b") {
		t.Fatalf("after remove: %v\n%s", got, out2)
	}

	// Reorder swaps the two flow slots and leaves the static source between.
	out3, cfg3 := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows[0], f.Flows[1] = f.Flows[1], f.Flows[0] })
	back, _ = ParseForm([]byte(out3))
	if got := sourceTypes(cfg3); got[1] != "static" || back.Flows[0].TopN != "20" || back.Flows[1].TopN != "10" ||
		cfg3.Sources[0].Name != "edge-b" || cfg3.Sources[2].Name != "edge-a" {
		t.Fatalf("after reorder: %v %+v\n%s", got, back.Flows, out3)
	}

	// A new one is added after the last.
	out4, cfg4 := applyAndLoad(t, twoFlowsYAML, func(f *Form) {
		f.Flows = append(f.Flows, FormFlow{Listen: []string{"192.0.2.10:2057"}})
	})
	if len(cfg4.Sources) != 4 || cfg4.Sources[3].Type != "flow" || !strings.Contains(out4, "2057") {
		t.Fatalf("after add:\n%s", out4)
	}

	// Two collectors cannot share an address.
	f, _ = ParseForm([]byte(twoFlowsYAML))
	f.Flows[1].Listen = []string{"192.0.2.10:2055"}
	if _, err := ApplyForm([]byte(twoFlowsYAML), f); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("shared listen: %v", err)
	}
}

const twoRulePoliciesYAML = observeYAML + `policies:
  - type: rules
    name: first
    config:
      rules:
        - name: quiet
          action: ignore
          prefixes: [192.0.2.0/24]
  - type: maintenance
    config:
      windows:
        - name: weekly
          providers: [transit-b]
          schedule: "0 2 * * 6"
          duration: 2h
  - type: rules
    name: second
    config:
      rules:
        - name: locals
          action: allow
          providers: [transit-a]
          traffic: local
`

func TestFormEditsEveryRulesPolicy(t *testing.T) {
	f, err := ParseForm([]byte(twoRulePoliciesYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.RulePolicies) != 2 || f.RulePolicies[0].Rules[0].Name != "quiet" || f.RulePolicies[1].Rules[0].Name != "locals" ||
		f.RulePolicies[1].Rules[0].Key != "0" {
		t.Fatalf("policies = %+v", f.RulePolicies)
	}
	out, cfg := applyAndLoad(t, twoRulePoliciesYAML, func(f *Form) {
		f.RulePolicies[1].Rules[0].Providers = []string{"transit-b"}
		f.RulePolicies[1].Rules = append(f.RulePolicies[1].Rules, FormRule{Name: "vips", Action: "vip", Prefixes: []string{"198.51.100.0/24"}})
	})
	back, _ := ParseForm([]byte(out))
	if len(cfg.Policies) != 3 || cfg.Policies[1].Type != "maintenance" ||
		back.RulePolicies[0].Rules[0].Name != "quiet" || len(back.RulePolicies[0].Rules) != 1 ||
		back.RulePolicies[1].Rules[0].Providers[0] != "transit-b" || len(back.RulePolicies[1].Rules) != 2 {
		t.Fatalf("after edit = %+v\n%s", back.RulePolicies, out)
	}

	// Reorder: the chain runs the policies in file order, and maintenance
	// keeps its slot between them.
	out2, cfg2 := applyAndLoad(t, twoRulePoliciesYAML, func(f *Form) {
		f.RulePolicies[0], f.RulePolicies[1] = f.RulePolicies[1], f.RulePolicies[0]
	})
	if len(cfg2.Policies) != 3 || cfg2.Policies[0].Name != "second" || cfg2.Policies[1].Type != "maintenance" || cfg2.Policies[2].Name != "first" {
		t.Fatalf("after reorder: %+v\n%s", cfg2.Policies, out2)
	}

	// Remove the first; the second takes its slot and maintenance stays after it.
	_, cfg3 := applyAndLoad(t, twoRulePoliciesYAML, func(f *Form) { f.RulePolicies = f.RulePolicies[1:] })
	if len(cfg3.Policies) != 2 || cfg3.Policies[0].Name != "second" || cfg3.Policies[1].Type != "maintenance" {
		t.Fatalf("after remove: %+v", cfg3.Policies)
	}

	// Add a third.
	out4, cfg4 := applyAndLoad(t, twoRulePoliciesYAML, func(f *Form) {
		f.RulePolicies = append(f.RulePolicies, FormRulePolicy{Rules: []FormRule{{Name: "x", Action: "ignore", Traffic: "transit"}}})
	})
	if len(cfg4.Policies) != 4 || cfg4.Policies[3].Type != "rules" || !strings.Contains(out4, "name: x") {
		t.Fatalf("after add:\n%s", out4)
	}
}

func TestFormRulePolicyGeoIPDB(t *testing.T) {
	db := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(db, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := func(f *Form) {
		f.RulePolicies = []FormRulePolicy{{GeoIPDB: db, Rules: []FormRule{{Name: "cc", Action: "ignore", Countries: []string{"US"}}}}}
	}
	f, _ := ParseForm([]byte(observeYAML))
	set(&f)
	out, err := ApplyForm([]byte(observeYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	back, _ := ParseForm(out)
	if back.RulePolicies[0].GeoIPDB != db || back.RulePolicies[0].Rules[0].Countries[0] != "US" || !strings.Contains(string(out), "geoip_db: "+db) {
		t.Fatalf("geoip_db not saved:\n%s", out)
	}
	// Clearing the path while a rule lists a country is refused; clearing
	// both removes the key.
	f = back
	f.RulePolicies[0].GeoIPDB = ""
	if _, err := ApplyForm(out, f); err == nil || !strings.Contains(err.Error(), "geoip_db") {
		t.Fatalf("country without geoip_db: %v", err)
	}
	f.RulePolicies[0].Rules[0].Countries = []string{}
	f.RulePolicies[0].Rules[0].Traffic = "local"
	out2, err := ApplyForm(out, f)
	if err != nil || strings.Contains(string(out2), "geoip_db") || strings.Contains(string(out2), "countries") {
		t.Fatalf("%v\n%s", err, out2)
	}
	f.RulePolicies[0].GeoIPDB = "relative/country.mmdb"
	if _, err := ApplyForm(out2, f); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative geoip_db: %v", err)
	}
}

func TestFormRulesRoundTrip(t *testing.T) {
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.RulePolicies = []FormRulePolicy{{Rules: []FormRule{
			{Name: "pin-a", Action: "static", Providers: []string{"transit-a"}, Prefixes: []string{"203.0.113.0/24"}, MaxLossPct: "1", MaxRTT: "150ms"},
			{Name: "no-b", Action: "deny", Providers: []string{"transit-b"}, ASNs: []string{"64500"}},
			{Name: "vips", Action: "vip", Prefixes: []string{"198.51.100.0/24"}},
			{Name: "quiet", Action: "ignore", Prefixes: []string{"192.0.2.0/24"}},
			{Name: "locals", Action: "allow", Providers: []string{"transit-a", "transit-b"}, Traffic: "local"},
		}}}
	})
	if len(cfg.Policies) != 1 || cfg.Policies[0].Type != "rules" {
		t.Fatalf("policies = %+v\n%s", cfg.Policies, out)
	}
	back, err := ParseForm([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	r := back.RulePolicies[0].Rules
	if len(r) != 5 || r[0].Name != "pin-a" || r[0].MaxLossPct != "1" || r[0].MaxRTT != "150ms" || r[0].Providers[0] != "transit-a" ||
		r[1].ASNs[0] != "64500" || r[4].Traffic != "local" || len(r[4].Providers) != 2 || r[2].Key != "2" {
		t.Fatalf("rules = %+v\n%s", r, out)
	}

	// Reorder, edit one, drop one: keys carry the rows' own keys.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		rules := f.RulePolicies[0].Rules
		rules[1].Providers = []string{"transit-a"}
		f.RulePolicies[0].Rules = []FormRule{rules[1], rules[0], rules[4]}
	})
	back, _ = ParseForm([]byte(out2))
	r = back.RulePolicies[0].Rules
	if len(r) != 3 || r[0].Name != "no-b" || r[0].Providers[0] != "transit-a" || r[1].Name != "pin-a" || r[2].Name != "locals" {
		t.Fatalf("rules after edit = %+v\n%s", r, out2)
	}

	// No policies removes it. The loader needs at least one rule in one.
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.RulePolicies = []FormRulePolicy{} })
	if len(cfg3.Policies) != 0 || strings.Contains(out3, "policies:") {
		t.Fatalf("policy not removed:\n%s", out3)
	}
}

func TestFormRulesKeepOtherPolicies(t *testing.T) {
	in := observeYAML + `policies:
  - type: maintenance
    config:
      windows:
        - name: weekly
          providers: [transit-b]
          schedule: "0 2 * * 6"
          duration: 2h
  - type: rules
    config:
      rules:
        - name: quiet
          action: ignore
          prefixes: [192.0.2.0/24]
`
	out, cfg := applyAndLoad(t, in, func(f *Form) {
		p := &f.RulePolicies[0]
		p.Rules = append(p.Rules, FormRule{Name: "vips", Action: "vip", Prefixes: []string{"198.51.100.0/24"}})
	})
	if len(cfg.Policies) != 2 || !strings.Contains(out, "type: maintenance") || !strings.Contains(out, "name: vips") {
		t.Fatalf("policies:\n%s", out)
	}
	// Removing the rules policy keeps the maintenance policy.
	out2, cfg2 := applyAndLoad(t, in, func(f *Form) { f.RulePolicies = []FormRulePolicy{} })
	if len(cfg2.Policies) != 1 || cfg2.Policies[0].Type != "maintenance" || !strings.Contains(out2, "policies:") {
		t.Fatalf("policies after remove:\n%s", out2)
	}
}

func TestFormVIPRoundTrip(t *testing.T) {
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.VIPs = []FormVIP{{
			Interval: "10s", MaxTargets: "50",
			Prefixes: []FormTarget{{Prefix: "203.0.113.0/24", Host: "203.0.113.1"}, {Prefix: "198.51.100.0/24"}},
			ASNs:     []string{"64496", "64497"},
		}}
	})
	if got := sourceTypes(cfg); len(got) != 1 || got[0] != "vip" {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	back, _ := ParseForm([]byte(out))
	v := back.VIPs[0]
	if v.Interval != "10s" || v.MaxTargets != "50" || len(v.Prefixes) != 2 || v.Prefixes[0].Host != "203.0.113.1" ||
		len(v.ASNs) != 2 || v.ASNs[1] != "64497" {
		t.Fatalf("vip = %+v\n%s", v, out)
	}
	// Drop the first prefix and the ASNs; the second row keeps its key.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		f.VIPs[0].Prefixes = f.VIPs[0].Prefixes[1:]
		f.VIPs[0].ASNs = nil
	})
	back, _ = ParseForm([]byte(out2))
	if len(back.VIPs[0].Prefixes) != 1 || back.VIPs[0].Prefixes[0].Prefix != "198.51.100.0/24" || len(back.VIPs[0].ASNs) != 0 || strings.Contains(out2, "asns") {
		t.Fatalf("vip after edit = %+v\n%s", back.VIPs, out2)
	}
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.VIPs = []FormVIP{} })
	if len(cfg3.Sources) != 0 || strings.Contains(out3, "vip") {
		t.Fatalf("vip not removed:\n%s", out3)
	}
}

func TestFormOutageRoundTrip(t *testing.T) {
	// One outage source with every default: it has no config block.
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) { f.Outages = []FormOutage{{}} })
	if got := sourceTypes(cfg); len(got) != 1 || got[0] != "outage" || strings.Contains(out, "config:") {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		o := &f.Outages[0]
		o.MinPrefixes = "5"
		o.Window = "3m"
		o.LossPct = "30"
		o.RTTMs = "250"
		o.Interval = "4s"
		o.MaxTargets = "40"
		o.IgnoreASNs = []string{"64500"}
	})
	back, _ := ParseForm([]byte(out2))
	o := back.Outages[0]
	if o.MinPrefixes != "5" || o.Window != "3m" || o.LossPct != "30" || o.RTTMs != "250" || o.Interval != "4s" ||
		o.MaxTargets != "40" || len(o.IgnoreASNs) != 1 || o.IgnoreASNs[0] != "64500" {
		t.Fatalf("outage = %+v\n%s", o, out2)
	}
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.Outages = []FormOutage{} })
	if len(cfg3.Sources) != 0 || strings.Contains(out3, "outage") {
		t.Fatalf("outage not removed:\n%s", out3)
	}
}

// A request that does not carry the sections (an older client) leaves
// them alone; an unchanged form keeps the bytes.
func TestFormOmittedSectionsAreUntouched(t *testing.T) {
	in := observeYAML + `sources:
  - type: flow
    config:
      listen: 192.0.2.10:2055
  - type: vip
    config:
      interval: 10s
      prefixes:
        - prefix: 203.0.113.0/24
  - type: outage
policies:
  - type: rules
    config:
      rules:
        - action: ignore
          prefixes: [192.0.2.0/24]
`
	f, err := ParseForm([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	same, err := ApplyForm([]byte(in), f)
	if err != nil || string(same) != in {
		t.Fatalf("unchanged form changed the file: %v\n%s", err, same)
	}
	f.Flows, f.RulePolicies, f.VIPs, f.Outages = nil, nil, nil, nil
	f.HoldTime = "20m"
	out, err := ApplyForm([]byte(in), f)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type: flow", "type: vip", "type: outage", "type: rules", "hold_time: 20m"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("lost %q:\n%s", want, out)
		}
	}
	if _, err := config.Parse(out); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestFormSectionErrors(t *testing.T) {
	rp := func(rules ...FormRule) FormRulePolicy { return FormRulePolicy{Rules: rules} }
	base := observeYAML
	for name, tc := range map[string]struct {
		mut  func(*Form)
		want string
	}{
		"flow no listen":  {func(f *Form) { f.Flows = []FormFlow{{}} }, "listen"},
		"flow bad listen": {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{"2055"}}} }, "host:port"},
		"flow host name":  {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{"example.net:2055"}}} }, "IP address"},
		"flow dup listen": {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{"0.0.0.0:2055", "0.0.0.0:2055"}}} }, "duplicate"},
		"flow bad window": {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, Window: "0s"}} }, "flow[0].window"},
		"flow top_n":      {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, TopN: "0"}} }, "flow[0].top_n"},
		"flow min_pct":    {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, MinPct: "101"}} }, "flow[0].min_pct"},
		"flow min_bytes":  {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, MinBytes: "-1"}} }, "flow[0].min_bytes"},
		"flow agg v4":     {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, AggregateV4: "33"}} }, "aggregate_v4"},
		"flow agg v6":     {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, AggregateV6: "0x"}} }, "aggregate_v6"},
		"flow second bad": {func(f *Form) {
			f.Flows = []FormFlow{{Name: "a", Listen: []string{":2055"}}, {Name: "b", Listen: []string{":2056"}, TopN: "0"}}
		}, "flow[1].top_n"},
		"flow exclude":   {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}, Exclude: []string{"192.0.2.1/24"}}} }, "host bits"},
		"flow stale key": {func(f *Form) { f.Flows = []FormFlow{{Key: "3", Listen: []string{":2055"}}} }, "not in the file"},
		"flow key twice": {func(f *Form) {
			f.Flows = []FormFlow{{Key: "0", Name: "a", Listen: []string{":2055"}}, {Key: "0", Name: "b", Listen: []string{":2056"}}}
		}, "not in the file"},
		"flow same name": {func(f *Form) {
			f.Flows = []FormFlow{{Name: "x", Listen: []string{":2055"}}, {Name: "x", Listen: []string{":2056"}}}
		}, "unique name"},
		"flow two unnamed": {func(f *Form) { f.Flows = []FormFlow{{Listen: []string{":2055"}}, {Listen: []string{":2056"}}} }, "unique name"},
		"vip two unnamed": {func(f *Form) {
			v := FormVIP{Interval: "10s", ASNs: []string{"64496"}}
			f.VIPs = []FormVIP{v, v}
		}, "unique name"},
		"outage two unnamed": {func(f *Form) { f.Outages = []FormOutage{{}, {}} }, "unique name"},
		"policy two unnamed": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "ignore", Traffic: "local"}), rp(FormRule{Action: "ignore", Traffic: "local"})}
		}, "unique name"},
		"policy no rules": {func(f *Form) { f.RulePolicies = []FormRulePolicy{{}} }, "at least one rule"},
		"policy country no db": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{{Rules: []FormRule{{Action: "ignore", Countries: []string{"US"}}}}}
		}, "geoip_db"},
		"policy second bad": {func(f *Form) {
			second := rp(FormRule{Action: "steer", Traffic: "local"})
			second.Name = "second"
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "ignore", Traffic: "local"}), second}
		}, "policy[1] rules[0]"},
		"rule bad action": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "steer", Prefixes: []string{"192.0.2.0/24"}})}
		}, "action"},
		"rule unknown provider": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "deny", Providers: []string{"nope"}, Prefixes: []string{"192.0.2.0/24"}})}
		}, "not a provider"},
		"rule deny no provider": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "deny", Prefixes: []string{"192.0.2.0/24"}})}
		}, "at least one provider"},
		"rule static two": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "static", Providers: []string{"transit-a", "transit-b"}, Prefixes: []string{"192.0.2.0/24"}, MaxLossPct: "1"})}
		}, "exactly one"},
		"rule static no loss": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "static", Providers: []string{"transit-a"}, Prefixes: []string{"192.0.2.0/24"}})}
		}, "max_loss_pct"},
		"rule loss on allow": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "allow", Providers: []string{"transit-a"}, Prefixes: []string{"192.0.2.0/24"}, MaxLossPct: "1"})}
		}, "only for static"},
		"rule vip providers": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "vip", Providers: []string{"transit-a"}, Prefixes: []string{"192.0.2.0/24"}})}
		}, "takes no providers"},
		"rule no match": {func(f *Form) { f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "ignore"})} }, "at least one of"},
		"rule bad asn":  {func(f *Form) { f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "ignore", ASNs: []string{"0"}})} }, "AS number"},
		"rule bad country": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{{GeoIPDB: "/etc/packeteer/c.mmdb", Rules: []FormRule{{Action: "ignore", Countries: []string{"USA"}}}}}
		}, "two-letter"},
		"rule bad traffic": {func(f *Form) { f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "ignore", Traffic: "all"})} }, "traffic"},
		"rule bad prefix": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Action: "ignore", Prefixes: []string{"192.0.2.1/24"}})}
		}, "host bits"},
		"rule dup name": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Name: "x", Action: "ignore", Traffic: "local"}, FormRule{Name: "x", Action: "ignore", Traffic: "transit"})}
		}, "duplicate name"},
		"rule stale key": {func(f *Form) {
			f.RulePolicies = []FormRulePolicy{rp(FormRule{Key: "7", Action: "ignore", Traffic: "local"})}
		}, "not in the file"},
		"vip no interval": {func(f *Form) { f.VIPs = []FormVIP{{ASNs: []string{"64496"}}} }, "interval"},
		"vip empty":       {func(f *Form) { f.VIPs = []FormVIP{{Interval: "10s"}} }, "at least one prefix or ASN"},
		"vip default route": {func(f *Form) {
			f.VIPs = []FormVIP{{Interval: "10s", Prefixes: []FormTarget{{Prefix: "0.0.0.0/0"}}}}
		}, "default route"},
		"vip host outside": {func(f *Form) {
			f.VIPs = []FormVIP{{Interval: "10s", Prefixes: []FormTarget{{Prefix: "203.0.113.0/24", Host: "192.0.2.1"}}}}
		}, "inside"},
		"outage min 1":   {func(f *Form) { f.Outages = []FormOutage{{MinPrefixes: "1"}} }, "below 2"},
		"outage loss":    {func(f *Form) { f.Outages = []FormOutage{{LossPct: "200"}} }, "outage[0].loss_pct"},
		"outage rtt":     {func(f *Form) { f.Outages = []FormOutage{{RTTMs: "-3"}} }, "outage[0].rtt_ms"},
		"outage asn dup": {func(f *Form) { f.Outages = []FormOutage{{IgnoreASNs: []string{"64500", "64500"}}} }, "duplicate AS"},
	} {
		f, err := ParseForm([]byte(base))
		if err != nil {
			t.Fatal(err)
		}
		tc.mut(&f)
		out, err := ApplyForm([]byte(base), f)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q (out %q)", name, err, tc.want, out)
		}
	}
}

func TestWizardFlowStep(t *testing.T) {
	in := WizardInput{
		ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{"transit-a", "192.0.2.11", "192.0.2.1"}},
		Prefix:    "198.51.100.0/24",
		Flow:      &WizardFlow{Listen: "192.0.2.10:2055"},
	}
	out, err := Wizard(in)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if cfg.Mode != config.ModeObserve || len(cfg.Allowlist.Prefixes) != 0 || cfg.Announcer != nil {
		t.Fatalf("wizard flow config can announce: %+v", cfg)
	}
	if got := sourceTypes(cfg); len(got) != 2 || got[0] != "static" || got[1] != "flow" {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	for _, want := range []string{"listen: 192.0.2.10:2055", "mode: observe", "exporter", "do not publish"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "mode: inject") || strings.Contains(string(out), "announcer:") {
		t.Fatalf("can announce:\n%s", out)
	}

	// No other probe prefix: the flow source is the only source. An empty
	// host listens on every address.
	in.Prefix = ""
	in.Flow = &WizardFlow{Listen: ":2055"}
	out, err = Wizard(in)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Parse(out)
	if err != nil || len(cfg.Sources) != 1 || cfg.Sources[0].Type != "flow" || cfg.Mode != config.ModeObserve {
		t.Fatalf("flow only: %v\n%s", err, out)
	}
	// IPv6 collector address.
	in.Flow = &WizardFlow{Listen: "[2001:db8::10]:6343"}
	if out, err = Wizard(in); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// Without the step nothing changes: no flow source.
	in.Flow = nil
	out, err = Wizard(in)
	if err != nil || strings.Contains(string(out), "flow") {
		t.Fatalf("no flow step: %v\n%s", err, out)
	}
}

func TestWizardFlowErrors(t *testing.T) {
	good := WizardInput{
		ASN: 64512, RouterID: "192.0.2.10", Edge: "192.0.2.254",
		Providers: []WizardProvider{{"transit-a", "192.0.2.11", "192.0.2.1"}},
	}
	for listen, want := range map[string]string{
		"":                  "host:port",
		"2055":              "host:port",
		"192.0.2.10":        "host:port",
		"192.0.2.10:0":      "port must be 1 to 65535",
		"192.0.2.10:70000":  "port must be 1 to 65535",
		"192.0.2.10:x":      "port must be 1 to 65535",
		"example.net:2055":  "IP address",
		"192.0.2.10:2055\n": "",
	} {
		in := good
		in.Flow = &WizardFlow{Listen: listen}
		_, err := Wizard(in)
		if want == "" {
			// Surrounding whitespace is trimmed, not an error.
			if err != nil {
				t.Errorf("%q: %v", listen, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", listen, err, want)
		}
	}
	// Inject still refused with the flow step present.
	in := good
	in.Flow = &WizardFlow{Listen: "192.0.2.10:2055"}
	in.Mode = "inject"
	if _, err := Wizard(in); err == nil || !strings.Contains(err.Error(), "inject is not a step") {
		t.Fatalf("inject with flow: %v", err)
	}
}
