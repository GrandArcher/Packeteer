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
		t.Fatalf("bad output:\n%s", out)
	}

	// Edit it: two listen addresses (one IPv6), a lower floor, no exclude,
	// default aggregates.
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

const twoFlowYAML = observeYAML + `sources:
  - type: flow
    config:
      listen: 192.0.2.10:2055
      aggregate_v4: 22
      transit:
        customers: [198.51.100.0/24]
        share_pct: 40
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
  - type: flow
    name: flow-sflow
    config:
      listen: 192.0.2.10:6343
      top_n: 30
`

// Every flow source is its own row; an edit to one leaves the other, the
// static source between them, and the hidden blocks where they are.
func TestFormTwoFlowSources(t *testing.T) {
	f, err := ParseForm([]byte(twoFlowYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Flows) != 2 || f.Flows[0].Key != "0" || f.Flows[1].Key != "2" || f.Flows[1].TopN != "30" || f.Flows[0].AggregateV4 != "22" {
		t.Fatalf("flows = %+v", f.Flows)
	}
	out, cfg := applyAndLoad(t, twoFlowYAML, func(f *Form) {
		f.Flows[1].TopN = "60"
		f.Flows[1].AggregateV6 = "48"
	})
	if got := sourceTypes(cfg); len(got) != 3 || got[0] != "flow" || got[1] != "static" || got[2] != "flow" {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	for _, want := range []string{"listen: 192.0.2.10:2055", "aggregate_v4: 22", "share_pct: 40", "top_n: 60", "aggregate_v6: 48"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "top_n: 30") {
		t.Fatalf("second flow not edited:\n%s", out)
	}
	// Unchanged first source keeps its text exactly.
	first := twoFlowYAML[strings.Index(twoFlowYAML, "  - type: flow"):strings.Index(twoFlowYAML, "  - type: static")]
	if !strings.Contains(out, first) {
		t.Fatalf("first flow rewritten:\n%s", out)
	}

	// Swap them, drop none: the other-type source keeps its slot.
	out2, cfg2 := applyAndLoad(t, twoFlowYAML, func(f *Form) { f.Flows[0], f.Flows[1] = f.Flows[1], f.Flows[0] })
	back, _ := ParseForm([]byte(out2))
	if len(back.Flows) != 2 || back.Flows[0].Listen[0] != "192.0.2.10:6343" || back.Flows[1].Listen[0] != "192.0.2.10:2055" ||
		back.Flows[1].AggregateV4 != "22" || sourceTypes(cfg2)[1] != "static" || !strings.Contains(out2, "share_pct: 40") {
		t.Fatalf("swapped = %+v\n%s", back.Flows, out2)
	}

	// Remove the first, add a third on its own port.
	out3, cfg3 := applyAndLoad(t, twoFlowYAML, func(f *Form) {
		f.Flows = append(f.Flows[1:], FormFlow{Name: "flow-ipfix", Listen: []string{"192.0.2.10:4739"}})
	})
	back, _ = ParseForm([]byte(out3))
	if len(back.Flows) != 2 || back.Flows[0].Listen[0] != "192.0.2.10:6343" || back.Flows[1].Listen[0] != "192.0.2.10:4739" ||
		strings.Contains(out3, "share_pct") || len(cfg3.Sources) != 3 {
		t.Fatalf("after remove and add = %+v\n%s", back.Flows, out3)
	}
}

func TestFormRulesRoundTrip(t *testing.T) {
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Policies = []FormPolicy{{Rules: []FormRule{
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
	r := back.Policies[0].Rules
	if len(r) != 5 || r[0].Name != "pin-a" || r[0].MaxLossPct != "1" || r[0].MaxRTT != "150ms" || r[0].Providers[0] != "transit-a" ||
		r[1].ASNs[0] != "64500" || r[4].Traffic != "local" || len(r[4].Providers) != 2 || r[2].Key != "2" {
		t.Fatalf("rules = %+v\n%s", r, out)
	}

	// Reorder, edit one, drop one: keys carry the rows' own keys.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		rules := f.Policies[0].Rules
		rules[1].Providers = []string{"transit-a"}
		f.Policies[0].Rules = []FormRule{rules[1], rules[0], rules[4]}
	})
	back, _ = ParseForm([]byte(out2))
	r = back.Policies[0].Rules
	if len(r) != 3 || r[0].Name != "no-b" || r[0].Providers[0] != "transit-a" || r[1].Name != "pin-a" || r[2].Name != "locals" {
		t.Fatalf("rules after edit = %+v\n%s", r, out2)
	}

	// No policies removes it. The loader needs at least one rule.
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.Policies = []FormPolicy{} })
	if len(cfg3.Policies) != 0 || strings.Contains(out3, "policies:") {
		t.Fatalf("policy not removed:\n%s", out3)
	}
}

const twoPolicyYAML = observeYAML + `policies:
  - type: rules
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
    name: rules-b
    config:
      rules:
        - name: vips
          action: vip
          prefixes: [198.51.100.0/24]
        - name: nob
          action: deny
          providers: [transit-b]
          asns: [64500]
`

// Two policies of the same type: both editable, the maintenance policy
// between them keeps its place and its keys, and order is the chain order.
func TestFormTwoRulesPolicies(t *testing.T) {
	f, err := ParseForm([]byte(twoPolicyYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Policies) != 2 || f.Policies[0].Key != "0" || f.Policies[1].Key != "2" || len(f.Policies[1].Rules) != 2 {
		t.Fatalf("policies = %+v", f.Policies)
	}
	out, cfg := applyAndLoad(t, twoPolicyYAML, func(f *Form) {
		f.Policies[1].Rules[1].Providers = []string{"transit-a"}
		f.Policies[0].Rules = append(f.Policies[0].Rules, FormRule{Name: "local", Action: "allow", Providers: []string{"transit-a"}, Traffic: "local"})
	})
	if len(cfg.Policies) != 3 || cfg.Policies[1].Type != "maintenance" || !strings.Contains(out, "schedule: \"0 2 * * 6\"") {
		t.Fatalf("policies = %+v\n%s", cfg.Policies, out)
	}
	back, _ := ParseForm([]byte(out))
	if len(back.Policies[0].Rules) != 2 || back.Policies[0].Rules[1].Name != "local" ||
		back.Policies[1].Rules[1].Providers[0] != "transit-a" || back.Policies[1].Rules[0].Name != "vips" {
		t.Fatalf("after edit = %+v\n%s", back.Policies, out)
	}

	// Swap the two policies: the maintenance policy stays in the middle.
	out2, cfg2 := applyAndLoad(t, twoPolicyYAML, func(f *Form) { f.Policies[0], f.Policies[1] = f.Policies[1], f.Policies[0] })
	back, _ = ParseForm([]byte(out2))
	if cfg2.Policies[1].Type != "maintenance" || back.Policies[0].Rules[0].Name != "vips" || back.Policies[1].Rules[0].Name != "quiet" {
		t.Fatalf("swapped = %+v\n%s", back.Policies, out2)
	}

	// Remove the first policy; the second and maintenance stay.
	out3, cfg3 := applyAndLoad(t, twoPolicyYAML, func(f *Form) { f.Policies = f.Policies[1:] })
	if len(cfg3.Policies) != 2 || cfg3.Policies[0].Type != "maintenance" || strings.Contains(out3, "name: quiet") {
		t.Fatalf("after remove:\n%s", out3)
	}
	// Add a third policy: it follows the last rules policy.
	out4, cfg4 := applyAndLoad(t, twoPolicyYAML, func(f *Form) {
		f.Policies = append(f.Policies, FormPolicy{Name: "rules-c", Rules: []FormRule{{Name: "extra", Action: "ignore", Traffic: "transit"}}})
	})
	if len(cfg4.Policies) != 4 || !strings.Contains(out4, "name: extra") || cfg4.Policies[1].Type != "maintenance" {
		t.Fatalf("after add:\n%s", out4)
	}
}

// A country rule sets or points to geoip_db on its policy. The database
// file itself is mounted, never fetched here.
func TestFormGeoIPDB(t *testing.T) {
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Policies = []FormPolicy{{GeoIPDB: "/etc/packeteer/GeoLite2-Country.mmdb",
			Rules: []FormRule{{Name: "de", Action: "ignore", Countries: []string{"DE", "FR"}}}}}
	})
	if len(cfg.Policies) != 1 || !strings.Contains(out, "geoip_db: /etc/packeteer/GeoLite2-Country.mmdb") {
		t.Fatalf("geoip_db not written:\n%s", out)
	}
	back, _ := ParseForm([]byte(out))
	if back.Policies[0].GeoIPDB != "/etc/packeteer/GeoLite2-Country.mmdb" || back.Policies[0].Rules[0].Countries[1] != "FR" {
		t.Fatalf("read back = %+v", back.Policies)
	}
	// Point at another file, then clear it once no rule needs it.
	out2, _ := applyAndLoad(t, out, func(f *Form) { f.Policies[0].GeoIPDB = "/data/country.mmdb" })
	if !strings.Contains(out2, "geoip_db: /data/country.mmdb") || strings.Contains(out2, "GeoLite2") {
		t.Fatalf("geoip_db not changed:\n%s", out2)
	}
	out3, _ := applyAndLoad(t, out2, func(f *Form) {
		f.Policies[0].GeoIPDB = ""
		f.Policies[0].Rules[0].Countries = nil
		f.Policies[0].Rules[0].Traffic = "local"
	})
	if strings.Contains(out3, "geoip_db") {
		t.Fatalf("geoip_db kept:\n%s", out3)
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
		f.Policies[0].Rules = append(f.Policies[0].Rules, FormRule{Name: "vips", Action: "vip", Prefixes: []string{"198.51.100.0/24"}})
	})
	if len(cfg.Policies) != 2 || !strings.Contains(out, "type: maintenance") || !strings.Contains(out, "name: vips") {
		t.Fatalf("policies:\n%s", out)
	}
	// Removing the policy keeps the maintenance policy.
	out2, cfg2 := applyAndLoad(t, in, func(f *Form) { f.Policies = []FormPolicy{} })
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
	// A second vip source is its own row.
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) {
		f.VIPs = append(f.VIPs, FormVIP{Name: "vip-2", Interval: "30s", Prefixes: []FormTarget{{Prefix: "203.0.113.0/24"}}})
	})
	back, _ = ParseForm([]byte(out3))
	if len(cfg3.Sources) != 2 || len(back.VIPs) != 2 || back.VIPs[1].Interval != "30s" || back.VIPs[0].Interval != "10s" {
		t.Fatalf("two vips = %+v\n%s", back.VIPs, out3)
	}
	out4, cfg4 := applyAndLoad(t, out3, func(f *Form) { f.VIPs = []FormVIP{} })
	if len(cfg4.Sources) != 0 || strings.Contains(out4, "vip") {
		t.Fatalf("vip not removed:\n%s", out4)
	}
}

func TestFormOutageRoundTrip(t *testing.T) {
	// Every default: the source has no config block.
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
	f.Flows, f.Policies, f.VIPs, f.Outages = nil, nil, nil, nil
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
	base := observeYAML
	flow := func(mut func(*FormFlow)) func(*Form) {
		return func(f *Form) {
			fl := FormFlow{Listen: []string{":2055"}}
			mut(&fl)
			f.Flows = []FormFlow{fl}
		}
	}
	rules := func(r ...FormRule) func(*Form) {
		return func(f *Form) { f.Policies = []FormPolicy{{Rules: r}} }
	}
	vip := func(mut func(*FormVIP)) func(*Form) {
		return func(f *Form) {
			v := FormVIP{Interval: "10s", ASNs: []string{"64496"}}
			mut(&v)
			f.VIPs = []FormVIP{v}
		}
	}
	outage := func(mut func(*FormOutage)) func(*Form) {
		return func(f *Form) {
			o := FormOutage{}
			mut(&o)
			f.Outages = []FormOutage{o}
		}
	}
	for name, tc := range map[string]struct {
		mut  func(*Form)
		want string
	}{
		"flow no listen":  {flow(func(fl *FormFlow) { fl.Listen = nil }), "listen"},
		"flow bad listen": {flow(func(fl *FormFlow) { fl.Listen = []string{"2055"} }), "host:port"},
		"flow host name":  {flow(func(fl *FormFlow) { fl.Listen = []string{"example.net:2055"} }), "IP address"},
		"flow dup listen": {flow(func(fl *FormFlow) { fl.Listen = []string{"0.0.0.0:2055", "0.0.0.0:2055"} }), "duplicate"},
		"flow dup listen across sources": {func(f *Form) {
			f.Flows = []FormFlow{{Listen: []string{"192.0.2.10:2055"}}, {Name: "b", Listen: []string{"192.0.2.10:2055"}}}
		}, "duplicate"},
		"flow same name": {func(f *Form) {
			f.Flows = []FormFlow{{Listen: []string{":2055"}}, {Listen: []string{":6343"}}}
		}, "give each its own name"},
		"flow name collides with vip": {func(f *Form) {
			f.Flows = []FormFlow{{Name: "x", Listen: []string{":2055"}}}
			f.VIPs = []FormVIP{{Name: "x", Interval: "10s", ASNs: []string{"64496"}}}
		}, "named \"x\""},
		"flow bad name": {flow(func(fl *FormFlow) { fl.Name = "a b" }), "letters, digits"},
		"two rules policies same name": {func(f *Form) {
			r := []FormRule{{Action: "ignore", Traffic: "local"}}
			f.Policies = []FormPolicy{{Rules: r}, {Rules: r}}
		}, "give each its own name"},
		"flow bad window": {flow(func(fl *FormFlow) { fl.Window = "0s" }), "flow.window"},
		"flow top_n":      {flow(func(fl *FormFlow) { fl.TopN = "0" }), "flow.top_n"},
		"flow min_pct":    {flow(func(fl *FormFlow) { fl.MinPct = "101" }), "flow.min_pct"},
		"flow min_bytes":  {flow(func(fl *FormFlow) { fl.MinBytes = "-1" }), "flow.min_bytes"},
		"flow agg v4":     {flow(func(fl *FormFlow) { fl.AggregateV4 = "33" }), "flow.aggregate_v4"},
		"flow agg v6":     {flow(func(fl *FormFlow) { fl.AggregateV6 = "0" }), "flow.aggregate_v6"},
		"flow stale key":  {flow(func(fl *FormFlow) { fl.Key = "3" }), "not in the file"},
		"flow exclude":    {flow(func(fl *FormFlow) { fl.Exclude = []string{"192.0.2.1/24"} }), "host bits"},
		"rule bad action": {rules(FormRule{Action: "steer", Prefixes: []string{"192.0.2.0/24"}}), "action"},
		"rule unknown provider": {
			rules(FormRule{Action: "deny", Providers: []string{"nope"}, Prefixes: []string{"192.0.2.0/24"}}), "not a provider"},
		"rule deny no provider": {rules(FormRule{Action: "deny", Prefixes: []string{"192.0.2.0/24"}}), "at least one provider"},
		"rule static two": {
			rules(FormRule{Action: "static", Providers: []string{"transit-a", "transit-b"}, Prefixes: []string{"192.0.2.0/24"}, MaxLossPct: "1"}), "exactly one"},
		"rule static no loss": {
			rules(FormRule{Action: "static", Providers: []string{"transit-a"}, Prefixes: []string{"192.0.2.0/24"}}), "max_loss_pct"},
		"rule loss on allow": {
			rules(FormRule{Action: "allow", Providers: []string{"transit-a"}, Prefixes: []string{"192.0.2.0/24"}, MaxLossPct: "1"}), "only for static"},
		"rule vip providers": {
			rules(FormRule{Action: "vip", Providers: []string{"transit-a"}, Prefixes: []string{"192.0.2.0/24"}}), "takes no providers"},
		"rule no match":    {rules(FormRule{Action: "ignore"}), "at least one of"},
		"rule bad asn":     {rules(FormRule{Action: "ignore", ASNs: []string{"0"}}), "AS number"},
		"rule bad traffic": {rules(FormRule{Action: "ignore", Traffic: "all"}), "traffic"},
		"rule bad prefix":  {rules(FormRule{Action: "ignore", Prefixes: []string{"192.0.2.1/24"}}), "host bits"},
		"rule dup name": {
			rules(FormRule{Name: "x", Action: "ignore", Traffic: "local"}, FormRule{Name: "x", Action: "ignore", Traffic: "transit"}), "duplicate name"},
		"rule stale key": {rules(FormRule{Key: "7", Action: "ignore", Traffic: "local"}), "not in the file"},
		"rule bad country": {func(f *Form) {
			f.Policies = []FormPolicy{{GeoIPDB: "/etc/packeteer/c.mmdb", Rules: []FormRule{{Action: "ignore", Countries: []string{"USA"}}}}}
		}, "two-letter"},
		"country without geoip_db": {rules(FormRule{Action: "ignore", Countries: []string{"DE"}}), "geoip_db"},
		"geoip_db relative": {func(f *Form) {
			f.Policies = []FormPolicy{{GeoIPDB: "c.mmdb", Rules: []FormRule{{Action: "ignore", Traffic: "local"}}}}
		}, "absolute path"},
		"policy no rules": {func(f *Form) { f.Policies = []FormPolicy{{}} }, "at least one rule"},
		"policy stale key": {func(f *Form) {
			f.Policies = []FormPolicy{{Key: "4", Rules: []FormRule{{Action: "ignore", Traffic: "local"}}}}
		}, "not in the file"},
		"vip no interval":   {vip(func(v *FormVIP) { v.Interval = "" }), "interval"},
		"vip empty":         {vip(func(v *FormVIP) { v.ASNs = nil }), "at least one prefix or ASN"},
		"vip default route": {vip(func(v *FormVIP) { v.Prefixes = []FormTarget{{Prefix: "0.0.0.0/0"}} }), "default route"},
		"vip host outside": {vip(func(v *FormVIP) {
			v.Prefixes = []FormTarget{{Prefix: "203.0.113.0/24", Host: "192.0.2.1"}}
		}), "inside"},
		"vip targets cap":    {vip(func(v *FormVIP) { v.MaxTargets = "100001" }), "vip.max_targets"},
		"outage min cap":     {outage(func(o *FormOutage) { o.MinPrefixes = "100001" }), "outage.min_prefixes"},
		"outage targets cap": {outage(func(o *FormOutage) { o.MaxTargets = "100001" }), "outage.max_targets"},
		"flow top_n cap":     {flow(func(fl *FormFlow) { fl.TopN = "10001" }), "flow.top_n"},
		"flow targets cap":   {flow(func(fl *FormFlow) { fl.MaxTargets = "10001" }), "flow.max_targets"},
		"outage min 1":       {outage(func(o *FormOutage) { o.MinPrefixes = "1" }), "below 2"},
		"outage loss":        {outage(func(o *FormOutage) { o.LossPct = "200" }), "outage.loss_pct"},
		"outage rtt":         {outage(func(o *FormOutage) { o.RTTMs = "-3" }), "outage.rtt_ms"},
		"outage asn dup":     {outage(func(o *FormOutage) { o.IgnoreASNs = []string{"64500", "64500"} }), "duplicate AS"},
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

func TestFormTargetCapsAtLimit(t *testing.T) {
	f, err := ParseForm([]byte(observeYAML))
	if err != nil {
		t.Fatal(err)
	}
	f.VIPs = []FormVIP{{Interval: "10s", ASNs: []string{"64496"}, MaxTargets: "100000"}}
	f.Outages = []FormOutage{{MinPrefixes: "100000", MaxTargets: "100000"}}
	out, err := ApplyForm([]byte(observeYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(out); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"max_targets: 100000", "min_prefixes: 100000"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("lost %q:\n%s", want, out)
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
