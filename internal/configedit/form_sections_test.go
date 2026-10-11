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

func parseForm(t *testing.T, yaml string) Form {
	t.Helper()
	f, err := ParseForm([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return f
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
	fl := parseForm(t, out).Flows
	if len(fl) != 1 || len(fl[0].Listen) != 1 || fl[0].Listen[0] != "192.0.2.10:2055" || fl[0].Window != "10m" || fl[0].TopN != "50" ||
		fl[0].MaxTargets != "200" || fl[0].TailInterval != "2m" || fl[0].MinBytes != "1000000" || fl[0].MinPct != "0.5" ||
		fl[0].AggregateV4 != "22" || fl[0].AggregateV6 != "56" || len(fl[0].Exclude) != 2 {
		t.Fatalf("flows = %+v\n%s", fl, out)
	}
	if !strings.Contains(out, "aggregate_v4: 22") || strings.Contains(out, "mode: inject") {
		t.Fatalf("yaml:\n%s", out)
	}

	// Edit it: two listen addresses (one IPv6), no exclude, aggregates cleared.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		fl := &f.Flows[0]
		fl.Listen = []string{"192.0.2.10:2055", "[2001:db8::10]:6343"}
		fl.MaxTargets, fl.TailInterval, fl.MinPct = "", "", "0"
		fl.AggregateV4, fl.AggregateV6 = "", ""
		fl.Exclude = nil
	})
	back := parseForm(t, out2).Flows[0]
	if len(back.Listen) != 2 || back.Listen[1] != "[2001:db8::10]:6343" || back.MaxTargets != "" ||
		len(back.Exclude) != 0 || back.MinPct != "0" || back.AggregateV4 != "" || strings.Contains(out2, "aggregate") {
		t.Fatalf("flow after edit = %+v\n%s", back, out2)
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
	if fl := parseForm(t, in).Flows; len(fl) != 1 || fl[0].AggregateV4 != "22" || fl[0].Key != "1" {
		t.Fatalf("flows = %+v", fl)
	}
	out, cfg := applyAndLoad(t, in, func(f *Form) { f.Flows[0].TopN = "25" })
	if !strings.Contains(out, "aggregate_v4: 22") || !strings.Contains(out, "share_pct: 40") || !strings.Contains(out, "top_n: 25") {
		t.Fatalf("hidden keys lost:\n%s", out)
	}
	if got := sourceTypes(cfg); len(got) != 2 || got[0] != "static" || got[1] != "flow" {
		t.Fatalf("sources = %v", got)
	}
	// An unrelated edit leaves the flow source alone.
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
      top_n: 20
      transit:
        customers: [198.51.100.0/24]
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
  - type: flow
    name: edge-b
    config:
      listen: 192.0.2.10:6343
      top_n: 30
      aggregate_v4: 23
`

// Every flow source is a row. Editing the second leaves the first and the
// unrelated source in the middle as they are; removing the first keeps the
// second with its own hidden keys; a new third is appended.
func TestFormTwoFlowSources(t *testing.T) {
	f := parseForm(t, twoFlowsYAML)
	if len(f.Flows) != 2 || f.Flows[0].Name != "edge-a" || f.Flows[0].Key != "0" || f.Flows[1].Name != "edge-b" || f.Flows[1].Key != "2" ||
		f.Flows[1].AggregateV4 != "23" || f.Flows[1].Listen[0] != "192.0.2.10:6343" {
		t.Fatalf("flows = %+v", f.Flows)
	}

	out, cfg := applyAndLoad(t, twoFlowsYAML, func(f *Form) {
		f.Flows[1].TopN = "35"
		f.Flows[1].AggregateV4 = "24"
	})
	got := parseForm(t, out).Flows
	if got[0].TopN != "20" || got[1].TopN != "35" || got[1].AggregateV4 != "24" || !strings.Contains(out, "customers:") {
		t.Fatalf("flows after edit = %+v\n%s", got, out)
	}
	if types := sourceTypes(cfg); strings.Join(types, ",") != "flow,static,flow" {
		t.Fatalf("source order = %v", types)
	}

	out2, cfg2 := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows = f.Flows[1:] })
	if strings.Contains(out2, "edge-a") || strings.Contains(out2, "customers:") || !strings.Contains(out2, "aggregate_v4: 23") {
		t.Fatalf("remove first:\n%s", out2)
	}
	if types := sourceTypes(cfg2); strings.Join(types, ",") != "static,flow" {
		t.Fatalf("sources = %v", types)
	}

	out3, cfg3 := applyAndLoad(t, twoFlowsYAML, func(f *Form) {
		f.Flows = append(f.Flows, FormFlow{Name: "edge-c", Listen: []string{"192.0.2.10:9995"}})
	})
	if len(cfg3.Sources) != 4 || parseForm(t, out3).Flows[2].Name != "edge-c" {
		t.Fatalf("add third:\n%s", out3)
	}
}

func TestFormRulesRoundTrip(t *testing.T) {
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Policies = []FormPolicies{{Rules: []FormRule{
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
	r := parseForm(t, out).Policies[0].Rules
	if len(r) != 5 || r[0].Name != "pin-a" || r[0].MaxLossPct != "1" || r[0].MaxRTT != "150ms" || r[0].Providers[0] != "transit-a" ||
		r[1].ASNs[0] != "64500" || r[4].Traffic != "local" || len(r[4].Providers) != 2 || r[2].Key != "2" {
		t.Fatalf("rules = %+v\n%s", r, out)
	}

	// Reorder, edit one, drop one: rows carry their own keys.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		rules := f.Policies[0].Rules
		rules[1].Providers = []string{"transit-a"}
		f.Policies[0].Rules = []FormRule{rules[1], rules[0], rules[4]}
	})
	r = parseForm(t, out2).Policies[0].Rules
	if len(r) != 3 || r[0].Name != "no-b" || r[0].Providers[0] != "transit-a" || r[1].Name != "pin-a" || r[2].Name != "locals" {
		t.Fatalf("rules after edit = %+v\n%s", r, out2)
	}

	// Removing the policy removes it; the loader needs at least one rule.
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.Policies = []FormPolicies{} })
	if len(cfg3.Policies) != 0 || strings.Contains(out3, "policies:") {
		t.Fatalf("policy not removed:\n%s", out3)
	}
}

const twoPoliciesYAML = observeYAML + `policies:
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
        - name: no-b
          action: deny
          providers: [transit-b]
          asns: [64500]
        - name: vips
          action: vip
          prefixes: [198.51.100.0/24]
`

// Each rules policy is its own entry. Reordering swaps them between the
// positions rules policies hold, so the maintenance policy between them
// does not move; removing one keeps the other and the maintenance policy.
func TestFormTwoRulesPolicies(t *testing.T) {
	f := parseForm(t, twoPoliciesYAML)
	if len(f.Policies) != 2 || f.Policies[0].Name != "first" || f.Policies[0].Key != "0" || f.Policies[1].Name != "second" ||
		f.Policies[1].Key != "2" || len(f.Policies[1].Rules) != 2 || f.Policies[1].Rules[1].Key != "1" {
		t.Fatalf("policies = %+v", f.Policies)
	}

	out, cfg := applyAndLoad(t, twoPoliciesYAML, func(f *Form) {
		f.Policies[1].Rules[0].Providers = []string{"transit-a"}
		f.Policies[1].Rules = f.Policies[1].Rules[:1]
		f.Policies[0].Rules = append(f.Policies[0].Rules, FormRule{Name: "locals", Action: "ignore", Traffic: "local"})
	})
	got := parseForm(t, out).Policies
	if len(got[0].Rules) != 2 || got[0].Rules[1].Name != "locals" || len(got[1].Rules) != 1 || got[1].Rules[0].Providers[0] != "transit-a" {
		t.Fatalf("policies after edit = %+v\n%s", got, out)
	}
	if len(cfg.Policies) != 3 || cfg.Policies[1].Type != "maintenance" {
		t.Fatalf("policy order = %+v", cfg.Policies)
	}

	out2, cfg2 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) { f.Policies[0], f.Policies[1] = f.Policies[1], f.Policies[0] })
	got = parseForm(t, out2).Policies
	if got[0].Name != "second" || got[1].Name != "first" || len(got[0].Rules) != 2 {
		t.Fatalf("swap = %+v\n%s", got, out2)
	}
	if cfg2.Policies[0].Name != "second" || cfg2.Policies[1].Type != "maintenance" || cfg2.Policies[2].Name != "first" {
		t.Fatalf("swap file order = %+v", cfg2.Policies)
	}

	out3, cfg3 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) { f.Policies = f.Policies[:1] })
	if len(cfg3.Policies) != 2 || cfg3.Policies[1].Type != "maintenance" || strings.Contains(out3, "second") {
		t.Fatalf("remove second:\n%s", out3)
	}
	out4, cfg4 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) { f.Policies = f.Policies[1:] })
	if len(cfg4.Policies) != 2 || cfg4.Policies[0].Type != "maintenance" || strings.Contains(out4, "quiet") {
		t.Fatalf("remove first:\n%s", out4)
	}

	// Adding a policy keeps the existing ones where they are.
	out5, cfg5 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) {
		f.Policies = append(f.Policies, FormPolicies{Name: "third", Rules: []FormRule{{Name: "x", Action: "ignore", Traffic: "transit"}}})
	})
	if len(cfg5.Policies) != 4 || cfg5.Policies[3].Name != "third" || parseForm(t, out5).Policies[2].Name != "third" {
		t.Fatalf("add third:\n%s", out5)
	}
}

func TestFormRulesGeoIPDB(t *testing.T) {
	out, _ := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Policies = []FormPolicies{{GeoIPDB: "/etc/packeteer/GeoLite2-Country.mmdb", Rules: []FormRule{
			{Name: "de", Action: "ignore", Countries: []string{"DE", "FR"}},
		}}}
	})
	p := parseForm(t, out).Policies[0]
	if p.GeoIPDB != "/etc/packeteer/GeoLite2-Country.mmdb" || len(p.Rules[0].Countries) != 2 || !strings.Contains(out, "geoip_db: /etc/packeteer/GeoLite2-Country.mmdb") {
		t.Fatalf("policy = %+v\n%s", p, out)
	}
	// Clearing the path while a rule still lists countries is refused.
	f := parseForm(t, out)
	f.Policies[0].GeoIPDB = ""
	if _, err := ApplyForm([]byte(out), f); err == nil || !strings.Contains(err.Error(), "geoip_db") {
		t.Fatalf("countries without geoip_db: %v", err)
	}
	f = parseForm(t, out)
	f.Policies[0].Rules[0].Countries = nil
	f.Policies[0].Rules[0].Traffic = "local"
	f.Policies[0].GeoIPDB = ""
	out2, err := ApplyForm([]byte(out), f)
	if err != nil || strings.Contains(string(out2), "geoip_db") {
		t.Fatalf("clear geoip_db: %v\n%s", err, out2)
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
	v := parseForm(t, out).VIPs[0]
	if v.Interval != "10s" || v.MaxTargets != "50" || len(v.Prefixes) != 2 || v.Prefixes[0].Host != "203.0.113.1" ||
		len(v.ASNs) != 2 || v.ASNs[1] != "64497" {
		t.Fatalf("vip = %+v\n%s", v, out)
	}
	// Drop the first prefix and the ASNs; the second row keeps its key.
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		f.VIPs[0].Prefixes = f.VIPs[0].Prefixes[1:]
		f.VIPs[0].ASNs = nil
	})
	v = parseForm(t, out2).VIPs[0]
	if len(v.Prefixes) != 1 || v.Prefixes[0].Prefix != "198.51.100.0/24" || len(v.ASNs) != 0 || strings.Contains(out2, "asns") {
		t.Fatalf("vip after edit = %+v\n%s", v, out2)
	}
	out3, cfg3 := applyAndLoad(t, out2, func(f *Form) { f.VIPs = []FormVIP{} })
	if len(cfg3.Sources) != 0 || strings.Contains(out3, "vip") {
		t.Fatalf("vip not removed:\n%s", out3)
	}
}

func TestFormTwoVIPAndOutageSources(t *testing.T) {
	in := observeYAML + `sources:
  - type: vip
    name: vip-a
    config:
      interval: 10s
      prefixes: [{prefix: 203.0.113.0/24}]
  - type: vip
    name: vip-b
    config:
      interval: 20s
      asns: [64496]
  - type: outage
    name: out-a
    config: {min_prefixes: 4}
  - type: outage
    name: out-b
    config: {min_prefixes: 6, ignore_asns: [64500]}
`
	f := parseForm(t, in)
	if len(f.VIPs) != 2 || len(f.Outages) != 2 || f.VIPs[1].Interval != "20s" || f.Outages[1].IgnoreASNs[0] != "64500" {
		t.Fatalf("form = %+v %+v", f.VIPs, f.Outages)
	}
	out, cfg := applyAndLoad(t, in, func(f *Form) {
		f.VIPs[1].Interval = "30s"
		f.Outages[0].MinPrefixes = "5"
		f.Outages = f.Outages[:1]
	})
	g := parseForm(t, out)
	if g.VIPs[0].Interval != "10s" || g.VIPs[1].Interval != "30s" || len(g.Outages) != 1 || g.Outages[0].MinPrefixes != "5" || len(cfg.Sources) != 3 {
		t.Fatalf("after edit = %+v %+v\n%s", g.VIPs, g.Outages, out)
	}
}

func TestFormOutageRoundTrip(t *testing.T) {
	// One entry with every default: the source has no config block.
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) { f.Outages = []FormOutage{{}} })
	if got := sourceTypes(cfg); len(got) != 1 || got[0] != "outage" || strings.Contains(out, "config:") {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	out2, _ := applyAndLoad(t, out, func(f *Form) {
		f.Outages[0] = FormOutage{Key: f.Outages[0].Key, MinPrefixes: "5", Window: "3m", LossPct: "30", RTTMs: "250", Interval: "4s",
			MaxTargets: "40", IgnoreASNs: []string{"64500"}}
	})
	o := parseForm(t, out2).Outages[0]
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
	f := parseForm(t, in)
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
	flow := func(mut func(*FormFlow)) func(*Form) {
		return func(f *Form) {
			fl := FormFlow{Listen: []string{":2055"}}
			mut(&fl)
			f.Flows = []FormFlow{fl}
		}
	}
	rules := func(r ...FormRule) func(*Form) {
		return func(f *Form) { f.Policies = []FormPolicies{{Rules: r}} }
	}
	vip := func(mut func(*FormVIP)) func(*Form) {
		return func(f *Form) {
			v := FormVIP{Interval: "10s"}
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
	pfx := []string{"192.0.2.0/24"}
	for name, tc := range map[string]struct {
		mut  func(*Form)
		want string
	}{
		"flow no listen":    {flow(func(fl *FormFlow) { fl.Listen = nil }), "flow[0]: at least one listen"},
		"flow bad listen":   {flow(func(fl *FormFlow) { fl.Listen = []string{"2055"} }), "host:port"},
		"flow host name":    {flow(func(fl *FormFlow) { fl.Listen = []string{"example.net:2055"} }), "IP address"},
		"flow dup listen":   {flow(func(fl *FormFlow) { fl.Listen = []string{"0.0.0.0:2055", "0.0.0.0:2055"} }), "already used"},
		"flow bad window":   {flow(func(fl *FormFlow) { fl.Window = "0s" }), "flow[0].window"},
		"flow top_n":        {flow(func(fl *FormFlow) { fl.TopN = "0" }), "flow[0].top_n"},
		"flow min_pct":      {flow(func(fl *FormFlow) { fl.MinPct = "101" }), "flow[0].min_pct"},
		"flow min_bytes":    {flow(func(fl *FormFlow) { fl.MinBytes = "-1" }), "flow[0].min_bytes"},
		"flow aggregate v4": {flow(func(fl *FormFlow) { fl.AggregateV4 = "33" }), "flow[0].aggregate_v4"},
		"flow aggregate v6": {flow(func(fl *FormFlow) { fl.AggregateV6 = "0" }), "flow[0].aggregate_v6"},
		"flow exclude":      {flow(func(fl *FormFlow) { fl.Exclude = []string{"192.0.2.1/24"} }), "host bits"},
		"flow two unnamed": {func(f *Form) {
			f.Flows = []FormFlow{{Listen: []string{":2055"}}, {Listen: []string{":2056"}}}
		}, "unique name"},
		"flow same port across sources": {func(f *Form) {
			f.Flows = []FormFlow{{Name: "a", Listen: []string{"192.0.2.10:2055"}}, {Name: "b", Listen: []string{"192.0.2.10:2055"}}}
		}, "already used by another"},
		"flow name two lines": {flow(func(fl *FormFlow) { fl.Name = "a\nb" }), "one line"},
		"flow stale key": {func(f *Form) {
			f.Flows = []FormFlow{{Key: "9", Listen: []string{":2055"}}}
		}, "not in the file"},
		"rule bad action":       {rules(FormRule{Action: "steer", Prefixes: pfx}), "action"},
		"rule unknown provider": {rules(FormRule{Action: "deny", Providers: []string{"nope"}, Prefixes: pfx}), "not a provider"},
		"rule deny no provider": {rules(FormRule{Action: "deny", Prefixes: pfx}), "at least one provider"},
		"rule static two": {rules(FormRule{Action: "static", Providers: []string{"transit-a", "transit-b"}, Prefixes: pfx, MaxLossPct: "1"}),
			"exactly one"},
		"rule static no loss": {rules(FormRule{Action: "static", Providers: []string{"transit-a"}, Prefixes: pfx}), "max_loss_pct"},
		"rule loss on allow":  {rules(FormRule{Action: "allow", Providers: []string{"transit-a"}, Prefixes: pfx, MaxLossPct: "1"}), "only for static"},
		"rule vip providers":  {rules(FormRule{Action: "vip", Providers: []string{"transit-a"}, Prefixes: pfx}), "takes no providers"},
		"rule no match":       {rules(FormRule{Action: "ignore"}), "at least one of"},
		"rule bad asn":        {rules(FormRule{Action: "ignore", ASNs: []string{"0"}}), "AS number"},
		"rule bad country": {func(f *Form) {
			f.Policies = []FormPolicies{{GeoIPDB: "/etc/packeteer/geo.mmdb", Rules: []FormRule{{Action: "ignore", Countries: []string{"USA"}}}}}
		}, "two-letter"},
		"rule country no db": {rules(FormRule{Action: "ignore", Countries: []string{"DE"}}), "need geoip_db"},
		"geoip relative": {func(f *Form) {
			f.Policies = []FormPolicies{{GeoIPDB: "geo.mmdb", Rules: []FormRule{{Action: "ignore", Traffic: "local"}}}}
		}, "absolute path"},
		"rule bad traffic": {rules(FormRule{Action: "ignore", Traffic: "all"}), "traffic"},
		"rule bad prefix":  {rules(FormRule{Action: "ignore", Prefixes: []string{"192.0.2.1/24"}}), "host bits"},
		"rule dup name": {rules(FormRule{Name: "x", Action: "ignore", Traffic: "local"}, FormRule{Name: "x", Action: "ignore", Traffic: "transit"}),
			"duplicate name"},
		"rule stale key":  {rules(FormRule{Key: "7", Action: "ignore", Traffic: "local"}), "not in the file"},
		"policy no rules": {func(f *Form) { f.Policies = []FormPolicies{{}} }, "at least one rule"},
		"policy two unnamed": {func(f *Form) {
			r := []FormRule{{Action: "ignore", Traffic: "local"}}
			f.Policies = []FormPolicies{{Rules: r}, {Rules: r}}
		}, "unique name"},
		"policy stale key": {func(f *Form) {
			f.Policies = []FormPolicies{{Key: "3", Rules: []FormRule{{Action: "ignore", Traffic: "local"}}}}
		}, "not in the file"},
		"vip no interval":   {vip(func(v *FormVIP) { v.Interval = ""; v.ASNs = []string{"64496"} }), "interval"},
		"vip empty":         {vip(func(v *FormVIP) {}), "at least one prefix or ASN"},
		"vip default route": {vip(func(v *FormVIP) { v.Prefixes = []FormTarget{{Prefix: "0.0.0.0/0"}} }), "default route"},
		"vip host outside": {vip(func(v *FormVIP) {
			v.Prefixes = []FormTarget{{Prefix: "203.0.113.0/24", Host: "192.0.2.1"}}
		}), "inside"},
		"outage min 1":   {outage(func(o *FormOutage) { o.MinPrefixes = "1" }), "below 2"},
		"outage loss":    {outage(func(o *FormOutage) { o.LossPct = "200" }), "outage[0].loss_pct"},
		"outage rtt":     {outage(func(o *FormOutage) { o.RTTMs = "-3" }), "outage[0].rtt_ms"},
		"outage asn dup": {outage(func(o *FormOutage) { o.IgnoreASNs = []string{"64500", "64500"} }), "duplicate AS"},
	} {
		f := parseForm(t, observeYAML)
		tc.mut(&f)
		out, err := ApplyForm([]byte(observeYAML), f)
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
