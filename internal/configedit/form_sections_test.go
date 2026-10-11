package configedit

import (
	"os"
	"path/filepath"
	"reflect"
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
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Flows = []FormFlow{{
			Listen: []string{"192.0.2.10:2055"}, Window: "10m", TopN: "50", MaxTargets: "200", TailInterval: "2m",
			MinBytes: "1000000", MinPct: "0.5", AggregateV4: "22", AggregateV6: "56", Exclude: []string{"192.0.2.0/25", "2001:db8::/32"},
		}}
	})
	if got := sourceTypes(cfg); len(got) != 1 || got[0] != "flow" {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	back, err := ParseForm([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	want := FormFlow{
		Key: "0", Listen: []string{"192.0.2.10:2055"}, Window: "10m", TopN: "50", MaxTargets: "200", TailInterval: "2m",
		MinBytes: "1000000", MinPct: "0.5", AggregateV4: "22", AggregateV6: "56", Exclude: []string{"192.0.2.0/25", "2001:db8::/32"},
	}
	if len(back.Flows) != 1 || !reflect.DeepEqual(back.Flows[0], want) {
		t.Fatalf("flows = %+v\n%s", back.Flows, out)
	}
	if strings.Contains(out, "mode: inject") {
		t.Fatalf("inject appeared:\n%s", out)
	}

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
	fl := back.Flows[0]
	if len(fl.Listen) != 2 || fl.Listen[1] != "[2001:db8::10]:6343" || fl.MaxTargets != "" ||
		len(fl.Exclude) != 0 || fl.MinPct != "0" || fl.AggregateV4 != "" || fl.AggregateV6 != "56" {
		t.Fatalf("flow after edit = %+v\n%s", fl, out2)
	}

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
      transit:
        customers: [198.51.100.0/24]
        share_pct: 40
`
	out, cfg := applyAndLoad(t, in, func(f *Form) { f.Flows[0].TopN = "25"; f.Flows[0].AggregateV4 = "22" })
	if !strings.Contains(out, "aggregate_v4: 22") || !strings.Contains(out, "share_pct: 40") || !strings.Contains(out, "top_n: 25") {
		t.Fatalf("hidden keys lost:\n%s", out)
	}
	if got := sourceTypes(cfg); len(got) != 2 || got[0] != "static" || got[1] != "flow" {
		t.Fatalf("sources = %v", got)
	}
	out2, _ := applyAndLoad(t, in, func(f *Form) { f.HoldTime = "20m" })
	if !strings.Contains(out2, "listen: 192.0.2.10:2055") || !strings.Contains(out2, "customers:") {
		t.Fatalf("flow changed:\n%s", out2)
	}
}

const twoFlowsYAML = observeYAML + `sources:
  - type: flow
    name: flow-a
    config:
      listen: 192.0.2.10:2055
      window: 5m
      transit:
        customers: [198.51.100.0/24]
  - type: static
    config:
      targets:
        - prefix: 198.51.100.0/24
  - type: flow
    name: flow-b
    config:
      listen: 192.0.2.11:6343
      window: 10m
`

// Every flow source is a form entry: editing the second changes only the
// second, and the static source between them keeps its slot.
func TestFormEditsEveryFlowSource(t *testing.T) {
	f, err := ParseForm([]byte(twoFlowsYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Flows) != 2 || f.Flows[0].Key != "0" || f.Flows[1].Key != "1" || f.Flows[1].Listen[0] != "192.0.2.11:6343" {
		t.Fatalf("flows = %+v", f.Flows)
	}
	out, cfg := applyAndLoad(t, twoFlowsYAML, func(f *Form) {
		f.Flows[1].Window = "20m"
		f.Flows[1].AggregateV6 = "64"
	})
	if got := sourceTypes(cfg); !reflect.DeepEqual(got, []string{"flow", "static", "flow"}) {
		t.Fatalf("sources = %v\n%s", got, out)
	}
	back, _ := ParseForm([]byte(out))
	if back.Flows[0].Name != "flow-a" || back.Flows[1].Name != "flow-b" || back.Flows[0].Window != "5m" || back.Flows[1].Window != "20m" || back.Flows[1].AggregateV6 != "64" || !strings.Contains(out, "customers:") {
		t.Fatalf("flows after edit = %+v\n%s", back.Flows, out)
	}

	// Remove the first: the second keeps its settings and the static slot.
	out2, cfg2 := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows = f.Flows[1:] })
	if got := sourceTypes(cfg2); !reflect.DeepEqual(got, []string{"flow", "static"}) || strings.Contains(out2, "192.0.2.10:2055") || !strings.Contains(out2, "192.0.2.11:6343") {
		t.Fatalf("after remove: %v\n%s", got, out2)
	}

	// Add a third, then swap the first two.
	out3, cfg3 := applyAndLoad(t, twoFlowsYAML, func(f *Form) {
		f.Flows = []FormFlow{f.Flows[1], f.Flows[0], {Name: "flow-c", Listen: []string{"192.0.2.12:9995"}}}
	})
	if got := sourceTypes(cfg3); !reflect.DeepEqual(got, []string{"flow", "static", "flow", "flow"}) {
		t.Fatalf("sources = %v\n%s", got, out3)
	}
	back, _ = ParseForm([]byte(out3))
	if back.Flows[0].Listen[0] != "192.0.2.11:6343" || back.Flows[1].Listen[0] != "192.0.2.10:2055" || back.Flows[2].Listen[0] != "192.0.2.12:9995" {
		t.Fatalf("order = %+v\n%s", back.Flows, out3)
	}

	// An empty list removes every flow source; nil leaves them.
	out4, cfg4 := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows = []FormFlow{} })
	if got := sourceTypes(cfg4); !reflect.DeepEqual(got, []string{"static"}) {
		t.Fatalf("sources = %v\n%s", got, out4)
	}
	out5, _ := applyAndLoad(t, twoFlowsYAML, func(f *Form) { f.Flows = nil; f.HoldTime = "20m" })
	if strings.Count(out5, "type: flow") != 2 {
		t.Fatalf("nil flows changed the file:\n%s", out5)
	}
}

func TestFormFlowKeyErrors(t *testing.T) {
	for name, keys := range map[string][]string{"stale": {"0", "5"}, "twice": {"1", "1"}} {
		f, _ := ParseForm([]byte(twoFlowsYAML))
		f.Flows[0].Key, f.Flows[1].Key = keys[0], keys[1]
		if _, err := ApplyForm([]byte(twoFlowsYAML), f); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

const twoPoliciesYAML = observeYAML + `policies:
  - type: rules
    name: rules-a
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
        - name: no-b
          action: deny
          providers: [transit-b]
          asns: [64500]
`

// Two rules policies of the same type are both editable and reorderable;
// the maintenance policy between them keeps its slot.
func TestFormEditsEveryRulesPolicy(t *testing.T) {
	f, _ := ParseForm([]byte(twoPoliciesYAML))
	if len(f.Policies) != 2 || f.Policies[1].Key != "1" || f.Policies[1].Rules[0].Name != "no-b" {
		t.Fatalf("policies = %+v", f.Policies)
	}
	out, cfg := applyAndLoad(t, twoPoliciesYAML, func(f *Form) {
		f.Policies[1].Rules[0].Providers = []string{"transit-a"}
		f.Policies[1].Rules = append(f.Policies[1].Rules, FormRule{Name: "vips", Action: "vip", Prefixes: []string{"198.51.100.0/24"}})
	})
	back, _ := ParseForm([]byte(out))
	if len(cfg.Policies) != 3 || cfg.Policies[1].Type != "maintenance" || len(back.Policies[1].Rules) != 2 ||
		back.Policies[1].Rules[0].Providers[0] != "transit-a" || len(back.Policies[0].Rules) != 1 || back.Policies[0].Rules[0].Name != "quiet" {
		t.Fatalf("policies after edit = %+v\n%s", back.Policies, out)
	}

	out2, cfg2 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) { f.Policies[0], f.Policies[1] = f.Policies[1], f.Policies[0] })
	back, _ = ParseForm([]byte(out2))
	if back.Policies[0].Rules[0].Name != "no-b" || back.Policies[1].Rules[0].Name != "quiet" || cfg2.Policies[1].Type != "maintenance" {
		t.Fatalf("order after swap = %+v\n%s", back.Policies, out2)
	}

	out3, cfg3 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) { f.Policies = f.Policies[:1] })
	if len(cfg3.Policies) != 2 || strings.Contains(out3, "no-b") || !strings.Contains(out3, "type: maintenance") {
		t.Fatalf("policy not removed:\n%s", out3)
	}

	out4, cfg4 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) { f.Policies = []FormRulesPolicy{} })
	if len(cfg4.Policies) != 1 || cfg4.Policies[0].Type != "maintenance" || !strings.Contains(out4, "policies:") {
		t.Fatalf("policies after remove:\n%s", out4)
	}

	out5, cfg5 := applyAndLoad(t, twoPoliciesYAML, func(f *Form) {
		f.Policies = append(f.Policies, FormRulesPolicy{Name: "rules-c", Rules: []FormRule{{Name: "locals", Action: "ignore", Traffic: "local"}}})
	})
	back, _ = ParseForm([]byte(out5))
	if len(cfg5.Policies) != 4 || len(back.Policies) != 3 || back.Policies[2].Rules[0].Name != "locals" {
		t.Fatalf("added policy:\n%s", out5)
	}
}

func TestFormRulesRoundTrip(t *testing.T) {
	out, cfg := applyAndLoad(t, observeYAML, func(f *Form) {
		f.Policies = []FormRulesPolicy{{Rules: []FormRule{
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
}

func TestFormRulesGeoIPDB(t *testing.T) {
	// A fake database is enough to set the path: the form never opens it,
	// and the loader here only decodes config. Rules with countries load
	// through config.Parse (the plugin opens the file at start).
	f, _ := ParseForm([]byte(observeYAML))
	f.Policies = []FormRulesPolicy{{GeoIPDB: "/etc/packeteer/GeoLite2-Country.mmdb", Rules: []FormRule{{Name: "eu", Action: "ignore", Countries: []string{"DE", "FR"}}}}}
	out, err := ApplyForm([]byte(observeYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	back, _ := ParseForm(out)
	p := back.Policies[0]
	if p.GeoIPDB != "/etc/packeteer/GeoLite2-Country.mmdb" || !reflect.DeepEqual(p.Rules[0].Countries, []string{"DE", "FR"}) {
		t.Fatalf("policy = %+v\n%s", p, out)
	}
	if !strings.Contains(string(out), "geoip_db: /etc/packeteer/GeoLite2-Country.mmdb") {
		t.Fatalf("no geoip_db key:\n%s", out)
	}

	// Clearing it while a country rule stays is refused; clearing the
	// country rule too clears the key.
	f2, _ := ParseForm(out)
	f2.Policies[0].GeoIPDB = ""
	if _, err := ApplyForm(out, f2); err == nil || !strings.Contains(err.Error(), "geoip_db is required") {
		t.Fatalf("err = %v", err)
	}
	f3, _ := ParseForm(out)
	f3.Policies[0].GeoIPDB = ""
	f3.Policies[0].Rules[0].Countries = nil
	f3.Policies[0].Rules[0].Traffic = "local"
	out3, err := ApplyForm(out, f3)
	if err != nil || strings.Contains(string(out3), "geoip_db") {
		t.Fatalf("err = %v\n%s", err, out3)
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
		return func(f *Form) { f.Policies = []FormRulesPolicy{{Rules: r}} }
	}
	vip := func(mut func(*FormVIP)) func(*Form) {
		return func(f *Form) {
			v := FormVIP{}
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
		"flow bad window": {flow(func(fl *FormFlow) { fl.Window = "0s" }), "window"},
		"flow top_n":      {flow(func(fl *FormFlow) { fl.TopN = "0" }), "top_n"},
		"flow min_pct":    {flow(func(fl *FormFlow) { fl.MinPct = "101" }), "min_pct"},
		"flow min_bytes":  {flow(func(fl *FormFlow) { fl.MinBytes = "-1" }), "min_bytes"},
		"flow agg v4":     {flow(func(fl *FormFlow) { fl.AggregateV4 = "33" }), "aggregate_v4"},
		"flow agg v6":     {flow(func(fl *FormFlow) { fl.AggregateV6 = "0" }), "aggregate_v6"},
		"flow exclude":    {flow(func(fl *FormFlow) { fl.Exclude = []string{"192.0.2.1/24"} }), "host bits"},
		"flow shared listen": {func(f *Form) {
			f.Flows = []FormFlow{{Name: "a", Listen: []string{"192.0.2.10:2055"}}, {Name: "b", Listen: []string{"192.0.2.10:2055"}}}
		}, "already used"},
		"flow same name": {func(f *Form) {
			f.Flows = []FormFlow{{Name: "x", Listen: []string{":2055"}}, {Name: "x", Listen: []string{":2056"}}}
		}, "unique name"},
		"flow unnamed pair": {func(f *Form) {
			f.Flows = []FormFlow{{Listen: []string{":2055"}}, {Listen: []string{":2056"}}}
		}, "unique name"},
		"policy same name": {func(f *Form) {
			r := []FormRule{{Action: "ignore", Traffic: "local"}}
			f.Policies = []FormRulesPolicy{{Rules: r}, {Rules: r}}
		}, "unique name"},
		"policy no rules": {func(f *Form) { f.Policies = []FormRulesPolicy{{}} }, "at least one rule"},
		"geoip relative": {func(f *Form) {
			f.Policies = []FormRulesPolicy{{GeoIPDB: "geo.mmdb", Rules: []FormRule{{Action: "ignore", Traffic: "local"}}}}
		}, "absolute path"},
		"country no geoip": {rules(FormRule{Action: "ignore", Countries: []string{"DE"}}), "geoip_db is required"},
		"rule bad action":  {rules(FormRule{Action: "steer", Prefixes: []string{"192.0.2.0/24"}}), "action"},
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
		"rule bad country": {rules(FormRule{Action: "ignore", Countries: []string{"USA"}}), "two-letter"},
		"rule bad traffic": {rules(FormRule{Action: "ignore", Traffic: "all"}), "traffic"},
		"rule bad prefix":  {rules(FormRule{Action: "ignore", Prefixes: []string{"192.0.2.1/24"}}), "host bits"},
		"rule dup name": {
			rules(FormRule{Name: "x", Action: "ignore", Traffic: "local"}, FormRule{Name: "x", Action: "ignore", Traffic: "transit"}), "duplicate name"},
		"rule stale key": {rules(FormRule{Key: "7", Action: "ignore", Traffic: "local"}), "not in the file"},
		"policy stale key": {func(f *Form) {
			f.Policies = []FormRulesPolicy{{Key: "3", Rules: []FormRule{{Action: "ignore", Traffic: "local"}}}}
		}, "not in the file"},
		"vip no interval": {vip(func(v *FormVIP) { v.ASNs = []string{"64496"} }), "interval"},
		"vip empty":       {vip(func(v *FormVIP) { v.Interval = "10s" }), "at least one prefix or ASN"},
		"vip default route": {
			vip(func(v *FormVIP) { v.Interval = "10s"; v.Prefixes = []FormTarget{{Prefix: "0.0.0.0/0"}} }), "default route"},
		"vip host outside": {
			vip(func(v *FormVIP) {
				v.Interval = "10s"
				v.Prefixes = []FormTarget{{Prefix: "203.0.113.0/24", Host: "192.0.2.1"}}
			}), "inside"},
		"outage min 1":   {outage(func(o *FormOutage) { o.MinPrefixes = "1" }), "below 2"},
		"outage loss":    {outage(func(o *FormOutage) { o.LossPct = "200" }), "loss_pct"},
		"outage rtt":     {outage(func(o *FormOutage) { o.RTTMs = "-3" }), "rtt_ms"},
		"outage asn dup": {outage(func(o *FormOutage) { o.IgnoreASNs = []string{"64500", "64500"} }), "duplicate AS"},
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
