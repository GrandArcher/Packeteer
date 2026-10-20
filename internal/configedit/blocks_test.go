package configedit

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// blocksYAML has every block of the page filled, with comments and keys the
// form does not know (bgp.next_hops, a webhook's headers and url secret, an
// anomaly rule) that must survive every edit. Documentation addresses and
// ASNs only.
const blocksYAML = `# lab edge
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 200
hold_time: 15m
max_improvements: 50
thresholds: {min_loss_delta_pct: 1, min_rtt_delta_ms: 15}
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
    bmp: prefer
  - name: transit-b
    source_ip: 192.0.2.12
    next_hop: 192.0.2.2
allowlist:
  prefixes: [198.51.100.0/24]
bgp:
  neighbors:
    - address: 192.0.2.254 # the edge
      description: edge
      add_path: true
      providers: [transit-a]
      next_hops:
        transit-b: 192.0.2.3
    - address: 192.0.2.253
      providers: [transit-b]
rib_sources:
  - type: bmp
    config:
      listen: ":11019"
      routers: [192.0.2.254]
scorer:
  type: commit
  config:
    loss_weight: 100 # keep
    balance: equal
sources:
  - type: flow
    config:
      listen: "127.0.0.1:2055"
      problems:
        local: [192.0.2.0/24]
        failure_pct: 25
policies:
  - type: maintenance
    name: windows
    config:
      timezone: UTC
      windows:
        - name: nightly
          providers: [transit-b]
          schedule: "0 2 * * 0"
          duration: 2h
inbound:
  mode: observe
  prefixes: [198.51.100.0/24]
  performance: {}
  announcer:
    type: gobgp
    config:
      marker: "64512:777"
      providers:
        - provider: transit-a
          communities: ["64512:1001"]
          prepend: 2
mitigation:
  mode: observe
  allowlist: [198.51.100.0/24]
  max_rules: 10
anomaly:
  detector:
    type: baseline
    config: {sensitivity: 4}
  rules:
    - name: udp-flood
      prefixes: [198.51.100.0/24]
      action: blackhole
http:
  listen: 127.0.0.1:8080
  config_editor: true
  allow_from: [127.0.0.0/8]
notifiers:
  - type: webhook
    name: chat
    config:
      url: https://hooks.example.test/T000/B000/secret
      timeout: 5s
      headers: {X-Lab: one}
probers:
  - type: tcp
    config:
      port: 443
storage:
  type: sqlite
  config:
    path: /data/history.db
`

// editBlocks parses blocksYAML, lets edit change the form, applies it, and
// returns the text and the loaded config. The text must load.
func editBlocks(t *testing.T, edit func(f *Form)) (string, *config.Config) {
	t.Helper()
	f, err := ParseForm([]byte(blocksYAML))
	if err != nil {
		t.Fatal(err)
	}
	edit(&f)
	out, err := ApplyForm([]byte(blocksYAML), f)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("the merged text does not load: %v\n%s", err, out)
	}
	return string(out), cfg
}

func TestBlocksFixtureLoads(t *testing.T) {
	if _, err := config.Parse([]byte(blocksYAML)); err != nil {
		t.Fatalf("fixture: %v", err)
	}
}

func TestBlocksUnchangedFormWritesNothing(t *testing.T) {
	f, err := ParseForm([]byte(blocksYAML))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ApplyForm([]byte(blocksYAML), f)
	if err != nil || string(out) != blocksYAML {
		t.Fatalf("an unchanged form changed the file: %v\n%s", err, out)
	}
	// Through JSON, as the page sends it.
	again := roundTripJSON(t, f)
	out, err = ApplyForm([]byte(blocksYAML), again)
	if err != nil || string(out) != blocksYAML {
		t.Fatalf("a JSON round trip changed the file: %v\n%s", err, out)
	}
}

func TestBlocksReadEveryBlock(t *testing.T) {
	f, err := ParseForm([]byte(blocksYAML))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range Blocks() {
		if _, ok := f.Blocks[b.ID]; !ok {
			t.Errorf("block %s is not read", b.ID)
		}
	}
	bgp := f.Blocks["bgp"]
	rows := bgp["neighbors"].([]Values)
	if len(rows) != 2 || rows[0]["address"] != "192.0.2.254" || rows[0]["add_path"] != true || rows[1]["_key"] != "1" {
		t.Fatalf("neighbors = %+v", rows)
	}
	if got := f.Blocks["bmp"]["routers"].([]string); len(got) != 1 || got[0] != "192.0.2.254" {
		t.Fatalf("bmp routers = %v", got)
	}
	if f.Blocks["bmp"]["loc_rib"] != true {
		t.Fatalf("loc_rib defaults on: %v", f.Blocks["bmp"]["loc_rib"])
	}
	if f.Blocks["anomaly"]["detector.config.sensitivity"] != "4" || f.Blocks["inbound_announcer"]["config.marker"] != "64512:777" {
		t.Fatalf("dotted keys: %+v %+v", f.Blocks["anomaly"], f.Blocks["inbound_announcer"])
	}
	if f.Blocks["maintenance"]["windows"].([]Values)[0]["duration"] != "2h" {
		t.Fatalf("windows = %+v", f.Blocks["maintenance"])
	}
	if f.Providers[0].BMP != "prefer" {
		t.Fatalf("provider bmp = %q", f.Providers[0].BMP)
	}
	if f.Flows[0].Extra["problems"].(Values)["failure_pct"] != "25" || f.Flows[0].Extra["transit"].(Values) != nil {
		t.Fatalf("flow extra = %+v", f.Flows[0].Extra)
	}
	none, err := ParseForm([]byte(observeYAML))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"bmp", "maintenance", "inbound_announcer", "anomaly", "mitigation"} {
		if none.Blocks[id] != nil {
			t.Errorf("optional block %s reads as present in a file without it", id)
		}
	}
}

func TestBlocksBGPNeighborRows(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		rows := f.Blocks["bgp"]["neighbors"].([]Values)
		rows[0]["description"] = "edge-1"
		rows[0]["port"] = "1179"
		// Reorder, and add one.
		added := Values{"address": "192.0.2.252", "add_path": true, "providers": []string{"transit-a"}}
		f.Blocks["bgp"]["neighbors"] = []Values{rows[1], rows[0], added}
		f.Blocks["bgp"]["as_path"] = "native"
		f.Blocks["bgp"]["listen_port"] = "179"
	})
	n := cfg.BGP.Neighbors
	if len(n) != 3 || n[0].Address != "192.0.2.253" || n[1].Address != "192.0.2.254" || n[2].Address != "192.0.2.252" {
		t.Fatalf("neighbors = %+v", n)
	}
	if n[1].Description != "edge-1" || n[1].Port != 1179 || !n[1].AddPath || n[1].NextHops["transit-b"] != "192.0.2.3" {
		t.Fatalf("edited neighbor lost a key: %+v\n%s", n[1], out)
	}
	if cfg.BGP.ASPath != "native" || cfg.BGP.ListenPort != 179 || !n[2].AddPath {
		t.Fatalf("bgp = %+v", cfg.BGP)
	}
	if !strings.Contains(out, "# lab edge") {
		t.Fatalf("comment lost:\n%s", out)
	}
}

func TestBlocksBGPRemoveKeepsUnknown(t *testing.T) {
	out, _ := editBlocks(t, func(f *Form) {
		rows := f.Blocks["bgp"]["neighbors"].([]Values)
		rows[0]["add_path"] = false
		rows[0]["description"] = ""
		f.Blocks["bgp"]["neighbors"] = rows[:1]
	})
	if strings.Contains(out, "192.0.2.253") || strings.Contains(out, "add_path") || strings.Contains(out, "description") {
		t.Fatalf("removed rows or keys stayed:\n%s", out)
	}
	if !strings.Contains(out, "next_hops:") || !strings.Contains(out, "transit-b: 192.0.2.3") || !strings.Contains(out, "# the edge") {
		t.Fatalf("keys the form does not know were lost:\n%s", out)
	}
}

func TestBlocksBMP(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		f.Blocks["bmp"]["routers"] = []string{"192.0.2.254", "192.0.2.253"}
		f.Blocks["bmp"]["loc_rib"] = false
		f.Blocks["bmp"]["idle_timeout"] = "30s"
		f.Providers[1].BMP = "only"
	})
	if !strings.Contains(out, "loc_rib: false") || !strings.Contains(out, "idle_timeout: 30s") {
		t.Fatalf("bmp:\n%s", out)
	}
	if cfg.Providers[1].BMP != "only" || cfg.Providers[0].BMP != "prefer" {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
	// Back to the default drops the key.
	out2, _ := editBlocks(t, func(f *Form) {
		f.Blocks["bmp"]["loc_rib"] = true
	})
	if strings.Contains(out2, "loc_rib") {
		t.Fatalf("a default true is not written:\n%s", out2)
	}
	// Off removes the entry and the list.
	out3, _ := editBlocks(t, func(f *Form) {
		f.Blocks["bmp"] = nil
		f.Providers[0].BMP = ""
	})
	if strings.Contains(out3, "rib_sources") || strings.Contains(out3, "bmp") {
		t.Fatalf("bmp not removed:\n%s", out3)
	}
}

func TestBlocksScorerKnobs(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		f.Blocks["scorer"]["rtt_weight"] = "2"
		f.Blocks["scorer"]["loss_override"] = true
		f.Blocks["scorer"]["max_age"] = "30m"
	})
	keys := scorerKeys(t, cfg)
	if keys["rtt_weight"] != 2 || keys["loss_override"] != true || keys["max_age"] != "30m" || keys["balance"] != "equal" || keys["loss_weight"] != 100 {
		t.Fatalf("keys = %v\n%s", keys, out)
	}
	if !strings.Contains(out, "loss_weight: 100 # keep") {
		t.Fatalf("an untouched knob lost its comment:\n%s", out)
	}
}

func TestBlocksScorerSwitchDropsOtherKnobs(t *testing.T) {
	// The page still holds the commit knobs when the type is switched.
	out, cfg := editBlocks(t, func(f *Form) {
		f.Blocks["scorer"]["loss_override"] = true
		f.Blocks["scorer"]["min_mbps"] = "5"
		f.Commit.Scorer, f.Commit.Balance = "weighted", ""
	})
	keys := scorerKeys(t, cfg)
	if cfg.Scorer.Type != "weighted" || keys["loss_override"] != nil || keys["min_mbps"] != nil || keys["balance"] != nil || keys["loss_weight"] != 100 {
		t.Fatalf("scorer = %s %v\n%s", cfg.Scorer.Type, keys, out)
	}
}

func TestBlocksScorerKnobsOnNoScorerAddsDefaultType(t *testing.T) {
	const yaml = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
`
	f, _ := ParseForm([]byte(yaml))
	f.Blocks["scorer"]["rtt_weight"] = "3"
	out, err := ApplyForm([]byte(yaml), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil || cfg.Scorer == nil || cfg.Scorer.Type != "weighted" {
		t.Fatalf("scorer = %+v %v\n%s", cfg.Scorer, err, out)
	}
	if keys := scorerKeys(t, cfg); keys["rtt_weight"] != 3 {
		t.Fatalf("keys = %v", keys)
	}
}

func TestBlocksMaintenance(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		w := f.Blocks["maintenance"]["windows"].([]Values)
		w[0]["duration"] = "3h"
		f.Blocks["maintenance"]["windows"] = append(w, Values{
			"name": "one-off", "providers": []string{"transit-a"}, "start": "2026-11-01T01:00:00Z", "end": "2026-11-01T03:00:00Z", "reason": "ticket 1",
		})
	})
	if len(cfg.Policies) != 1 || !strings.Contains(out, "duration: 3h") || !strings.Contains(out, "start: \"2026-11-01T01:00:00Z\"") && !strings.Contains(out, "start: 2026-11-01T01:00:00Z") {
		t.Fatalf("maintenance:\n%s", out)
	}
	if !strings.Contains(out, "name: windows") {
		t.Fatalf("the policy's own name was lost:\n%s", out)
	}
	// Off removes the policy and the list; on again adds a bare entry.
	off, _ := editBlocks(t, func(f *Form) { f.Blocks["maintenance"] = nil })
	if strings.Contains(off, "policies") || strings.Contains(off, "maintenance") {
		t.Fatalf("not removed:\n%s", off)
	}
	const bare = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
`
	f, _ := ParseForm([]byte(bare))
	f.Blocks["maintenance"] = Values{"timezone": "Europe/Berlin", "windows": []Values{{"providers": []string{"transit-a"}, "schedule": "0 3 * * *", "duration": "1h"}}}
	on, err := ApplyForm([]byte(bare), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg2, err := config.Parse(on)
	if err != nil || len(cfg2.Policies) != 1 || cfg2.Policies[0].Type != "maintenance" || !strings.Contains(string(on), "Europe/Berlin") {
		t.Fatalf("on: %v\n%s", err, on)
	}
}

func TestBlocksInboundAnnouncer(t *testing.T) {
	out, _ := editBlocks(t, func(f *Form) {
		rows := f.Blocks["inbound_announcer"]["config.providers"].([]Values)
		rows[0]["prepend"] = "3"
		f.Blocks["inbound_announcer"]["config.providers"] = append(rows, Values{"provider": "transit-b", "communities": []string{"64512:1002"}, "withhold": true})
		f.Blocks["inbound_announcer"]["config.marker"] = "64512:778"
	})
	if !strings.Contains(out, "prepend: 3") || !strings.Contains(out, "withhold: true") || !strings.Contains(out, "64512:778") {
		t.Fatalf("announcer:\n%s", out)
	}
	off, _ := editBlocks(t, func(f *Form) { f.Blocks["inbound_announcer"] = nil })
	if strings.Contains(off, "announcer") || !strings.Contains(off, "performance: {}") {
		t.Fatalf("announcer off:\n%s", off)
	}
}

func TestBlocksAnomalyDetector(t *testing.T) {
	out, _ := editBlocks(t, func(f *Form) {
		f.Blocks["anomaly"]["detector.config.sensitivity"] = "5"
		f.Blocks["anomaly"]["detector.config.min_mbps"] = "20"
		f.Blocks["anomaly"]["interval"] = "30s"
		f.Blocks["anomaly"]["source"] = "flow"
	})
	for _, want := range []string{"sensitivity: 5", "min_mbps: 20", "interval: 30s", "source: flow", "name: udp-flood"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	// Clearing a nested knob removes it and the empty config.
	cleared, _ := editBlocks(t, func(f *Form) { f.Blocks["anomaly"]["detector.config.sensitivity"] = "" })
	if strings.Contains(cleared, "sensitivity") || strings.Contains(cleared, "config: {}") {
		t.Fatalf("not cleared:\n%s", cleared)
	}
	// Off takes the rules with it.
	off, _ := editBlocks(t, func(f *Form) { f.Blocks["anomaly"] = nil })
	if strings.Contains(off, "anomaly") || strings.Contains(off, "udp-flood") {
		t.Fatalf("anomaly off:\n%s", off)
	}
}

func TestBlocksMitigation(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		f.Blocks["mitigation"]["allowlist"] = []string{"198.51.100.0/24", "203.0.113.0/24"}
		f.Blocks["mitigation"]["max_rules"] = "20"
	})
	if cfg.Mitigation == nil || cfg.Mitigation.MaxRules != 20 || len(cfg.Mitigation.Allowlist) != 2 {
		t.Fatalf("mitigation = %+v\n%s", cfg.Mitigation, out)
	}
	// Turning inject on is not a form choice.
	f, _ := ParseForm([]byte(blocksYAML))
	f.Blocks["mitigation"]["mode"] = "inject"
	if _, err := ApplyForm([]byte(blocksYAML), f); err == nil || !strings.Contains(err.Error(), "mitigation.mode") {
		t.Fatalf("mitigation inject: %v", err)
	}
}

func TestBlocksHTTP(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		f.Blocks["http"]["allow_from"] = []string{"127.0.0.0/8", "192.0.2.0/24", "2001:db8::/32"}
		f.Blocks["http"]["listen"] = "localhost:9090"
	})
	if len(cfg.HTTP.AllowFrom) != 3 || *cfg.HTTP.Listen != "localhost:9090" || cfg.HTTP.ConfigEditor == nil || !*cfg.HTTP.ConfigEditor {
		t.Fatalf("http = %+v\n%s", cfg.HTTP, out)
	}
	off, _ := editBlocks(t, func(f *Form) {
		f.Blocks["http"]["allow_from"] = []string{}
		f.Blocks["http"]["config_editor"] = false
	})
	if strings.Contains(off, "allow_from") || strings.Contains(off, "config_editor") {
		t.Fatalf("cleared keys stayed:\n%s", off)
	}
}

func TestBlocksInjectSettings(t *testing.T) {
	const bare = `mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
`
	f, _ := ParseForm([]byte(bare))
	f.Blocks["inject"]["packeteer_community"] = "64512:666"
	f.Blocks["inject"]["local_pref"] = "200"
	f.Blocks["inject"]["announcer"] = Values{"type": "gobgp"}
	out, err := ApplyForm([]byte(bare), f)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(out)
	if err != nil || cfg.PacketeerCommunity != "64512:666" || cfg.LocalPref != 200 || cfg.Announcer == nil || cfg.Mode != config.ModeObserve {
		t.Fatalf("inject settings: %v\n%s", err, out)
	}
	back, _ := ParseForm(out)
	back.Blocks["inject"]["announcer"] = nil
	again, err := ApplyForm(out, back)
	if err != nil || strings.Contains(string(again), "announcer") {
		t.Fatalf("announcer off: %v\n%s", err, again)
	}
}

// TestModeInjectIsAFormChoice (#330): the mode dropdown offers inject. The
// form merges it and the loader refuses it without the checklist.
// TestSaveInjectNeedsConfirmation covers Save without confirm_inject.
func TestModeInjectIsAFormChoice(t *testing.T) {
	f, _ := ParseForm([]byte(blocksYAML))
	f.Mode = "inject"
	out, err := ApplyForm([]byte(blocksYAML), f)
	if err != nil || !strings.Contains(string(out), "mode: inject") {
		t.Fatalf("mode inject: %v\n%s", err, out)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "inject") {
		t.Fatalf("the loader accepted inject without the checklist: %v", err)
	}
	bare, _ := ParseForm([]byte(observeYAML))
	bare.Mode = "inject"
	out, err = ApplyForm([]byte(observeYAML), bare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "inject") {
		t.Fatalf("the loader accepted inject without the checklist: %v", err)
	}
}

func TestFlowExtras(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		e := f.Flows[0].Extra
		e["problems"].(Values)["failure_pct"] = "30"
		e["transit"] = Values{"customers": []string{"203.0.113.0/24"}, "share_pct": "60"}
		e["subranges"] = Values{"bits_v4": "26", "bits_v6": "56", "max_subranges": "4", "max_total": "100"}
	})
	if !strings.Contains(out, "failure_pct: 30") || !strings.Contains(out, "share_pct: 60") || !strings.Contains(out, "bits_v4: 26") {
		t.Fatalf("flow extras:\n%s", out)
	}
	if len(cfg.Sources) != 1 {
		t.Fatalf("sources = %d", len(cfg.Sources))
	}
	off, _ := editBlocks(t, func(f *Form) { f.Flows[0].Extra["problems"] = Values(nil) })
	if strings.Contains(off, "problems") || !strings.Contains(off, "listen:") {
		t.Fatalf("problems off:\n%s", off)
	}
	// A request that leaves Extra out keeps the blocks.
	f, _ := ParseForm([]byte(blocksYAML))
	f.Flows[0].Extra = nil
	f.Flows[0].Window = "10m"
	kept, err := ApplyForm([]byte(blocksYAML), f)
	if err != nil || !strings.Contains(string(kept), "failure_pct: 25") || !strings.Contains(string(kept), "window: 10m") {
		t.Fatalf("an old client dropped the blocks: %v\n%s", err, kept)
	}
	// A new source starts with none.
	nf, _ := ParseForm([]byte(blocksYAML))
	nf.Flows = append(nf.Flows, FormFlow{Name: "flow-b", Listen: []string{"127.0.0.1:2056"}})
	added, err := ApplyForm([]byte(blocksYAML), nf)
	if err != nil || strings.Count(string(added), "problems:") != 1 {
		t.Fatalf("new source: %v\n%s", err, added)
	}
}

func TestBlocksPluginsKeepUnknownAndSecrets(t *testing.T) {
	f, err := ParseForm([]byte(blocksYAML))
	if err != nil {
		t.Fatal(err)
	}
	var hook *FormPlugin
	for i := range f.Plugins {
		if f.Plugins[i].Type == "webhook" {
			hook = &f.Plugins[i]
		}
	}
	if hook == nil || hook.List != "notifiers" || hook.Name != "chat" || !hook.Enabled {
		t.Fatalf("plugins = %+v", f.Plugins)
	}
	kinds := map[string]FormSetting{}
	for _, s := range hook.Settings {
		kinds[s.Key] = s
	}
	if kinds["url"].Kind != settingHidden || kinds["url"].Value != "" || kinds["headers"].Kind != settingNested || kinds["timeout"].Value != "5s" {
		t.Fatalf("settings = %+v", hook.Settings)
	}
	for _, p := range f.Plugins {
		for _, s := range p.Settings {
			if strings.Contains(s.Value, "secret") {
				t.Fatalf("a secret reached the form: %+v", s)
			}
		}
	}
	for i := range hook.Settings {
		if hook.Settings[i].Key == "timeout" {
			hook.Settings[i].Value = "10s"
		}
	}
	hook.Settings = append(hook.Settings, FormSetting{Key: "preset", Value: "slack"})
	out, err := ApplyForm([]byte(blocksYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "timeout: 10s") || !strings.Contains(text, "preset: slack") || !strings.Contains(text, "hooks.example.test/T000/B000/secret") ||
		!strings.Contains(text, "X-Lab: one") {
		t.Fatalf("webhook:\n%s", text)
	}
}

func TestBlocksPluginsToggleAddAndRefuse(t *testing.T) {
	f, _ := ParseForm([]byte(blocksYAML))
	for i := range f.Plugins {
		if f.Plugins[i].Type == "webhook" {
			f.Plugins[i].Enabled = false
		}
	}
	f.Plugins = append(f.Plugins, FormPlugin{List: "probers", Type: "udp", Enabled: true, Settings: []FormSetting{{Key: "port", Value: "33434"}}})
	out, err := ApplyForm([]byte(blocksYAML), f)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if strings.Contains(text, "notifiers") || strings.Contains(text, "webhook") || !strings.Contains(text, "type: udp") || !strings.Contains(text, "port: 33434") ||
		!strings.Contains(text, "type: tcp") {
		t.Fatalf("plugins:\n%s", text)
	}
	cases := []struct {
		name string
		edit func(f *Form)
		want string
	}{
		{"a secret value in a plain key", func(f *Form) {
			f.Plugins = append(f.Plugins, FormPlugin{List: "notifiers", Type: "smtp", Enabled: true, Settings: []FormSetting{{Key: "password", Value: "hunter2"}}})
		}, "may hold a secret. Secrets stay in environment variables: use a password_env key"},
		{"a literal url", func(f *Form) {
			f.Plugins = append(f.Plugins, FormPlugin{List: "notifiers", Type: "webhook", Enabled: true, Settings: []FormSetting{{Key: "url", Value: "https://hooks.example.test/x"}}})
		}, "take the value from a ${VAR} reference, or use a url_env key"},
		{"an exec plugin", func(f *Form) { f.Plugins = append(f.Plugins, FormPlugin{List: "probers", Type: "exec", Enabled: true}) }, "raw YAML"},
		{"a type change", func(f *Form) { f.Plugins[0].Type = "udp" }, "cannot change"},
		{"a policy another card owns", func(f *Form) {
			f.Plugins = append(f.Plugins, FormPlugin{List: "policies", Type: "maintenance", Enabled: true})
		}, "edited in its own section"},
		{"a bad key", func(f *Form) {
			f.Plugins = append(f.Plugins, FormPlugin{List: "probers", Type: "udp", Enabled: true, Settings: []FormSetting{{Key: "Bad Key", Value: "1"}}})
		}, "lowercase"},
		{"a bad list", func(f *Form) { f.Plugins = append(f.Plugins, FormPlugin{List: "scorer", Type: "x", Enabled: true}) }, "not a plugin list"},
		{"a number that is not", func(f *Form) {
			f.Plugins = append(f.Plugins, FormPlugin{List: "probers", Type: "udp", Enabled: true, Settings: []FormSetting{{Key: "port", Kind: "int", Value: "x"}}})
		}, "whole number"},
		{"a second storage", func(f *Form) {
			f.Plugins = append(f.Plugins, FormPlugin{List: "storage", Type: "sqlite", Enabled: true})
		}, "storage takes one"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, _ := ParseForm([]byte(blocksYAML))
			c.edit(&f)
			if _, err := ApplyForm([]byte(blocksYAML), f); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// Turning the storage plugin off and adding another in one Apply leaves
// only the new one. Removing the old entry used to delete the storage key
// the new entry had just been written to.
func TestBlocksPluginsReplaceStorage(t *testing.T) {
	out, cfg := editBlocks(t, func(f *Form) {
		for i := range f.Plugins {
			if f.Plugins[i].List == "storage" {
				f.Plugins[i].Enabled = false
			}
		}
		f.Plugins = append(f.Plugins, FormPlugin{List: "storage", Type: "sqlite", Enabled: true, Settings: []FormSetting{{Key: "path", Value: "/data/new.db"}}})
	})
	if strings.Count(out, "storage:") != 1 || strings.Contains(out, "history.db") || !strings.Contains(out, "path: /data/new.db") ||
		cfg.Storage == nil || cfg.Storage.Type != "sqlite" {
		t.Fatalf("storage = %+v\n%s", cfg.Storage, out)
	}
	back := mustParse(t, out)
	var storage []FormPlugin
	for _, p := range back.Plugins {
		if p.List == "storage" {
			storage = append(storage, p)
		}
	}
	if len(storage) != 1 || len(storage[0].Settings) != 1 || storage[0].Settings[0] != (FormSetting{Key: "path", Value: "/data/new.db", Kind: settingString}) {
		t.Fatalf("storage rows = %+v", storage)
	}
}

// One Apply that removes entries from a list and adds others, or turns on
// two parts of the file that share a key, keeps what it adds.
func TestFormRemoveAndAddInOneApply(t *testing.T) {
	const telemetryYAML = observeYAML + `telemetry:
  - type: snmp
    config:
      hosts:
        - name: edge
          address: 192.0.2.254
          community_env: PACKETEER_SNMP_COMMUNITY
  - type: fixed
    name: one
`
	const sourcesYAML = observeYAML + `sources:
  - type: flow
    config:
      listen: 192.0.2.10:2055
  - type: traceroute
`
	off := func(f *Form, typ string) {
		for i := range f.Plugins {
			if f.Plugins[i].Type == typ {
				f.Plugins[i].Enabled = false
			}
		}
	}
	cases := []struct {
		name  string
		in    string
		edit  func(f *Form)
		check func(cfg *config.Config) bool
	}{
		{"probers and notifiers", blocksYAML, func(f *Form) {
			off(f, "tcp")
			off(f, "webhook")
			f.Plugins = append(f.Plugins,
				FormPlugin{List: "probers", Type: "udp", Enabled: true},
				FormPlugin{List: "notifiers", Type: "webhook", Name: "new", Enabled: true, Settings: []FormSetting{{Key: "url_env", Value: "PACKETEER_HOOK"}}})
		}, func(cfg *config.Config) bool {
			return len(cfg.Probers) == 1 && cfg.Probers[0].Type == "udp" && len(cfg.Notifiers) == 1 && cfg.Notifiers[0].Name == "new"
		}},
		{"sources from two sections", sourcesYAML, func(f *Form) {
			f.Flows = []FormFlow{}
			f.VIPs = append(f.VIPs, FormVIP{Interval: "30s", Prefixes: []FormTarget{{Prefix: "203.0.113.0/24"}}})
			off(f, "traceroute")
			f.Plugins = append(f.Plugins, FormPlugin{List: "sources", Type: "span", Enabled: true})
		}, func(cfg *config.Config) bool { return slices.Equal(sourceTypes(cfg), []string{"vip", "span"}) }},
		{"telemetry with the last snmp host gone", telemetryYAML, func(f *Form) {
			f.Commit.Hosts = []FormCommitHost{}
			off(f, "fixed")
			f.Plugins = append(f.Plugins, FormPlugin{List: "telemetry", Type: "fixed", Name: "two", Enabled: true})
		}, func(cfg *config.Config) bool {
			return len(cfg.Telemetry) == 1 && cfg.Telemetry[0].Type == "fixed" && cfg.Telemetry[0].Name == "two"
		}},
		{"maintenance off and the rules policy replaced", maintenanceFirstYAML, func(f *Form) {
			f.Blocks["maintenance"] = nil
			f.Policies = []FormPolicy{{Rules: []FormRule{{Name: "new", Action: "ignore", Prefixes: []string{"192.0.2.0/24"}}}}}
		}, func(cfg *config.Config) bool {
			return len(cfg.Policies) == 1 && cfg.Policies[0].Type == "rules"
		}},
		{"inbound and its announcer on together", observeYAML, func(f *Form) {
			f.Inbound = &FormInbound{Enabled: true, Mode: "observe", Prefixes: []string{"198.51.100.0/24"}, Performance: FormInboundPerformance{Enabled: true}}
			f.Blocks["inbound_announcer"] = Values{"type": "gobgp", "config.marker": "64512:667"}
		}, func(cfg *config.Config) bool {
			return cfg.Inbound != nil && cfg.Inbound.Announcer != nil && cfg.Inbound.Announcer.Type == "gobgp"
		}},
		{"anomaly detector and rules on together", observeYAML, func(f *Form) {
			f.Blocks["mitigation"] = Values{"mode": "observe", "allowlist": []string{"198.51.100.0/24"}}
			f.Blocks["anomaly"] = Values{"detector.type": "baseline"}
			f.Anomaly.Rules = []FormAnomalyRule{{Name: "flood", Prefixes: []string{"198.51.100.0/24"}, Action: "blackhole"}}
		}, func(cfg *config.Config) bool {
			return cfg.Anomaly != nil && len(cfg.Anomaly.Rules) == 1 && cfg.Anomaly.Rules[0].Name == "flood"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, cfg := applyAndLoad(t, c.in, c.edit)
			if !c.check(cfg) {
				t.Fatalf("merged:\n%s", out)
			}
		})
	}
}

// An exec plugin in the file is shown and can be left alone, but the form
// does not rewrite it: its command runs a program.
func TestBlocksPluginsExecIsReadOnly(t *testing.T) {
	const withExec = `probers:
  - type: exec
    config:
      command: /usr/local/bin/probe
  - type: tcp
    config:
      port: 443
`
	text := strings.Replace(blocksYAML, "probers:\n  - type: tcp\n    config:\n      port: 443\n", withExec, 1)
	f, err := ParseForm([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyForm([]byte(text), f); err != nil {
		t.Fatalf("unchanged exec: %v", err)
	}
	for i := range f.Plugins {
		if f.Plugins[i].Type == "exec" {
			f.Plugins[i].Name = "renamed"
		}
	}
	if _, err := ApplyForm([]byte(text), f); err == nil || !strings.Contains(err.Error(), "raw YAML") {
		t.Fatalf("exec edit: %v", err)
	}
	f, _ = ParseForm([]byte(text))
	f.Plugins = slices.DeleteFunc(f.Plugins, func(p FormPlugin) bool { return p.Type == "exec" })
	if _, err := ApplyForm([]byte(text), f); err == nil || !strings.Contains(err.Error(), "exec plugin probers 0 is missing") {
		t.Fatalf("exec left out: %v", err)
	}
	f.Plugins = []FormPlugin{}
	if _, err := ApplyForm([]byte(text), f); err == nil || !strings.Contains(err.Error(), "raw YAML") {
		t.Fatalf("every plugin left out: %v", err)
	}
}

// The announcer publishes under inbound. Turning it on without the inbound
// block would leave inbound holding only the announcer.
func TestBlocksAnnouncerNeedsInbound(t *testing.T) {
	f, _ := ParseForm([]byte(observeYAML))
	f.Inbound = nil
	f.Blocks["inbound_announcer"] = Values{"type": "gobgp", "config.marker": "64512:667"}
	if _, err := ApplyForm([]byte(observeYAML), f); err == nil || !strings.Contains(err.Error(), "needs the inbound block on") {
		t.Fatalf("announcer without inbound: %v", err)
	}
}

func TestBlocksRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(f *Form)
		want string
	}{
		{"neighbor address", func(f *Form) { f.Blocks["bgp"]["neighbors"].([]Values)[0]["address"] = "not-an-ip" }, "bgp.neighbors[0].address"},
		{"neighbor duplicate", func(f *Form) { f.Blocks["bgp"]["neighbors"].([]Values)[1]["address"] = "192.0.2.254" }, "duplicate 192.0.2.254"},
		{"neighbor port", func(f *Form) { f.Blocks["bgp"]["neighbors"].([]Values)[0]["port"] = "70000" }, "bgp.neighbors[0].port"},
		{"as path", func(f *Form) { f.Blocks["bgp"]["as_path"] = "mine" }, "bgp.as_path"},
		{"missing router", func(f *Form) { f.Blocks["bmp"]["routers"] = []string{} }, "rib_sources[bmp].config.routers"},
		{"bmp listen", func(f *Form) { f.Blocks["bmp"]["listen"] = "11019" }, "listen"},
		{"window without time", func(f *Form) {
			w := f.Blocks["maintenance"]["windows"].([]Values)[0]
			w["schedule"], w["duration"] = "", ""
		}, "windows[0]"},
		{"window both kinds", func(f *Form) {
			f.Blocks["maintenance"]["windows"].([]Values)[0]["start"] = "2026-11-01T01:00:00Z"
		}, "not both"},
		{"window start, end, and duration", func(f *Form) {
			w := f.Blocks["maintenance"]["windows"].([]Values)[0]
			w["schedule"], w["start"], w["end"] = "", "2026-11-01T01:00:00Z", "2026-11-01T03:00:00Z"
		}, "only for a schedule"},
		{"window end before start", func(f *Form) {
			w := f.Blocks["maintenance"]["windows"].([]Values)[0]
			w["schedule"], w["duration"], w["start"], w["end"] = "", "", "2026-11-01T03:00:00Z", "2026-11-01T01:00:00Z"
		}, "after the start"},
		{"window time", func(f *Form) {
			w := f.Blocks["maintenance"]["windows"].([]Values)[0]
			w["schedule"], w["duration"], w["start"], w["end"] = "", "", "tomorrow", "2026-11-01T01:00:00Z"
		}, "RFC 3339"},
		{"marker", func(f *Form) { f.Blocks["inbound_announcer"]["config.marker"] = "mine" }, "config.marker"},
		{"prepend", func(f *Form) {
			f.Blocks["inbound_announcer"]["config.providers"].([]Values)[0]["prepend"] = "11"
		}, "prepend"},
		{"duplicate provider action", func(f *Form) {
			rows := f.Blocks["inbound_announcer"]["config.providers"].([]Values)
			f.Blocks["inbound_announcer"]["config.providers"] = append(rows, Values{"provider": "transit-a", "communities": []string{"64512:1"}})
		}, "duplicate transit-a"},
		{"sensitivity", func(f *Form) { f.Blocks["anomaly"]["detector.config.sensitivity"] = "101" }, "sensitivity"},
		{"detector type", func(f *Form) { f.Blocks["anomaly"]["detector.type"] = "ml" }, "detector.type"},
		{"mitigation allowlist", func(f *Form) { f.Blocks["mitigation"]["allowlist"] = []string{"198.51.100.1/24"} }, "host bits"},
		{"mitigation cap", func(f *Form) { f.Blocks["mitigation"]["max_rules"] = "0" }, "max_rules"},
		{"geoip path", func(f *Form) { f.Blocks["mitigation"]["geoip_db"] = "geo.mmdb" }, "absolute path"},
		{"http allow", func(f *Form) { f.Blocks["http"]["allow_from"] = []string{"nope"} }, "http.allow_from[0]"},
		{"http listen", func(f *Form) { f.Blocks["http"]["listen"] = "8080" }, "http.listen"},
		{"http listen unbracketed IPv6", func(f *Form) { f.Blocks["http"]["listen"] = "::1:8080" }, "wrap IPv6 in brackets"},
		{"bmp listen host name", func(f *Form) { f.Blocks["bmp"]["listen"] = "localhost:11019" }, "must be an IP address"},
		{"community secret", func(f *Form) { f.Blocks["inject"]["packeteer_community"] = "x" }, "packeteer_community"},
		{"scorer weight", func(f *Form) { f.Blocks["scorer"]["loss_weight"] = "-1" }, "loss_weight"},
		{"unknown block", func(f *Form) { f.Blocks["magic"] = Values{} }, "not a settings block"},
		{"wrong type", func(f *Form) { f.Blocks["http"]["allow_from"] = "127.0.0.0/8" }, "wrong type"},
		{"required block off", func(f *Form) { f.Blocks["http"] = nil }, "cannot be turned off"},
		{"flow problems without networks", func(f *Form) { f.Flows[0].Extra["problems"].(Values)["local"] = []string{} }, "flow.problems.local"},
		{"flow subranges bound", func(f *Form) {
			f.Flows[0].Extra["subranges"] = Values{"bits_v4": "40"}
		}, "flow.subranges.bits_v4"},
		{"stale row", func(f *Form) { f.Blocks["bgp"]["neighbors"].([]Values)[0]["_key"] = "9" }, "not in the file anymore"},
		{"row twice", func(f *Form) { f.Blocks["bgp"]["neighbors"].([]Values)[1]["_key"] = "0" }, "listed twice"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := mustParse(t, blocksYAML)
			c.edit(&f)
			// The page sends JSON; so does this.
			f = roundTripJSON(t, f)
			_, err := ApplyForm([]byte(blocksYAML), f)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestBlocksSchemaIsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, b := range Blocks() {
		if seen[b.ID] || b.Title == "" || b.Help == "" || len(b.Fields) == 0 {
			t.Errorf("block %q is incomplete or repeated", b.ID)
		}
		seen[b.ID] = true
		checkFields(t, b.ID, b.Fields)
	}
	checkFields(t, "flow", flowExtras)
}

func checkFields(t *testing.T, where string, fields []Field) {
	t.Helper()
	keys := map[string]bool{}
	for _, f := range fields {
		at := where + "." + f.Key
		if f.Key == "" || f.Label == "" || f.Help == "" || keys[f.Key] {
			t.Errorf("%s: key, label, and help are required, and a key is used once", at)
		}
		keys[f.Key] = true
		if strings.HasSuffix(f.Help, "  ") || strings.ContainsAny(f.Label, "_") {
			t.Errorf("%s: the label shows a config key or the help is untidy: %q", at, f.Label)
		}
		if f.Kind == KindEnum && len(f.Options) == 0 {
			t.Errorf("%s: an enum needs options", at)
		}
		if f.Check != "" && checkers[f.Check] == nil {
			t.Errorf("%s: unknown check %q", at, f.Check)
		}
		if (f.Kind == KindRows || f.Kind == KindGroup) != (len(f.Fields) > 0) {
			t.Errorf("%s: rows and groups carry fields, other kinds do not", at)
		}
		checkFields(t, at, f.Fields)
	}
}

// TestBlocksReadWriteAgree writes a value into each block field in turn, on
// a file that has the block, and reads it back unchanged.
func TestBlocksReadWriteAgree(t *testing.T) {
	for _, b := range Blocks() {
		var doc yaml.Node
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Kind, doc.Content = yaml.DocumentNode, []*yaml.Node{m}
		want := sampleValues(b.Fields)
		if err := b.apply(m, want); err != nil {
			t.Fatalf("%s: %v", b.ID, err)
		}
		got := b.read(m)
		if !equalValues(got, want) {
			t.Errorf("%s: read %+v, wrote %+v", b.ID, got, want)
		}
	}
}

func mustParse(t *testing.T, yaml string) Form {
	t.Helper()
	f, err := ParseForm([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func roundTripJSON(t *testing.T, f Form) Form {
	t.Helper()
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var out Form
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// sampleValues makes a non-default value for every field.
func sampleValues(fields []Field) Values {
	v := Values{}
	for _, f := range fields {
		switch f.Kind {
		case KindBool:
			v[f.Key] = !f.DefaultTrue
		case KindList, KindCIDRs:
			if f.Kind == KindCIDRs {
				v[f.Key] = []string{"192.0.2.0/24", "198.51.100.0/24"}
			} else {
				v[f.Key] = []string{"192.0.2.1", "192.0.2.2"}
			}
		case KindRows:
			row := sampleValues(f.Fields)
			row[rowKey] = ""
			v[f.Key] = []Values{row}
		case KindGroup:
			v[f.Key] = sampleValues(f.Fields)
		case KindEnum:
			v[f.Key] = f.Options[len(f.Options)-1]
		case KindTime:
			v[f.Key] = "2026-11-01T01:00:00Z"
		default:
			v[f.Key] = "7"
		}
	}
	return v
}

// equalValues compares ignoring the row keys the read adds.
func equalValues(a, b Values) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv := b[k]
		switch x := av.(type) {
		case []Values:
			y, _ := bv.([]Values)
			if len(x) != len(y) {
				return false
			}
			for i := range x {
				xi, yi := Values{}, Values{}
				for kk, vv := range x[i] {
					if kk != rowKey {
						xi[kk] = vv
					}
				}
				for kk, vv := range y[i] {
					if kk != rowKey {
						yi[kk] = vv
					}
				}
				if !equalValues(xi, yi) {
					return false
				}
			}
		case Values:
			y, _ := bv.(Values)
			if !equalValues(x, y) {
				return false
			}
		default:
			if !reflect.DeepEqual(av, bv) {
				return false
			}
		}
	}
	return true
}
