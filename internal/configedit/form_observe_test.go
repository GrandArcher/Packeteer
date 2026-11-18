package configedit

import (
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// observeBlocksYAML is an observe-mode edge with an allowlist, a community,
// and an announcer, plus every block of #670 with keys the forms leave to the
// raw YAML. Documentation addresses and ASNs only.
const observeBlocksYAML = `# lab edge
mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 200
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: [198.51.100.0/24]
announcer:
  type: gobgp
bgp:
  neighbors:
    - address: 192.0.2.254
storage:
  type: sqlite
  config:
    path: /var/lib/packeteer/packeteer.db
rpki:
  enabled: true
  avoid_invalid: false
  sources:
    - type: rtr
      name: routinator
      config:
        address: 192.0.2.20:3323
        refresh: 5m
        tls:
          ca_file: /etc/packeteer/rtr-ca.pem
  only_invalid:
    enabled: true
    stable_after: 720h
    hijack_feeds:
      - type: file
        name: incidents
        config:
          path: /etc/packeteer/hijacks.json
    slurm:
      path: /var/lib/packeteer/slurm.json
      prefixes: [203.0.113.0/24]
registry:
  enabled: true
  asns: [64496]
  push_enabled: false
  sources:
    - type: peeringdb
mcp:
  enabled: true
  write_tools: false
verify:
  enabled: true
  backout: [inbound, outbound]
herd:
  enabled: true
  share:
    classes: [measurements]
    exclude:
      prefixes: [203.0.113.0/24]
      asns: [64501]
  vantage: {country: US}
  listen: 0.0.0.0:9444
  peers:
    - url: https://192.0.2.30:9444
      key: ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  limits: {rate_global: 700}
  outside:
    atlas: {enabled: true, measurements: [1001]}
preflight:
  router_check:
    type: frr
    config:
      socket_env: PACKETEER_FRR_SOCKET
`

// observeBlockIDs are the blocks of #670.
var observeBlockIDs = []string{"rpki", "rpki_only_invalid", "registry", "mcp", "verify", "herd", "router_check"}

func observeEdit(t *testing.T, src string, edit func(f *Form)) (string, *config.Config) {
	t.Helper()
	f := mustParse(t, src)
	edit(&f)
	out, err := ApplyForm([]byte(src), roundTripJSON(t, f))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("the merged text does not load: %v\n%s", err, out)
	}
	return string(out), cfg
}

func TestObserveBlocksReadTheFile(t *testing.T) {
	f := mustParse(t, observeBlocksYAML)
	b := f.Blocks
	src := b["rpki"]["sources"].([]Values)
	if b["rpki"]["enabled"] != true || len(src) != 1 || src[0]["type"] != "rtr" || src[0]["config.address"] != "192.0.2.20:3323" || src[0]["config.refresh"] != "5m" {
		t.Fatalf("rpki = %+v", b["rpki"])
	}
	oi := b["rpki_only_invalid"]
	if oi["enabled"] != true || oi["stable_after"] != "720h" || oi["hijack_feeds"].([]Values)[0]["config.path"] != "/etc/packeteer/hijacks.json" {
		t.Fatalf("only_invalid = %+v", oi)
	}
	if got := b["registry"]["asns"].([]string); len(got) != 1 || got[0] != "64496" {
		t.Fatalf("registry asns = %v", got)
	}
	h := b["herd"]
	if h["vantage.country"] != "US" || h["listen"] != "0.0.0.0:9444" || h["share.exclude.asns"].([]string)[0] != "64501" || h["peers"].([]Values)[0]["url"] != "https://192.0.2.30:9444" {
		t.Fatalf("herd = %+v", h)
	}
	if b["router_check"]["type"] != "frr" || b["router_check"]["config.socket_env"] != "PACKETEER_FRR_SOCKET" {
		t.Fatalf("router_check = %+v", b["router_check"])
	}
	bare := mustParse(t, observeYAML)
	for _, id := range observeBlockIDs {
		if bare.Blocks[id] != nil {
			t.Errorf("%s reads as set in a file without it: %+v", id, bare.Blocks[id])
		}
	}
}

func TestObserveBlocksUnchangedFormWritesNothing(t *testing.T) {
	f := mustParse(t, observeBlocksYAML)
	for _, form := range []Form{f, roundTripJSON(t, f)} {
		out, err := ApplyForm([]byte(observeBlocksYAML), form)
		if err != nil || string(out) != observeBlocksYAML {
			t.Fatalf("unchanged form changed the file: %v\n%s", err, out)
		}
	}
}

// An edit of each block keeps the keys the forms do not show: the SLURM
// exceptions, push_enabled, the backout list, the herd limits and Atlas, and
// an rtr source's TLS settings.
func TestObserveBlocksKeepTheRestOfTheFile(t *testing.T) {
	out, cfg := observeEdit(t, observeBlocksYAML, func(f *Form) {
		f.Blocks["rpki"]["avoid_invalid"] = true
		f.Blocks["rpki_only_invalid"]["stable_after"] = "240h"
		f.Blocks["registry"]["asns"] = []string{"64496", "64497"}
		f.Blocks["registry"]["interval"] = "12h"
		f.Blocks["mcp"]["rate_per_minute"] = "60"
		f.Blocks["verify"]["verified_pct"] = "60"
		f.Blocks["herd"]["retention_days"] = "60"
		f.Blocks["router_check"]["config.socket_env"] = "PACKETEER_FRR_SOCKET2"
	})
	if !cfg.RPKI.AvoidInvalid || cfg.RPKI.OnlyInvalid.StableAfter.Hours() != 240 || len(cfg.Registry.ASNs) != 2 || cfg.Registry.Interval.Hours() != 12 ||
		cfg.MCP.RatePerMinute != 60 || cfg.Verify.VerifiedPct != 60 || cfg.Herd.RetentionDays != 60 {
		t.Fatalf("edits not applied: %+v\n%s", cfg, out)
	}
	for _, keep := range []string{
		"slurm:\n      path: /var/lib/packeteer/slurm.json\n", "push_enabled: false\n", "backout: [inbound, outbound]\n",
		"limits: {rate_global: 700}\n", "atlas: {enabled: true, measurements: [1001]}\n", "ca_file: /etc/packeteer/rtr-ca.pem\n", "# lab edge\n",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q changed or vanished:\n%s", keep, out)
		}
	}
	if cfg.RPKI.Sources[0].Name != "routinator" || cfg.RPKI.OnlyInvalid.SLURM == nil || cfg.Registry.PushEnabled {
		t.Fatalf("kept keys changed: %+v", cfg.RPKI)
	}
}

// The forms never write mode, the allowlist, or the announcer, whatever is
// turned on, and no form field is one of them or a switch that enables a
// riskier feature.
func TestObserveBlocksNeverTouchSafetyKeys(t *testing.T) {
	forbidden := map[string]bool{
		"mode": true, "allowlist": true, "announcer": true, "packeteer_community": true, "local_pref": true,
		"push_enabled": true, "install_routes": true, "synthesize": true, "slurm": true, "backout": true,
	}
	for _, b := range Blocks() {
		if !isObserveBlock(b.ID) {
			continue
		}
		var walk func(fields []Field)
		walk = func(fields []Field) {
			for _, f := range fields {
				for _, part := range strings.Split(f.Key, ".") {
					if forbidden[part] {
						t.Errorf("%s: field %q reaches %q", b.ID, f.Key, part)
					}
				}
				walk(f.Fields)
			}
		}
		walk(b.Fields)
	}

	// Turn every block on in a file that has none of them and the safety
	// keys set: the safety keys read back exactly as they were.
	const base = `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 200
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: [198.51.100.0/24]
announcer:
  type: gobgp
bgp:
  neighbors:
    - address: 192.0.2.254
storage:
  type: sqlite
  config:
    path: /var/lib/packeteer/packeteer.db
`
	out, cfg := observeEdit(t, base, func(f *Form) {
		f.Blocks["rpki"] = Values{"enabled": true, "sources": []Values{{"type": "rtr", "config.address": "192.0.2.20:3323"}}}
		f.Blocks["rpki_only_invalid"] = Values{"enabled": true}
		f.Blocks["registry"] = Values{"enabled": true, "asns": []string{"64496"}, "sources": []Values{{"type": "peeringdb"}}}
		f.Blocks["mcp"] = Values{"enabled": true}
		f.Blocks["verify"] = Values{"enabled": true}
		f.Blocks["herd"] = Values{"enabled": true, "preview_only": true, "share.classes": []string{"measurements"}, "vantage.country": "US"}
		f.Blocks["router_check"] = Values{"type": "frr", "config.socket_env": "PACKETEER_FRR_SOCKET"}
	})
	if cfg.Mode != "observe" || cfg.Announcer == nil || cfg.Announcer.Type != "gobgp" || cfg.PacketeerCommunity != "64512:666" || cfg.LocalPref != 200 ||
		len(cfg.Allowlist.Prefixes) != 1 || cfg.Allowlist.Prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("safety keys changed: mode %q announcer %+v allowlist %v\n%s", cfg.Mode, cfg.Announcer, cfg.Allowlist.Prefixes, out)
	}
	if cfg.Synthesize != nil || cfg.NonBGP != nil || cfg.Registry.PushEnabled || cfg.MCP.WriteTools || cfg.RPKI.AvoidInvalid || cfg.RPKI.OnlyInvalid.SLURM != nil {
		t.Fatalf("a form switched on something it does not offer: %s", out)
	}
	for _, key := range []string{"push_enabled", "write_tools", "avoid_invalid", "slurm", "backout", "install_routes", "synthesize"} {
		if strings.Contains(out, key) {
			t.Errorf("%s written by the defaults:\n%s", key, out)
		}
	}
	// The first lines are the file's own, untouched.
	if !strings.HasPrefix(out, base[:strings.Index(base, "bgp:")]) {
		t.Fatalf("the top of the file changed:\n%s", out)
	}
}

func isObserveBlock(id string) bool { return slices.Contains(observeBlockIDs, id) }

// Every block is off in a file that does not have it, and an on switch starts
// ticked so that turning a block on turns it on.
func TestObserveBlocksDefaultOff(t *testing.T) {
	cfg, err := config.Parse([]byte(observeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RPKIOn() || cfg.OnlyInvalidOn() || cfg.RegistryOn() || cfg.MCPEnabled() || cfg.Verify.Enabled || cfg.HerdOn() || cfg.Preflight.RouterCheck != nil {
		t.Fatalf("a block is on without being set: %+v", cfg)
	}
	for _, b := range Blocks() {
		if !isObserveBlock(b.ID) || b.ID == "router_check" {
			continue
		}
		if !b.Optional {
			t.Errorf("%s must be optional so that off removes it", b.ID)
		}
		if f := b.Fields[0]; f.Key != "enabled" || f.Kind != KindBool || !f.StartOn || f.DefaultTrue {
			t.Errorf("%s: first field = %+v, want the enabled switch that starts on", b.ID, f)
		}
	}
	out, _ := observeEdit(t, observeBlocksYAML, func(f *Form) {
		for _, id := range []string{"rpki_only_invalid", "rpki", "registry", "mcp", "verify", "herd", "router_check"} {
			f.Blocks[id] = nil
		}
	})
	for _, gone := range []string{"rpki:", "registry:", "mcp:", "verify:", "herd:", "router_check", "slurm"} {
		if strings.Contains(out, gone) {
			t.Errorf("%s stayed after the switch went off:\n%s", gone, out)
		}
	}
}

func TestObserveBlocksRefusals(t *testing.T) {
	cases := []struct {
		name  string
		block string
		edit  func(v Values)
		want  string
	}{
		{"rtr without address", "rpki", func(v Values) { v["sources"].([]Values)[0]["config.address"] = "" }, "rpki.sources[0].config.address: is required"},
		{"rtr address", "rpki", func(v Values) { v["sources"].([]Values)[0]["config.address"] = "192.0.2.20" }, "config.address"},
		{"json key on rtr", "rpki", func(v Values) { v["sources"].([]Values)[0]["config.url"] = "http://192.0.2.20:8323/json" }, "not a setting of the rtr type"},
		{"url with login", "rpki", func(v Values) {
			s := v["sources"].([]Values)[0]
			s["type"], s["config.address"], s["config.url"] = "json", "", "http://user:pw@192.0.2.20/json"
		}, "no login"},
		{"source type", "rpki", func(v Values) { v["sources"].([]Values)[0]["type"] = "exec" }, "rpki.sources[0].type"},
		{"fallback type", "rpki", func(v Values) { v["display_fallback"] = Values{"type": "rtr"} }, "display_fallback.type"},
		{"refresh", "rpki", func(v Values) { v["sources"].([]Values)[0]["config.refresh"] = "0s" }, "config.refresh"},
		{"stable after", "rpki_only_invalid", func(v Values) { v["stable_after"] = "1m" }, "stable_after"},
		{"feed path", "rpki_only_invalid", func(v Values) { v["hijack_feeds"].([]Values)[0]["config.path"] = "hijacks.json" }, "absolute path"},
		{"asn zero", "registry", func(v Values) { v["asns"] = []string{"0"} }, "asns[0]"},
		{"asn text", "registry", func(v Values) { v["asns"] = []string{"AS64496"} }, "whole number"},
		{"asn missing", "registry", func(v Values) { v["asns"] = []string{} }, "needs at least one value"},
		{"interval", "registry", func(v Values) { v["interval"] = "1m" }, "interval"},
		{"headroom", "registry", func(v Values) { v["headroom_percent"] = "5000" }, "headroom_percent"},
		{"source type", "registry", func(v Values) { v["sources"].([]Values)[0]["type"] = "rtr" }, "registry.sources[0].type"},
		{"ripe key on peeringdb", "registry", func(v Values) { v["sources"].([]Values)[0]["config.source"] = "RIPE" }, "not a setting of the peeringdb type"},
		{"rate", "mcp", func(v Values) { v["rate_per_minute"] = "0" }, "rate_per_minute"},
		{"window", "verify", func(v Values) { v["outbound_window"] = "1s" }, "outbound_window"},
		{"percent", "verify", func(v Values) { v["verified_pct"] = "101" }, "verified_pct"},
		{"class", "herd", func(v Values) { v["share.classes"] = []string{"names"} }, "share.classes[0]"},
		{"no class", "herd", func(v Values) { v["share.classes"] = []string{} }, "share.classes"},
		{"source", "herd", func(v Values) { v["share.sources"] = []string{"snmp"} }, "share.sources[0]"},
		{"granularity", "herd", func(v Values) { v["share.granularity"] = "prefix" }, "share.granularity"},
		{"country", "herd", func(v Values) { v["vantage.country"] = "us" }, "capitals"},
		{"retention", "herd", func(v Values) { v["retention_days"] = "7" }, "retention_days"},
		{"peer url", "herd", func(v Values) { v["peers"].([]Values)[0]["url"] = "http://192.0.2.30:9444" }, "https://host:port"},
		{"peer key", "herd", func(v Values) { v["peers"].([]Values)[0]["key"] = "abc" }, "ed25519:"},
		{"exclude prefix", "herd", func(v Values) { v["share.exclude.prefixes"] = []string{"203.0.113.1/24"} }, "host bits"},
		{"exclude asn", "herd", func(v Values) { v["share.exclude.asns"] = []string{"-1"} }, "whole number"},
		{"listen", "herd", func(v Values) { v["listen"] = "9444" }, "listen"},
		{"router check type", "router_check", func(v Values) { v["type"] = "exec" }, "preflight.router_check.type"},
		{"router check key of another type", "router_check", func(v Values) { v["config.url"] = "https://192.0.2.254" }, "not a setting of the frr type"},
		{"router check without socket", "router_check", func(v Values) { v["config.socket_env"] = "" }, "is required for the frr type"},
		{"router check env name", "router_check", func(v Values) { v["config.socket_env"] = "bad name" }, "environment variable name"},
	}
	for _, c := range cases {
		t.Run(c.block+"/"+c.name, func(t *testing.T) {
			f := mustParse(t, observeBlocksYAML)
			c.edit(f.Blocks[c.block])
			_, err := ApplyForm([]byte(observeBlocksYAML), roundTripJSON(t, f))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// only_invalid is a key under rpki, so it cannot be set while the RPKI block
// is off, and the loader refuses a block that is enabled with nothing to
// read from.
func TestObserveOnlyInvalidNeedsRPKI(t *testing.T) {
	f := mustParse(t, observeYAML)
	f.Blocks["rpki_only_invalid"] = Values{"enabled": true}
	if _, err := ApplyForm([]byte(observeYAML), roundTripJSON(t, f)); err == nil || !strings.Contains(err.Error(), "needs the RPKI block on") {
		t.Fatalf("err = %v", err)
	}
	g := mustParse(t, observeBlocksYAML)
	g.Blocks["rpki"]["sources"] = []Values{}
	out, err := ApplyForm([]byte(observeBlocksYAML), roundTripJSON(t, g))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(out); err == nil || !strings.Contains(err.Error(), "rpki.sources: at least one source") {
		t.Fatalf("a source-less enabled rpki block loaded: %v", err)
	}
}

// The environment variable names the editor accepts for the router check are
// the documented ones, so a form cannot name PACKETEER_ADMIN_PASSWORD.
func TestRouterCheckEnvNames(t *testing.T) {
	for _, c := range []struct {
		place, name string
		want        bool
	}{
		{"preflight.router_check/frr", "PACKETEER_FRR_SOCKET", true},
		{"preflight.router_check/bird", "PACKETEER_BIRD_CONFIG", true},
		{"preflight.router_check/routeros", "PACKETEER_ROUTER_READ_PASSWORD", true},
		{"preflight.router_check/routeros", "PACKETEER_ROUTER_PASSWORD", false},
		{"preflight.router_check/routeros", "PACKETEER_ADMIN_PASSWORD", false},
		{"preflight.router_check/frr", "PACKETEER_BIRD_SOCKET", false},
	} {
		if got := EnvNameAllowed(c.place, c.name); got != c.want {
			t.Errorf("EnvNameAllowed(%s, %s) = %v, want %v", c.place, c.name, got, c.want)
		}
	}
}
