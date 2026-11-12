package snippet

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"gopkg.in/yaml.v3"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func std() Params {
	return Params{ASN: 64512, Router: "192.0.2.254", Packeteer: "192.0.2.10", Community: "64512:666"}
}

func large() Params {
	p := std()
	p.Community = "64512:1:666"
	return p
}

func full() Params {
	p := std()
	p.AddPath, p.IPv6 = true, true
	return p
}

func flow() Params {
	p := std()
	p.FlowHost, p.FlowPort = "192.0.2.10", 2055
	return p
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/snippet -update)", err)
	}
	if got != string(want) {
		t.Errorf("%s differs from %s:\n%s", name, path, got)
	}
}

func TestGolden(t *testing.T) {
	for _, vendor := range Vendors {
		cases := map[string]Params{vendor: std(), vendor + "-addpath-v6": full(), vendor + "-flow": flow()}
		if vendor != Arista {
			cases[vendor+"-large"] = large()
		}
		for name, p := range cases {
			t.Run(name, func(t *testing.T) {
				got, err := Generate(vendor, p)
				if err != nil {
					t.Fatal(err)
				}
				golden(t, name, got)
			})
		}
	}
}

// Whatever the vendor, the snippet carries the three things the router must
// do: accept only the community from Packeteer, reject it toward eBGP, and
// leave graceful restart off. Documentation values only.
func TestEverySnippetCarriesTheFilters(t *testing.T) {
	for _, vendor := range Vendors {
		got, err := Generate(vendor, std())
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"64512", "192.0.2.10", "192.0.2.254"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: no %q in\n%s", vendor, want, got)
			}
		}
		lower := strings.ToLower(got)
		if !strings.Contains(lower, "packeteer-in") && !strings.Contains(lower, "packeteer_in") {
			t.Errorf("%s: no import filter", vendor)
		}
		if !strings.Contains(lower, "ebgp-out") && !strings.Contains(lower, "ebgp_out") && !strings.Contains(lower, "no-packeteer-out") {
			t.Errorf("%s: no eBGP export deny", vendor)
		}
		if !strings.Contains(lower, "graceful") {
			t.Errorf("%s: says nothing about graceful restart", vendor)
		}
		for _, r := range got {
			if r > 0x7e || (r < 0x20 && r != '\n' && r != '\t') {
				t.Fatalf("%s: non-ASCII or control character %q", vendor, r)
			}
		}
	}
}

// The snippet is pasted onto a live edge. It must add a deny in front of the
// export policy the operator already has and never replace that policy.
func TestMikroTikSnippetKeepsTheExistingExportChain(t *testing.T) {
	got, err := Generate(MikroTik, std())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "output.filter-chain") || strings.Contains(got, "connection set") || strings.Contains(got, `rule="accept"`) {
		t.Errorf("the snippet rewires or replaces eBGP export policy:\n%s", got)
	}
	if !strings.Contains(got, "chain=ebgp-out place-before=0") {
		t.Errorf("the deny is not placed first in the chain:\n%s", got)
	}
}

func TestLargeCommunityIsMatchedAsLarge(t *testing.T) {
	want := map[string]string{
		FRR:      "bgp large-community-list standard packeteer permit 64512:1:666",
		BIRD:     "(64512, 1, 666) ~ bgp_large_community",
		Junos:    "members large:64512:1:666",
		IOSXR:    "large-community-set packeteer",
		MikroTik: "bgp-large-communities includes 64512:1:666",
	}
	for vendor, line := range want {
		got, err := Generate(vendor, large())
		if err != nil || !strings.Contains(got, line) {
			t.Errorf("%s: %q missing from\n%s (%v)", vendor, line, got, err)
		}
	}
}

func TestGenerateRefusals(t *testing.T) {
	if _, err := Generate(Arista, large()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("arista with a large community = %v", err)
	}
	if _, err := Generate("cumulus", std()); err == nil || !strings.Contains(err.Error(), "frr, bird, junos, iosxr, arista, mikrotik") {
		t.Fatalf("unknown vendor = %v", err)
	}
}

func loadConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `mode: observe
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
allowlist:
  prefixes: []
bgp:
  neighbors:
    - address: 192.0.2.254
` + extra
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestForConfigReadsTheAnswersFromTheConfig(t *testing.T) {
	cfg := loadConfig(t, "      add_path: true\n    - address: 192.0.2.253\n      local_address: 192.0.2.12\n")
	ps, err := ForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("%d params, want one per neighbor", len(ps))
	}
	if ps[0] != (Params{ASN: 64512, Router: "192.0.2.254", Packeteer: "192.0.2.10", Community: "64512:666", AddPath: true}) {
		t.Fatalf("first = %+v", ps[0])
	}
	if ps[1].Router != "192.0.2.253" || ps[1].Packeteer != "192.0.2.12" || ps[1].AddPath {
		t.Fatalf("second = %+v (local_address replaces router_id)", ps[1])
	}
	text, err := Join(FRR, ps)
	if err != nil || strings.Count(text, "route-map packeteer-in permit 10") != 2 || !strings.Contains(text, "neighbor 192.0.2.12 remote-as 64512") {
		t.Fatalf("join = %q, %v", text, err)
	}
}

func TestForConfigSetsIPv6FromProviders(t *testing.T) {
	cfg := loadConfig(t, "")
	cfg.Providers = append(cfg.Providers, config.Provider{Name: "transit-v6", SourceIP: "2001:db8::11", NextHop: "2001:db8::1"})
	ps, err := ForConfig(cfg)
	if err != nil || !ps[0].IPv6 {
		t.Fatalf("params = %+v, %v", ps, err)
	}
}

func TestForConfigRefusals(t *testing.T) {
	cases := map[string]func(*config.Config){
		"setup step 1 (Edge), or set bgp.neighbors":     func(c *config.Config) { c.BGP.Neighbors = nil },
		"setup step 4 (Generate) fills it as 64512:666": func(c *config.Config) { c.PacketeerCommunity = "" },
		"packeteer_community: ":                         func(c *config.Config) { c.PacketeerCommunity = "65536:1" },
		"enter the Router ID in setup step 1":           func(c *config.Config) { c.RouterID = "" },
		"bgp.neighbors address":                         func(c *config.Config) { c.BGP.Neighbors[0].Address = "edge" },
	}
	for want, mut := range cases {
		cfg := loadConfig(t, "")
		mut(cfg)
		if _, err := ForConfig(cfg); err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(want, ": ")) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
}

// With a flow source every vendor says where the router sends records. The
// vendors that can express it (Junos, IOS-XR, Arista, RouterOS) print the
// export config; FRR and BIRD cannot, and say so. Without one, nothing about
// flows appears.
func TestFlowExportLines(t *testing.T) {
	want := map[string][]string{
		FRR:      {"FRR does not export flows", "192.0.2.10, UDP 2055"},
		BIRD:     {"BIRD does not export flows", "192.0.2.10, UDP 2055"},
		Junos:    {"flow-server 192.0.2.10 {", "port 2055;", "source-address 192.0.2.254;", "version-ipfix"},
		IOSXR:    {"transport udp 2055", "destination 192.0.2.10", "flow exporter-map packeteer"},
		Arista:   {"sflow destination 192.0.2.10 2055", "sflow source 192.0.2.254", "sflow run"},
		MikroTik: {"/ip traffic-flow target add dst-address=192.0.2.10 port=2055 version=9", "src-address=192.0.2.254"},
	}
	for _, vendor := range Vendors {
		got, err := Generate(vendor, flow())
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range want[vendor] {
			if !strings.Contains(got, line) {
				t.Errorf("%s: %q missing from\n%s", vendor, line, got)
			}
		}
		plain, err := Generate(vendor, std())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(plain), "flow") && vendor != Junos {
			t.Errorf("%s: flow text without a flow source:\n%s", vendor, plain)
		}
		if vendor == Junos && strings.Contains(plain, "flow-server") {
			t.Errorf("junos: flow-server without a flow source")
		}
	}
}

func TestForConfigFlowCollector(t *testing.T) {
	flowSource := func(listen string) config.PluginSpec {
		var n yaml.Node
		if err := n.Encode(map[string]any{"listen": listen}); err != nil {
			t.Fatal(err)
		}
		return config.PluginSpec{Type: "flow", Config: n}
	}
	cases := []struct {
		name    string
		sources func() []config.PluginSpec
		host    string
		port    int
	}{
		{"no flow source", func() []config.PluginSpec { return nil }, "", 0},
		{"listen on every address uses Packeteer's address", func() []config.PluginSpec { return []config.PluginSpec{flowSource("0.0.0.0:2055")} }, "192.0.2.10", 2055},
		{"empty host", func() []config.PluginSpec { return []config.PluginSpec{flowSource(":4739")} }, "192.0.2.10", 4739},
		{"a given address", func() []config.PluginSpec { return []config.PluginSpec{flowSource("192.0.2.77:2055")} }, "192.0.2.77", 2055},
		{"ipv6 address", func() []config.PluginSpec { return []config.PluginSpec{flowSource("[2001:db8::10]:2055")} }, "2001:db8::10", 2055},
		{"another source type is ignored", func() []config.PluginSpec {
			s := flowSource("192.0.2.77:2055")
			s.Type = "static"
			return []config.PluginSpec{s}
		}, "", 0},
		{"a flow source with no listen (ebpf only)", func() []config.PluginSpec {
			return []config.PluginSpec{{Type: "flow"}}
		}, "", 0},
	}
	for _, c := range cases {
		cfg := loadConfig(t, "")
		cfg.Sources = c.sources()
		ps, err := ForConfig(cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if ps[0].FlowHost != c.host || ps[0].FlowPort != c.port {
			t.Errorf("%s: collector = %s:%d, want %s:%d", c.name, ps[0].FlowHost, ps[0].FlowPort, c.host, c.port)
		}
	}
}
