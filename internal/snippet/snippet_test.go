package snippet

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
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
		cases := map[string]Params{vendor: std(), vendor + "-addpath-v6": full()}
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
		"no bgp.neighbors":       func(c *config.Config) { c.BGP.Neighbors = nil },
		"packeteer_community":    func(c *config.Config) { c.PacketeerCommunity = "" },
		"packeteer_community: ":  func(c *config.Config) { c.PacketeerCommunity = "70000:1" },
		"needs Packeteer's addr": func(c *config.Config) { c.RouterID = "" },
		"bgp.neighbors address":  func(c *config.Config) { c.BGP.Neighbors[0].Address = "edge" },
	}
	for want, mut := range cases {
		cfg := loadConfig(t, "")
		mut(cfg)
		if _, err := ForConfig(cfg); err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(want, ": ")) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
}
