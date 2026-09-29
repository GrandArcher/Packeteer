package config

import (
	"strings"
	"testing"
)

// exchangeYAML is one edge with a transit and an exchange of two peers
// (#27). Documentation addresses and ASNs only.
const exchangeYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.21
exchanges:
  - name: ix-lab
    lans: [203.0.113.0/24]
    group: ix
    peers:
      - name: ix-peer-a
        asn: 64501
        next_hop: 203.0.113.11
        source_ip: 192.0.2.31
      - name: ix-peer-b
        asn: 64502
        next_hop: 203.0.113.12
        source_ip: 192.0.2.32
        precedence: 50
bgp:
  neighbors:
    - address: 192.0.2.254
      add_path: true
`

func TestExchangePeersAreProviders(t *testing.T) {
	cfg, err := Parse([]byte(exchangeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers) != 3 {
		t.Fatalf("providers = %+v", cfg.Providers)
	}
	a, b := cfg.Providers[1], cfg.Providers[2]
	if a.Name != "ix-peer-a" || a.NextHop != "203.0.113.11" || a.SourceIP != "192.0.2.31" || a.Exchange != "ix-lab" ||
		a.PeerASN != 64501 || a.Group != "ix" || !a.AddPath {
		t.Fatalf("peer a = %+v", a)
	}
	if b.Precedence != 50 || b.PeerASN != 64502 {
		t.Fatalf("peer b = %+v", b)
	}
	if cfg.Providers[0].Exchange != "" || cfg.Providers[0].AddPath {
		t.Fatalf("transit = %+v", cfg.Providers[0])
	}
	if cfg.BGP.ASPath != ASPathEmpty {
		t.Fatalf("as_path default = %q", cfg.BGP.ASPath)
	}
	// Validating again (the environment overlay does) is stable.
	if err := cfg.Validate(); err != nil || len(cfg.Providers) != 3 {
		t.Fatalf("revalidate: %v, %d providers", err, len(cfg.Providers))
	}
}

func TestExchangeInRouterLists(t *testing.T) {
	y := edit(t, exchangeYAML, "      add_path: true\n", `      add_path: true
      providers: [transit-a]
      next_hops:
        ix-lab: 192.0.2.252
    - address: 192.0.2.252
      providers: [ix-lab]
`)
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	n := cfg.BGP.Neighbors
	if len(n[0].NextHops) != 2 || n[0].NextHops["ix-peer-a"] != "192.0.2.252" || n[0].NextHops["ix-peer-b"] != "192.0.2.252" {
		t.Fatalf("next_hops = %v", n[0].NextHops)
	}
	if strings.Join(n[1].Providers, ",") != "ix-peer-a,ix-peer-b" {
		t.Fatalf("providers = %v", n[1].Providers)
	}
}

func TestExchangeBMPOnly(t *testing.T) {
	y := edit(t, exchangeYAML, "    group: ix\n", "    group: ix\n    bmp: only\n")
	y = edit(t, y, "      add_path: true\n", "") + "rib_sources:\n  - type: bmp\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if p := cfg.Providers[1]; p.BMP != BMPOnly || p.AddPath {
		t.Fatalf("peer = %+v", p)
	}
}

func TestExchangeErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"no lans":      {edit(t, exchangeYAML, "    lans: [203.0.113.0/24]\n", ""), "lans: at least one"},
		"bad lan":      {edit(t, exchangeYAML, "[203.0.113.0/24]", "[203.0.113.1/24]"), "not a CIDR without host bits"},
		"outside lan":  {edit(t, exchangeYAML, "next_hop: 203.0.113.12", "next_hop: 198.51.100.12"), "next_hop 198.51.100.12 is not inside"},
		"no asn":       {edit(t, exchangeYAML, "        asn: 64502\n", ""), "asn is required"},
		"no peers":     {exchangeYAML[:strings.Index(exchangeYAML, "    peers:")] + "bgp:\n  neighbors:\n    - address: 192.0.2.254\n      add_path: true\n", "peers: at least one"},
		"no name":      {edit(t, exchangeYAML, "  - name: ix-lab\n    lans:", "  - lans:"), "exchanges[0]: name is required"},
		"name clash":   {edit(t, exchangeYAML, "name: ix-lab", "name: transit-a"), "name is also a provider name"},
		"own peer":     {edit(t, exchangeYAML, "name: ix-peer-b", "name: ix-lab"), "name is also a provider name"},
		"peer clash":   {edit(t, exchangeYAML, "name: ix-peer-b", "name: transit-a"), "duplicate provider name"},
		"source clash": {edit(t, exchangeYAML, "source_ip: 192.0.2.32", "source_ip: 192.0.2.11"), "duplicate source_ip"},
		"no paths":     {edit(t, exchangeYAML, "      add_path: true\n", ""), "peers need their paths visible"},
		"no bgp":       {exchangeYAML[:strings.Index(exchangeYAML, "bgp:")], "exchanges require bgp.neighbors"},
		"bad as_path":  {exchangeYAML + "  as_path: origin\n", `bgp.as_path "origin" is invalid`},
	}
	for name, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
	if _, err := Parse([]byte(exchangeYAML + "  as_path: Provider\n")); err != nil {
		t.Fatalf("as_path provider: %v", err)
	}
}
