package config

import (
	"strings"
	"testing"
	"time"
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

func TestExchangeMaxPrefix(t *testing.T) {
	y := edit(t, exchangeYAML, "        asn: 64501\n", "        asn: 64501\n        max_prefix: 1000\n")
	y = edit(t, y, "    group: ix\n", "    group: ix\n    max_prefix_warn_pct: 80\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	ex := cfg.Exchanges[0]
	if ex.MaxPrefixWarnPct != 80 || ex.Peers[0].MaxPrefix != 1000 || ex.Peers[1].MaxPrefix != 0 {
		t.Fatalf("exchange = %+v", ex)
	}
	cfg, err = Parse([]byte(exchangeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Exchanges[0].MaxPrefixWarnPct; got != DefaultExchangeMaxPrefixWarnPct {
		t.Fatalf("default max_prefix_warn_pct = %d", got)
	}
}

func TestExchangeErrors(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"no lans":                {edit(t, exchangeYAML, "    lans: [203.0.113.0/24]\n", ""), "lans: at least one"},
		"bad lan":                {edit(t, exchangeYAML, "[203.0.113.0/24]", "[203.0.113.1/24]"), "not a CIDR without host bits"},
		"outside lan":            {edit(t, exchangeYAML, "next_hop: 203.0.113.12", "next_hop: 198.51.100.12"), "next_hop 198.51.100.12 is not inside"},
		"no asn":                 {edit(t, exchangeYAML, "        asn: 64502\n", ""), "asn is required"},
		"no peers":               {exchangeYAML[:strings.Index(exchangeYAML, "    peers:")] + "bgp:\n  neighbors:\n    - address: 192.0.2.254\n      add_path: true\n", "peers: at least one"},
		"no name":                {edit(t, exchangeYAML, "  - name: ix-lab\n    lans:", "  - lans:"), "exchanges[0]: name is required"},
		"name clash":             {edit(t, exchangeYAML, "name: ix-lab", "name: transit-a"), "name is also a provider name"},
		"own peer":               {edit(t, exchangeYAML, "name: ix-peer-b", "name: ix-lab"), "name is also a provider name"},
		"peer clash":             {edit(t, exchangeYAML, "name: ix-peer-b", "name: transit-a"), "duplicate provider name"},
		"source clash":           {edit(t, exchangeYAML, "source_ip: 192.0.2.32", "source_ip: 192.0.2.11"), "duplicate source_ip"},
		"no paths":               {edit(t, exchangeYAML, "      add_path: true\n", ""), "peers need their paths visible"},
		"negative max_prefix":    {edit(t, exchangeYAML, "        asn: 64501\n", "        asn: 64501\n        max_prefix: -1\n"), "max_prefix -1 must not be negative"},
		"bad max_prefix_warn":    {edit(t, exchangeYAML, "    group: ix\n", "    group: ix\n    max_prefix_warn_pct: 101\n"), "max_prefix_warn_pct 101 must be between 1 and 100"},
		"no bgp":                 {exchangeYAML[:strings.Index(exchangeYAML, "bgp:")], "exchanges require bgp.neighbors"},
		"bad as_path":            {exchangeYAML + "  as_path: origin\n", `bgp.as_path "origin" is invalid`},
		"allowlist equals lan":   {exchangeYAML + "allowlist:\n  prefixes: [203.0.113.0/24]\n", "overlaps exchange LAN 203.0.113.0/24"},
		"allowlist inside lan":   {exchangeYAML + "allowlist:\n  prefixes: [203.0.113.128/25]\n", "overlaps exchange LAN 203.0.113.0/24"},
		"allowlist contains lan": {exchangeYAML + "allowlist:\n  prefixes: [203.0.0.0/16]\n", "overlaps exchange LAN 203.0.113.0/24"},
		"allowlist v6 contains":  {edit(t, exchangeYAML, "lans: [203.0.113.0/24]", "lans: [203.0.113.0/24, 2001:db8:ffff::/64]") + "allowlist:\n  prefixes: [2001:db8::/32]\n", "overlaps exchange LAN 2001:db8:ffff::/64"},
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

func TestAllowlistBesideExchangeLAN(t *testing.T) {
	y := exchangeYAML + "allowlist:\n  prefixes: [198.51.100.0/24, \"2001:db8::/32\"]\n"
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Allowlist.Prefixes) != 2 {
		t.Fatalf("allowlist = %v", cfg.Allowlist.Prefixes)
	}
	// No exchanges: an allowlist may contain any documentation prefix.
	if _, err := Parse([]byte(minimalYAML + "allowlist:\n  prefixes: [203.0.113.0/24]\n")); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeHealthDefaults(t *testing.T) {
	cfg, err := Parse([]byte(exchangeYAML))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Exchanges[0].Health
	if !h.On() || h.LossPct != 50 || h.RTTMS != 0 || h.MinPeers != 3 || h.MinPercent != 0 || h.Window != 5*time.Minute {
		t.Fatalf("health defaults = %+v", h)
	}
}

func TestExchangeHealthSettings(t *testing.T) {
	y := edit(t, exchangeYAML, "    group: ix\n", `    group: ix
    health:
      enabled: false
      loss_pct: 20
      rtt_ms: 80
      min_peers: 2
      min_percent: 30
      window: 10m
`)
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Exchanges[0].Health
	if h.On() || h.LossPct != 20 || h.RTTMS != 80 || h.MinPeers != 2 || h.MinPercent != 30 || h.Window != 10*time.Minute {
		t.Fatalf("health = %+v", h)
	}
}

func TestExchangeHealthErrors(t *testing.T) {
	cases := map[string]struct{ set, want string }{
		"loss over 100":   {"loss_pct: 101", "loss_pct 101 must be above 0 and at most 100"},
		"loss negative":   {"loss_pct: -1", "loss_pct -1 must be above 0"},
		"rtt negative":    {"rtt_ms: -5", "rtt_ms -5 must be between 0 and"},
		"one peer":        {"min_peers: 1", "min_peers 1 must be at least 2"},
		"percent over":    {"min_percent: 101", "min_percent 101 must be between 0 and 100"},
		"window short":    {"window: 1s", "window 1s must be between probe.interval"},
		"window too long": {"window: 48h", "window 48h0m0s must be between probe.interval"},
		"unknown key":     {"min_peer: 3", "field min_peer not found"},
	}
	for name, tc := range cases {
		y := edit(t, exchangeYAML, "    group: ix\n", "    group: ix\n    health:\n      "+tc.set+"\n")
		_, err := Parse([]byte(y))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}

func TestExchangePort(t *testing.T) {
	y := edit(t, exchangeYAML, "    group: ix\n", "    group: ix\n    port:\n      capacity_mbps: 10000\n      commit_mbps: 6000\n      port_cost: 1500\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	pt := cfg.Exchanges[0].Port
	if pt == nil || pt.CapacityMbps != 10000 || pt.CommitMbps != 6000 || pt.PortCost == nil || *pt.PortCost != 1500 {
		t.Fatalf("port = %+v", pt)
	}
	for _, p := range cfg.Providers[1:] {
		if p.Cost == nil || *p.Cost != 0 {
			t.Fatalf("peer %s cost = %v, want marginal 0 under a flat port cost", p.Name, p.Cost)
		}
	}

	// Without port_cost the peers keep their own price, and the port needs
	// only a capacity.
	y = edit(t, exchangeYAML, "    group: ix\n", "    group: ix\n    port:\n      capacity_mbps: 1000\n")
	y = edit(t, y, "        asn: 64501\n", "        asn: 64501\n        cost: 3\n")
	cfg, err = Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if c := cfg.Providers[1].Cost; c == nil || *c != 3 || cfg.Providers[2].Cost != nil {
		t.Fatalf("peer costs = %v %v", cfg.Providers[1].Cost, cfg.Providers[2].Cost)
	}
	if cfg.Exchanges[0].Port.PortCost != nil || cfg.Exchanges[0].Port.CommitMbps != 0 {
		t.Fatalf("port = %+v", cfg.Exchanges[0].Port)
	}
	cfg, err = Parse([]byte(exchangeYAML))
	if err != nil || cfg.Exchanges[0].Port != nil {
		t.Fatalf("no port block: %v %+v", err, cfg.Exchanges[0].Port)
	}
}

func TestExchangePortErrors(t *testing.T) {
	withPort := func(block string) string {
		return edit(t, exchangeYAML, "    group: ix\n", "    group: ix\n    port:\n"+block)
	}
	cases := map[string]struct{ yaml, want string }{
		"no capacity":         {withPort("      commit_mbps: 10\n"), "port.capacity_mbps must be greater than 0"},
		"negative capacity":   {withPort("      capacity_mbps: -1\n"), "port.capacity_mbps must be greater than 0"},
		"huge capacity":       {withPort("      capacity_mbps: 1e9\n"), "port.capacity_mbps must be greater than 0"},
		"nan capacity":        {withPort("      capacity_mbps: .nan\n"), "port.capacity_mbps must be greater than 0"},
		"negative commit":     {withPort("      capacity_mbps: 100\n      commit_mbps: -5\n"), "port.commit_mbps -5 must be between 0 and capacity_mbps"},
		"commit over cap":     {withPort("      capacity_mbps: 100\n      commit_mbps: 101\n"), "port.commit_mbps 101 must be between 0 and capacity_mbps"},
		"negative port cost":  {withPort("      capacity_mbps: 100\n      port_cost: -1\n"), "port.port_cost -1 must be between"},
		"unknown port key":    {withPort("      capacity_mbps: 100\n      billing_day: 1\n"), "billing_day"},
		"peer cost conflicts": {edit(t, withPort("      capacity_mbps: 100\n      port_cost: 10\n"), "        asn: 64501\n", "        asn: 64501\n        cost: 2\n"), "peers[0] (ix-peer-a): cost conflicts with port.port_cost"},
	}
	for name, tc := range cases {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tc.want)
		}
	}
}
