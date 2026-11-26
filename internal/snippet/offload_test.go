package snippet

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func offload() Params {
	p := std()
	p.OffloadCommunity = "64512:777"
	return p
}

func offloadLargeV6() Params {
	p := large()
	p.OffloadCommunity = "64512:2:777"
	p.IPv6 = true
	return p
}

func TestOffloadGolden(t *testing.T) {
	for name, p := range map[string]Params{"mikrotik-offload": offload(), "mikrotik-offload-large-v6": offloadLargeV6()} {
		got, err := Generate(MikroTik, p)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, name, got)
	}
}

// ruleLines returns the "/routing filter rule add" commands of the snippet,
// continuation lines joined, in order.
func ruleLines(text string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(text, "\\\n", ""), "\n") {
		if strings.HasPrefix(l, "/routing filter rule add") {
			out = append(out, strings.Join(strings.Fields(l), " "))
		}
	}
	return out
}

func indexOf(t *testing.T, lines []string, sub string) int {
	t.Helper()
	for i, l := range lines {
		if strings.Contains(l, sub) {
			return i
		}
	}
	t.Fatalf("no rule contains %q in\n%s", sub, strings.Join(lines, "\n"))
	return -1
}

// The offload community only picks the hardware attribute: it never decides
// accept or reject on the way in, and it is rejected toward eBGP, below the
// Packeteer community.
func TestOffloadRuleOrderAndExport(t *testing.T) {
	text, err := Generate(MikroTik, offload())
	if err != nil {
		t.Fatal(err)
	}
	rules := ruleLines(text)
	yes := indexOf(t, rules, "chain=packeteer-in rule=\"if (bgp-communities includes 64512:666) { set suppress-hw-offload yes }\"")
	no := indexOf(t, rules, "chain=packeteer-in rule=\"if (bgp-communities includes 64512:777) { set suppress-hw-offload no }\"")
	accept := indexOf(t, rules, "chain=packeteer-in rule=\"if (bgp-communities includes 64512:666) { accept }\"")
	reject := indexOf(t, rules, "chain=packeteer-in rule=\"reject\"")
	if !(yes < no && no < accept && accept < reject) {
		t.Errorf("packeteer-in order: yes %d, no %d, accept %d, reject %d", yes, no, accept, reject)
	}
	for _, r := range rules {
		if strings.Contains(r, "64512:777") && (strings.Contains(r, "accept") || strings.Contains(r, "set suppress-hw-offload yes")) {
			t.Errorf("the offload community decides more than the attribute: %s", r)
		}
	}
	// place-before=0 puts the later command on top: the Packeteer reject
	// must be added after the offload reject so it stays rule 1.
	off := indexOf(t, rules, "chain=ebgp-out place-before=0 rule=\"if (bgp-communities includes 64512:777) { reject }\"")
	pk := indexOf(t, rules, "chain=ebgp-out place-before=0 rule=\"if (bgp-communities includes 64512:666) { reject }\"")
	if off > pk {
		t.Errorf("ebgp-out: offload reject at %d is added after the Packeteer reject at %d", off, pk)
	}
	indexOf(t, rules, "chain=ebgp-in place-before=0 rule=\"if (dst == 0.0.0.0/0) { set suppress-hw-offload yes }\"")
	if strings.Contains(text, "::/0") {
		t.Errorf("an IPv6 default rule without IPv6:\n%s", text)
	}
}

func TestOffloadLargeAndIPv6(t *testing.T) {
	text, err := Generate(MikroTik, offloadLargeV6())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"if (bgp-large-communities includes 64512:1:666) { set suppress-hw-offload yes }",
		"if (bgp-large-communities includes 64512:2:777) { set suppress-hw-offload no }",
		"chain=ebgp-out place-before=0 rule=\"if (bgp-large-communities includes 64512:2:777) { reject }\"",
		"if (dst == ::/0) { set suppress-hw-offload yes }",
	} {
		if !strings.Contains(strings.ReplaceAll(text, "\\\n    ", ""), want) {
			t.Errorf("%q missing from\n%s", want, text)
		}
	}
	mixed := std()
	mixed.OffloadCommunity = "64512:2:777"
	text, err = Generate(MikroTik, mixed)
	if err != nil || !strings.Contains(strings.ReplaceAll(text, "\\\n    ", ""), "if (bgp-communities includes 64512:666) { set suppress-hw-offload yes }") ||
		!strings.Contains(strings.ReplaceAll(text, "\\\n    ", ""), "if (bgp-large-communities includes 64512:2:777) { set suppress-hw-offload no }") {
		t.Errorf("a standard Packeteer community with a large offload community: %v\n%s", err, text)
	}
}

// Every other vendor prints what it printed before: the offload hardware
// decision is a RouterOS feature.
func TestOffloadCommunityChangesOnlyMikroTik(t *testing.T) {
	for _, vendor := range Vendors {
		plain, err := Generate(vendor, std())
		if err != nil {
			t.Fatal(err)
		}
		with, err := Generate(vendor, offload())
		if err != nil {
			t.Fatal(err)
		}
		if (plain == with) == (vendor == MikroTik) {
			t.Errorf("%s: output changed = %v", vendor, plain != with)
		}
		if strings.Contains(with, "64512:777") && vendor != MikroTik {
			t.Errorf("%s mentions the offload community", vendor)
		}
	}
}

func offloadConfig(t *testing.T, enabled bool, community string) *config.Config {
	t.Helper()
	cfg := loadConfig(t, "    - address: 192.0.2.253\n")
	cfg.OffloadAware = &config.OffloadAware{Enabled: enabled, Routers: []config.OffloadRouter{
		{Neighbor: "192.0.2.254", OffloadCommunity: community},
		{Neighbor: "192.0.2.253"},
	}}
	return cfg
}

func TestForConfigReadsTheOffloadCommunityPerRouter(t *testing.T) {
	ps, err := ForConfig(offloadConfig(t, true, "64512:777"))
	if err != nil {
		t.Fatal(err)
	}
	if ps[0].OffloadCommunity != "64512:777" || ps[1].OffloadCommunity != "" {
		t.Errorf("offload communities = %q, %q; want only the first router to carry one", ps[0].OffloadCommunity, ps[1].OffloadCommunity)
	}
	ps, err = ForConfig(offloadConfig(t, false, "64512:777"))
	if err != nil || ps[0].OffloadCommunity != "" {
		t.Errorf("offload_aware disabled: %+v, %v", ps, err)
	}
	cfg := loadConfig(t, "")
	ps, err = ForConfig(cfg)
	if err != nil || ps[0].OffloadCommunity != "" {
		t.Errorf("no offload_aware block: %+v, %v", ps, err)
	}
}

func TestForConfigRefusesTheOffloadCommunityEqualToPacketeers(t *testing.T) {
	if _, err := ForConfig(offloadConfig(t, true, "64512:666")); err == nil || !strings.Contains(err.Error(), "is the packeteer_community") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ForConfig(offloadConfig(t, true, "bogus")); err == nil || !strings.Contains(err.Error(), "offload_community") {
		t.Fatalf("bad community err = %v", err)
	}
}

// lab/chr/offload.rsc is what lab/e2e-chr.sh applies to the CHR. Each rule
// it adds for these chains must be a line the snippet prints, in the same
// order, so the lab proves the generated text.
func TestLabOffloadRulesAreTheSnippet(t *testing.T) {
	raw, err := os.ReadFile("../../lab/chr/offload.rsc")
	if err != nil {
		t.Fatal(err)
	}
	text, err := Generate(MikroTik, offload())
	if err != nil {
		t.Fatal(err)
	}
	chain := regexp.MustCompile(`chain=(packeteer-in|ebgp-out|ebgp-in) `)
	var want []string
	for _, l := range ruleLines(text) {
		if chain.MatchString(l) {
			want = append(want, l)
		}
	}
	var got []string
	for _, l := range ruleLines(string(raw)) {
		if chain.MatchString(l) && !strings.HasSuffix(l, `rule="accept"`) {
			got = append(got, l)
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lab/chr/offload.rsc differs from the snippet:\n--- lab\n%s\n--- snippet\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
