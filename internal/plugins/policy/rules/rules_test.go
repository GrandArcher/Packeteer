package rules

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var providers = []string{"transit-a", "transit-b", "transit-c"}

func build(t *testing.T, yaml string) (*Policy, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(c, plugin.Env{Providers: providers})
	if err != nil {
		return nil, err
	}
	return p.(*Policy), nil
}

func mustBuild(t *testing.T, yaml string) *Policy {
	t.Helper()
	p, err := build(t, yaml)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestRegistered(t *testing.T) {
	if !plugin.Policies.Has(TypeName) {
		t.Fatal("rules policy not registered")
	}
}

func TestEachAction(t *testing.T) {
	p := mustBuild(t, `
rules:
  - {name: skip, action: ignore, prefixes: [192.0.2.0/24]}
  - {name: only-a, action: allow, providers: [transit-a], prefixes: [198.51.100.0/25]}
  - {name: no-b, action: deny, providers: [transit-b], prefixes: [198.51.100.128/25]}
  - {name: pin-c, action: static, providers: [transit-c], prefixes: [203.0.113.0/25], max_loss_pct: 2, max_rtt: 80ms}
  - {name: gold, action: vip, prefixes: [203.0.113.128/25]}
`)
	tests := []struct {
		prefix    string
		action    string
		providers []string
		rule      string
	}{
		{"192.0.2.0/24", plugin.PolicyIgnore, nil, "skip"},
		{"198.51.100.0/25", plugin.PolicyAllow, []string{"transit-a"}, "only-a"},
		{"198.51.100.128/26", plugin.PolicyDeny, []string{"transit-b"}, "no-b"},
		{"203.0.113.0/25", plugin.PolicyStatic, []string{"transit-c"}, "pin-c"},
		{"203.0.113.128/25", plugin.PolicyVIP, nil, "gold"},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			v, ok := p.Match(plugin.PolicySubject{Prefix: netip.MustParsePrefix(tt.prefix)})
			if !ok {
				t.Fatal("no match")
			}
			if v.Action != tt.action || v.Rule != tt.rule || strings.Join(v.Providers, ",") != strings.Join(tt.providers, ",") {
				t.Fatalf("verdict = %+v", v)
			}
			if !strings.HasPrefix(v.Match, "prefix ") {
				t.Fatalf("match = %q", v.Match)
			}
			if tt.action == plugin.PolicyStatic && (v.MaxLossPct != 2 || v.MaxRTT != 80*time.Millisecond) {
				t.Fatalf("static ceiling = %v %v", v.MaxLossPct, v.MaxRTT)
			}
		})
	}
	// A less specific prefix than the rule does not match.
	if v, ok := p.Match(plugin.PolicySubject{Prefix: netip.MustParsePrefix("198.51.100.0/24")}); ok {
		t.Fatalf("covering prefix matched: %+v", v)
	}
}

func TestPrecedence(t *testing.T) {
	db := writeCountryDB(t, map[string]string{
		"192.0.2.0/24":    "NL",
		"198.51.100.0/24": "DE",
		"2001:db8::/32":   "NL",
	})
	p := mustBuild(t, `
geoip_db: `+db+`
rules:
  - {name: country-nl, action: deny, providers: [transit-a], countries: [nl]}
  - {name: asn-64500, action: allow, providers: [transit-b], asns: [64500]}
  - {name: asn-64500-late, action: ignore, asns: [64500]}
  - {name: wide, action: deny, providers: [transit-c], prefixes: [192.0.2.0/23]}
  - {name: narrow, action: static, providers: [transit-b], prefixes: [192.0.2.0/25], max_loss_pct: 1}
  - {name: first-equal, action: vip, prefixes: [198.51.100.0/24]}
  - {name: second-equal, action: ignore, prefixes: [198.51.100.0/24]}
`)
	tests := []struct {
		name   string
		prefix string
		path   []uint32
		rule   string
		match  string
	}{
		{"longest prefix wins", "192.0.2.0/25", []uint32{64501, 64500}, "narrow", "prefix 192.0.2.0/25"},
		{"shorter prefix still beats asn", "192.0.2.128/25", []uint32{64500}, "wide", "prefix 192.0.2.0/23"},
		{"equal prefix: first listed wins", "198.51.100.0/24", nil, "first-equal", "prefix 198.51.100.0/24"},
		{"asn beats country", "2001:db8:1::/48", []uint32{64510, 64500}, "asn-64500", "asn 64500"},
		{"origin only, transit asn ignored", "2001:db8:2::/48", []uint32{64500, 64510}, "country-nl", "country NL"},
		{"country alone", "2001:db8:3::/48", nil, "country-nl", "country NL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, ok := p.Match(plugin.PolicySubject{Prefix: netip.MustParsePrefix(tt.prefix), ASPath: tt.path})
			if !ok {
				t.Fatal("no match")
			}
			if v.Rule != tt.rule || v.Match != tt.match {
				t.Fatalf("got rule %q match %q, want %q %q", v.Rule, v.Match, tt.rule, tt.match)
			}
		})
	}
	// No rule matches an address outside the database and every rule.
	if v, ok := p.Match(plugin.PolicySubject{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64511}}); ok {
		t.Fatalf("unexpected match %+v", v)
	}
}

func TestVerdictIsACopy(t *testing.T) {
	p := mustBuild(t, `rules: [{action: deny, providers: [transit-a], prefixes: [192.0.2.0/24]}]`)
	v, _ := p.Match(plugin.PolicySubject{Prefix: netip.MustParsePrefix("192.0.2.0/24")})
	v.Providers[0] = "mutated"
	v2, _ := p.Match(plugin.PolicySubject{Prefix: netip.MustParsePrefix("192.0.2.0/24")})
	if v2.Providers[0] != "transit-a" || v2.Rule != "rules[0]" {
		t.Fatalf("verdict = %+v", v2)
	}
}

func TestValidation(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"empty", ``, "at least one rule"},
		{"unknown field", `rules: [{action: vip, prefixes: [192.0.2.0/24], bogus: 1}]`, "field bogus not found"},
		{"no action", `rules: [{prefixes: [192.0.2.0/24]}]`, "action is required"},
		{"bad action", `rules: [{action: prefer, prefixes: [192.0.2.0/24]}]`, `action "prefer" is invalid`},
		{"no match", `rules: [{action: vip}]`, "at least one of prefixes, asns, or countries"},
		{"deny without providers", `rules: [{action: deny, prefixes: [192.0.2.0/24]}]`, "needs at least one provider"},
		{"allow without providers", `rules: [{action: allow, prefixes: [192.0.2.0/24]}]`, "needs at least one provider"},
		{"static two providers", `rules: [{action: static, providers: [transit-a, transit-b], prefixes: [192.0.2.0/24], max_loss_pct: 1}]`, "exactly one provider"},
		{"static without loss ceiling", `rules: [{action: static, providers: [transit-a], prefixes: [192.0.2.0/24]}]`, "needs max_loss_pct"},
		{"static loss ceiling over 100", `rules: [{action: static, providers: [transit-a], prefixes: [192.0.2.0/24], max_loss_pct: 101}]`, "must be 0-100"},
		{"static negative loss ceiling", `rules: [{action: static, providers: [transit-a], prefixes: [192.0.2.0/24], max_loss_pct: -1}]`, "must be 0-100"},
		{"static negative rtt", `rules: [{action: static, providers: [transit-a], prefixes: [192.0.2.0/24], max_loss_pct: 1, max_rtt: -1s}]`, "max_rtt must not be negative"},
		{"ceiling on non-static", `rules: [{action: vip, prefixes: [192.0.2.0/24], max_loss_pct: 1}]`, "apply only to action static"},
		{"ignore with providers", `rules: [{action: ignore, providers: [transit-a], prefixes: [192.0.2.0/24]}]`, "takes no providers"},
		{"unknown provider", `rules: [{action: deny, providers: [transit-z], prefixes: [192.0.2.0/24]}]`, `provider "transit-z" is not configured`},
		{"duplicate provider", `rules: [{action: deny, providers: [transit-a, transit-a], prefixes: [192.0.2.0/24]}]`, "duplicate provider"},
		{"bad prefix", `rules: [{action: vip, prefixes: [nope]}]`, "not a valid CIDR"},
		{"host bits", `rules: [{action: vip, prefixes: [192.0.2.1/24]}]`, "host bits set"},
		{"asn zero", `rules: [{action: vip, asns: [0]}]`, "asn 0 is invalid"},
		{"bad country", `rules: [{action: vip, countries: [NLD]}]`, "ISO 3166-1 alpha-2"},
		{"country without db", `rules: [{action: vip, countries: [NL]}]`, "geoip_db is required"},
		{"missing db", "geoip_db: /nonexistent/country.mmdb\nrules: [{action: vip, countries: [NL]}]", "geoip_db"},
		{"duplicate name", `rules: [{name: x, action: vip, asns: [64500]}, {name: x, action: vip, asns: [64501]}]`, "duplicate rule name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := build(t, tt.yaml)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestBadGeoIPFile(t *testing.T) {
	path := t.TempDir() + "/junk.mmdb"
	if err := writeFile(path, "not a database"); err != nil {
		t.Fatal(err)
	}
	_, err := build(t, "geoip_db: "+path+"\nrules: [{action: vip, countries: [NL]}]")
	if err == nil || !strings.Contains(err.Error(), "geoip_db") {
		t.Fatalf("err = %v", err)
	}
}
