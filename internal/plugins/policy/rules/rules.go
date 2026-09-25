// Package rules implements the "rules" policy: routing policies matched by
// prefix, origin ASN, or country, with the actions ignore, allow, deny,
// static, and vip.
//
// Precedence between overlapping rules is fixed. A prefix match beats an
// ASN match, which beats a country match. Among prefix matches the longest
// rule prefix wins. Remaining ties go to the rule listed first.
//
// Country lookups read a MaxMind-format database (for example
// GeoLite2-Country.mmdb) from a path the operator mounts into the container.
// The database is never shipped with Packeteer. It is read once when the
// plugin is built; restart to load a new one.
//
// The plugin does not announce. Decide still requires the prefix in the
// learned RIB, the allowlist in inject mode, the improvement cap, and a
// usable path before any route is announced.
package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the plugin type used in config.
const TypeName = "rules"

// MaxRules caps the rule list.
const MaxRules = 10000

func init() { plugin.Policies.Register(TypeName, New) }

// Config is the rules policy's config block.
type Config struct {
	// GeoIPDB is the path of a MaxMind-format country database. Required
	// when any rule lists countries.
	GeoIPDB string `yaml:"geoip_db"`
	Rules   []Rule `yaml:"rules"`
}

// Rule is one routing policy. A rule matches when any of its prefixes,
// ASNs, or countries match.
type Rule struct {
	Name      string   `yaml:"name"`
	Action    string   `yaml:"action"`
	Providers []string `yaml:"providers"`
	// Prefixes match an equal or more-specific probed prefix.
	Prefixes []string `yaml:"prefixes"`
	// ASNs match the origin ASN of the learned AS path.
	ASNs []uint32 `yaml:"asns"`
	// Countries are ISO 3166-1 alpha-2 codes, looked up for the first
	// address of the prefix.
	Countries []string `yaml:"countries"`
}

type rule struct {
	name      string
	verdict   plugin.PolicyVerdict
	prefixes  []netip.Prefix
	asns      map[uint32]bool
	countries map[string]bool
}

// Policy is the rules policy.
type Policy struct {
	plugin.Base
	rules []rule
	geo   *maxminddb.Reader
}

// geoRecord is the part of a GeoIP2/GeoLite2 country record we read.
type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// New is the plugin factory. It reads the GeoIP database when one is
// configured, and does no network I/O.
func New(c plugin.Config, env plugin.Env) (plugin.Policy, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	rules, needGeo, err := compile(cfg.Rules, env.Providers)
	if err != nil {
		return nil, err
	}
	p := &Policy{rules: rules}
	switch {
	case needGeo && cfg.GeoIPDB == "":
		return nil, errors.New("geoip_db is required when a rule lists countries")
	case cfg.GeoIPDB != "":
		data, err := os.ReadFile(cfg.GeoIPDB)
		if err != nil {
			return nil, fmt.Errorf("geoip_db: %w", err)
		}
		db, err := maxminddb.OpenBytes(data)
		if err != nil {
			return nil, fmt.Errorf("geoip_db %s: %w", cfg.GeoIPDB, err)
		}
		p.geo = db
	}
	return p, nil
}

func compile(in []Rule, providers []string) ([]rule, bool, error) {
	if len(in) == 0 {
		return nil, false, errors.New("rules: at least one rule is required")
	}
	if len(in) > MaxRules {
		return nil, false, fmt.Errorf("rules: at most %d rules", MaxRules)
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	known := map[string]bool{}
	for _, n := range providers {
		known[n] = true
	}
	names := map[string]bool{}
	needGeo := false
	out := make([]rule, 0, len(in))
	for i, r := range in {
		label := fmt.Sprintf("rules[%d]", i)
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = label
		} else {
			label = fmt.Sprintf("rules[%d] (%s)", i, name)
		}
		if names[name] {
			add("%s: duplicate rule name", label)
		}
		names[name] = true

		cr := rule{name: name, asns: map[uint32]bool{}, countries: map[string]bool{}}
		action := strings.ToLower(strings.TrimSpace(r.Action))
		switch action {
		case plugin.PolicyIgnore, plugin.PolicyVIP:
			if len(r.Providers) > 0 {
				add("%s: action %s takes no providers", label, action)
			}
		case plugin.PolicyAllow, plugin.PolicyDeny:
			if len(r.Providers) == 0 {
				add("%s: action %s needs at least one provider", label, action)
			}
		case plugin.PolicyStatic:
			if len(r.Providers) != 1 {
				add("%s: action static needs exactly one provider", label)
			}
		case "":
			add("%s: action is required (ignore, allow, deny, static, or vip)", label)
		default:
			add("%s: action %q is invalid (want ignore, allow, deny, static, or vip)", label, r.Action)
		}
		seenProv := map[string]bool{}
		for _, pn := range r.Providers {
			if providers != nil && !known[pn] {
				add("%s: provider %q is not configured", label, pn)
			}
			if seenProv[pn] {
				add("%s: duplicate provider %q", label, pn)
			}
			seenProv[pn] = true
		}
		cr.verdict = plugin.PolicyVerdict{Action: action, Providers: slices.Clone(r.Providers), Rule: name}

		for j, s := range r.Prefixes {
			p, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				add("%s: prefixes[%d] %q is not a valid CIDR", label, j, s)
				continue
			}
			if p != p.Masked() {
				add("%s: prefixes[%d] %q has host bits set (did you mean %s?)", label, j, s, p.Masked())
				continue
			}
			cr.prefixes = append(cr.prefixes, p)
		}
		for _, a := range r.ASNs {
			if a == 0 {
				add("%s: asn 0 is invalid", label)
				continue
			}
			cr.asns[a] = true
		}
		for _, c := range r.Countries {
			code := strings.ToUpper(strings.TrimSpace(c))
			if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
				add("%s: country %q must be an ISO 3166-1 alpha-2 code", label, c)
				continue
			}
			cr.countries[code] = true
			needGeo = true
		}
		if len(r.Prefixes) == 0 && len(r.ASNs) == 0 && len(r.Countries) == 0 {
			add("%s: at least one of prefixes, asns, or countries is required", label)
		}
		out = append(out, cr)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, false, err
	}
	return out, needGeo, nil
}

// Match returns the verdict of the highest-precedence matching rule.
func (p *Policy) Match(s plugin.PolicySubject) (plugin.PolicyVerdict, bool) {
	if !s.Prefix.IsValid() {
		return plugin.PolicyVerdict{}, false
	}
	// Prefix rules: longest rule prefix wins, then list order.
	best, bestBits := -1, -1
	var bestPrefix netip.Prefix
	for i, r := range p.rules {
		for _, rp := range r.prefixes {
			if rp.Bits() <= s.Prefix.Bits() && rp.Contains(s.Prefix.Addr()) && rp.Bits() > bestBits {
				best, bestBits, bestPrefix = i, rp.Bits(), rp
			}
		}
	}
	if best >= 0 {
		return p.verdict(best, "prefix "+bestPrefix.String()), true
	}
	if origin := s.OriginASN(); origin != 0 {
		for i, r := range p.rules {
			if r.asns[origin] {
				return p.verdict(i, fmt.Sprintf("asn %d", origin)), true
			}
		}
	}
	if code := p.country(s.Prefix.Addr()); code != "" {
		for i, r := range p.rules {
			if r.countries[code] {
				return p.verdict(i, "country "+code), true
			}
		}
	}
	return plugin.PolicyVerdict{}, false
}

func (p *Policy) verdict(i int, match string) plugin.PolicyVerdict {
	v := p.rules[i].verdict
	v.Providers = slices.Clone(v.Providers)
	v.Match = match
	return v
}

// country returns the ISO code for addr, or "" when there is no database
// or no record. A lookup error is treated as no match.
func (p *Policy) country(addr netip.Addr) string {
	if p.geo == nil || !addr.IsValid() {
		return ""
	}
	var rec geoRecord
	if err := p.geo.Lookup(addr.Unmap()).Decode(&rec); err != nil {
		return ""
	}
	if rec.Country.ISOCode != "" {
		return strings.ToUpper(rec.Country.ISOCode)
	}
	return strings.ToUpper(rec.RegisteredCountry.ISOCode)
}
