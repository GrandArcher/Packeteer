// Package linkout builds the "open in" links on the prefix, ASN, and
// provider pages (#211). It only formats URLs from an object's own prefix
// or ASN. Packeteer never requests any of these sites, scrapes them, or
// stores what they show.
package linkout

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Limits on the operator's custom templates.
const (
	MaxCustom     = 20
	MaxNameLength = 40
)

// Kind is the object a link is built from.
type Kind string

const (
	KindPrefix Kind = "prefix"
	KindASN    Kind = "asn"
)

type site struct {
	id    string
	title string
	// prefix and asn are URL templates; empty means the site has no page
	// for that kind.
	prefix string
	asn    string
}

// builtin is every site Packeteer knows. NLNOG RING is a public looking
// glass page the operator opens by hand: Packeteer neither calls its API
// nor logs in to or runs commands on RING nodes, so it is off by default.
var builtin = []site{
	{"he", "HE BGP Toolkit", "https://bgp.he.net/net/{prefix}", "https://bgp.he.net/AS{asn}"},
	{"he_lg", "HE looking glass", "https://lg.he.net/", ""},
	{"ripestat", "RIPEstat", "https://stat.ripe.net/app/launchpad/{prefix}", "https://stat.ripe.net/app/launchpad/AS{asn}"},
	{"peeringdb", "PeeringDB", "", "https://www.peeringdb.com/asn/{asn}"},
	{"bgptools", "bgp.tools", "https://bgp.tools/prefix/{prefix}", "https://bgp.tools/as/{asn}"},
	{"cloudflare_radar", "Cloudflare Radar", "", "https://radar.cloudflare.com/routing/as{asn}"},
	{"irr_explorer", "IRR Explorer", "https://irrexplorer.nlnog.net/prefix/{prefix}", ""},
	{"nlnog_ring", "NLNOG RING looking glass", "https://lg.ring.nlnog.net/prefix?q={prefix}", ""},
}

// defaults are the sites shown when linkouts.enabled is not set.
var defaults = []string{"he", "he_lg", "ripestat", "peeringdb", "bgptools", "cloudflare_radar", "irr_explorer"}

// Custom is an operator template, for example an internal looking glass.
type Custom struct {
	Name string `yaml:"name"`
	// URL is an https URL holding {prefix} or {asn}, one of the two.
	URL string `yaml:"url"`
}

// Config is the linkouts block.
type Config struct {
	// Enabled lists the built-in sites to show. Unset shows the defaults;
	// an empty list shows none.
	Enabled []string `yaml:"enabled"`
	// Custom adds operator templates. They are always shown.
	Custom []Custom `yaml:"custom"`
	// HideInternal builds no link for an RFC 1918, ULA, loopback, or
	// link-local prefix or a private-use ASN (default true).
	HideInternal *bool `yaml:"hide_internal"`
}

func (c Config) hideInternal() bool { return c.HideInternal == nil || *c.HideInternal }

// Link is one link-out.
type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type entry struct {
	name string
	tmpl string
}

// Set builds links. Safe for concurrent use: it is read-only.
type Set struct {
	hide   bool
	prefix []entry
	asn    []entry
}

// Sample values stand in for the placeholders when a template is checked.
const (
	samplePrefix = "192.0.2.0/24"
	sampleASN    = "64496"
)

// ValidateTemplate checks a custom URL template and returns the kind it
// serves. Only https is accepted, the host cannot hold a placeholder, and
// exactly one of {prefix} and {asn} must appear.
func ValidateTemplate(tmpl string) (Kind, error) {
	var kind Kind
	rest := tmpl
	for {
		i := strings.IndexAny(rest, "{}")
		if i < 0 {
			break
		}
		if rest[i] == '}' {
			return "", fmt.Errorf("url %q: unmatched }", tmpl)
		}
		j := strings.IndexByte(rest[i:], '}')
		if j < 0 {
			return "", fmt.Errorf("url %q: unmatched {", tmpl)
		}
		var k Kind
		switch ph := rest[i+1 : i+j]; ph {
		case "prefix":
			k = KindPrefix
		case "asn":
			k = KindASN
		default:
			return "", fmt.Errorf("url %q: unknown placeholder {%s} (want {prefix} or {asn})", tmpl, ph)
		}
		if kind != "" && kind != k {
			return "", fmt.Errorf("url %q: use {prefix} or {asn}, not both", tmpl)
		}
		kind = k
		rest = rest[i+j+1:]
	}
	if kind == "" {
		return "", fmt.Errorf("url %q: must contain {prefix} or {asn}", tmpl)
	}
	u, err := url.Parse(strings.NewReplacer("{prefix}", samplePrefix, "{asn}", sampleASN).Replace(tmpl))
	switch {
	case err != nil:
		return "", fmt.Errorf("url %q: %v", tmpl, err)
	case u.Scheme != "https" || u.Host == "":
		return "", fmt.Errorf("url %q: must be an https URL with a host", tmpl)
	case u.User != nil:
		return "", fmt.Errorf("url %q: must not hold credentials", tmpl)
	case u.Fragment != "":
		return "", fmt.Errorf("url %q: must not hold a fragment", tmpl)
	}
	// The placeholder is data from the table: it may fill a path or query
	// value, never choose the site.
	authority := strings.TrimPrefix(tmpl, "https://")
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	if strings.ContainsAny(authority, "{}") {
		return "", fmt.Errorf("url %q: the host cannot hold a placeholder", tmpl)
	}
	return kind, nil
}

// Validate reports every problem with the block.
func (c Config) Validate(add func(string, ...any)) {
	seen := map[string]bool{}
	for _, id := range c.Enabled {
		switch {
		case !slices.ContainsFunc(builtin, func(s site) bool { return s.id == id }):
			add("linkouts.enabled: %q is not a link-out site (want one of %s)", id, strings.Join(ids(), ", "))
		case seen[id]:
			add("linkouts.enabled: %q is listed twice", id)
		}
		seen[id] = true
	}
	if len(c.Custom) > MaxCustom {
		add("linkouts.custom: at most %d entries", MaxCustom)
	}
	names := map[string]bool{}
	for i, cu := range c.Custom {
		where := fmt.Sprintf("linkouts.custom[%d]", i)
		switch {
		case cu.Name == "" || len(cu.Name) > MaxNameLength || strings.ContainsFunc(cu.Name, func(r rune) bool { return r < ' ' || r == 0x7f }):
			add("%s: name must be 1-%d printable characters", where, MaxNameLength)
		case names[cu.Name]:
			add("%s: name %q is used twice", where, cu.Name)
		}
		names[cu.Name] = true
		if _, err := ValidateTemplate(cu.URL); err != nil {
			add("%s: %v", where, err)
		}
	}
}

func ids() []string {
	out := make([]string, len(builtin))
	for i, s := range builtin {
		out[i] = s.id
	}
	return out
}

// New builds the set from a validated block.
func New(c Config) *Set {
	s := &Set{hide: c.hideInternal()}
	enabled := c.Enabled
	if enabled == nil {
		enabled = defaults
	}
	for _, b := range builtin {
		if !slices.Contains(enabled, b.id) {
			continue
		}
		if b.prefix != "" {
			s.prefix = append(s.prefix, entry{b.title, b.prefix})
		}
		if b.asn != "" {
			s.asn = append(s.asn, entry{b.title, b.asn})
		}
	}
	for _, cu := range c.Custom {
		kind, err := ValidateTemplate(cu.URL)
		switch {
		case err != nil:
			continue
		case kind == KindPrefix:
			s.prefix = append(s.prefix, entry{cu.Name, cu.URL})
		default:
			s.asn = append(s.asn, entry{cu.Name, cu.URL})
		}
	}
	return s
}

// Prefix returns the links for p, none when p is internal and
// hide_internal is on.
func (s *Set) Prefix(p netip.Prefix) []Link {
	p = p.Masked()
	if s.hide && internalAddr(p.Addr()) {
		return []Link{}
	}
	// "/" and ":" are legal in a path and a query, so a CIDR stays readable.
	v := strings.ReplaceAll(url.PathEscape(p.String()), "%2F", "/")
	return fill(s.prefix, "{prefix}", v)
}

// ASN returns the links for n, none when n is private-use and hide_internal
// is on.
func (s *Set) ASN(n uint32) []Link {
	if n == 0 || s.hide && privateASN(n) {
		return []Link{}
	}
	return fill(s.asn, "{asn}", strconv.FormatUint(uint64(n), 10))
}

func fill(es []entry, placeholder, value string) []Link {
	out := make([]Link, 0, len(es))
	for _, e := range es {
		out = append(out, Link{Name: e.name, URL: strings.ReplaceAll(e.tmpl, placeholder, value)})
	}
	return out
}

func internalAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified()
}

// privateASN is the RFC 6996 private-use range, 16 and 32 bit.
func privateASN(n uint32) bool {
	return n >= 64512 && n <= 65534 || n >= 4200000000 && n <= 4294967294
}
