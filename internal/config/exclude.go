package config

import "net/netip"

// ExcludeList is a list of prefixes and ASNs a feature leaves alone. The
// herd share block and probe.exclude (#203) read it; each documents what
// a match means for it.
type ExcludeList struct {
	Prefixes []string `yaml:"prefixes"`
	ASNs     []uint32 `yaml:"asns"`
}

// PrefixList is the exclude prefixes, parsed. Validate has already
// checked them.
func (e ExcludeList) PrefixList() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(e.Prefixes))
	for _, s := range e.Prefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// Empty reports whether nothing is listed.
func (e ExcludeList) Empty() bool { return len(e.Prefixes) == 0 && len(e.ASNs) == 0 }

// validate reports each malformed entry under key (for example
// "herd.share.exclude").
func (e ExcludeList) validate(add func(string, ...any), key string) {
	for i, s := range e.Prefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			add("%s.prefixes[%d]: %q is not a prefix", key, i, s)
		} else if p != p.Masked() {
			add("%s.prefixes[%d]: %q has host bits set", key, i, s)
		}
	}
	for i, a := range e.ASNs {
		if a == 0 {
			add("%s.asns[%d]: 0 is not an ASN", key, i)
		}
	}
}
