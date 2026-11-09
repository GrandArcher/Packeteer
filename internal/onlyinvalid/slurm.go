package onlyinvalid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SLURM is a local exceptions file (RFC 8416). Packeteer writes prefix
// filters and prefix assertions only; BGPsec members read from an existing
// file are kept as they are.
type SLURM struct {
	Version    int        `json:"slurmVersion"`
	Filters    Filters    `json:"validationOutputFilters"`
	Assertions Assertions `json:"locallyAddedAssertions"`
	// unknownKeys and missing are set by ParseSLURM and refused by
	// Validate.
	unknownKeys []string
	missing     []string
}

// Filters is the validationOutputFilters member (RFC 8416 section 3.3).
type Filters struct {
	Prefix []PrefixFilter   `json:"prefixFilters"`
	BGPsec []map[string]any `json:"bgpsecFilters"`
}

// Assertions is the locallyAddedAssertions member (RFC 8416 section 3.4).
type Assertions struct {
	Prefix []PrefixAssertion `json:"prefixAssertions"`
	BGPsec []map[string]any  `json:"bgpsecAssertions"`
}

// PrefixFilter removes the VRPs it matches: those whose prefix is equal to
// or more specific than Prefix, and whose AS is ASN, when each is set.
type PrefixFilter struct {
	Prefix  *netip.Prefix `json:"prefix,omitempty"`
	ASN     *uint32       `json:"asn,omitempty"`
	Comment string        `json:"comment,omitempty"`
}

// PrefixAssertion adds one VRP. MaxLength nil means the prefix length.
type PrefixAssertion struct {
	ASN       uint32       `json:"asn"`
	Prefix    netip.Prefix `json:"prefix"`
	MaxLength *uint8       `json:"maxPrefixLength,omitempty"`
	Comment   string       `json:"comment,omitempty"`
}

// emptySLURM is a version 1 file with every array present and empty, which
// RFC 8416 requires rather than omitted members.
func emptySLURM() SLURM {
	return SLURM{Version: 1,
		Filters:    Filters{Prefix: []PrefixFilter{}, BGPsec: []map[string]any{}},
		Assertions: Assertions{Prefix: []PrefixAssertion{}, BGPsec: []map[string]any{}}}
}

// ParseSLURM decodes b and records what Validate needs to refuse: unknown
// members and missing required ones. It does not validate.
func ParseSLURM(b []byte) (SLURM, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return SLURM{}, err
	}
	var doc SLURM
	for k := range top {
		switch k {
		case "slurmVersion", "validationOutputFilters", "locallyAddedAssertions":
		default:
			doc.unknownKeys = append(doc.unknownKeys, k)
		}
	}
	need := func(obj map[string]json.RawMessage, where string, keys ...string) {
		for _, k := range keys {
			if v, ok := obj[k]; !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				doc.missing = append(doc.missing, where+"."+k)
			}
		}
	}
	for _, k := range []string{"slurmVersion", "validationOutputFilters", "locallyAddedAssertions"} {
		if _, ok := top[k]; !ok {
			doc.missing = append(doc.missing, k)
		}
	}
	var f, a map[string]json.RawMessage
	if v, ok := top["validationOutputFilters"]; ok {
		if err := json.Unmarshal(v, &f); err != nil {
			return SLURM{}, fmt.Errorf("validationOutputFilters: %w", err)
		}
		need(f, "validationOutputFilters", "prefixFilters", "bgpsecFilters")
	}
	if v, ok := top["locallyAddedAssertions"]; ok {
		if err := json.Unmarshal(v, &a); err != nil {
			return SLURM{}, fmt.Errorf("locallyAddedAssertions: %w", err)
		}
		need(a, "locallyAddedAssertions", "prefixAssertions", "bgpsecAssertions")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&doc); err != nil {
		return SLURM{}, err
	}
	if _, err := entryMembers(f["prefixFilters"], "asn", "prefix", "comment"); err != nil {
		return SLURM{}, fmt.Errorf("prefixFilters: %w", err)
	}
	asserts, err := entryMembers(a["prefixAssertions"], "asn", "prefix", "maxPrefixLength", "comment")
	if err != nil {
		return SLURM{}, fmt.Errorf("prefixAssertions: %w", err)
	}
	for i, e := range asserts {
		need(e, fmt.Sprintf("prefixAssertions[%d]", i), "asn", "prefix")
	}
	doc.normalize()
	return doc, nil
}

// entryMembers decodes the entries of a prefix filter or assertion list
// and refuses a member RFC 8416 does not define.
func entryMembers(raw json.RawMessage, allowed ...string) ([]map[string]json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	for i, e := range list {
		for k := range e {
			if !slices.Contains(allowed, k) {
				return nil, fmt.Errorf("[%d]: unknown member %q", i, k)
			}
		}
	}
	return list, nil
}

func (s *SLURM) normalize() {
	if s.Filters.Prefix == nil {
		s.Filters.Prefix = []PrefixFilter{}
	}
	if s.Filters.BGPsec == nil {
		s.Filters.BGPsec = []map[string]any{}
	}
	if s.Assertions.Prefix == nil {
		s.Assertions.Prefix = []PrefixAssertion{}
	}
	if s.Assertions.BGPsec == nil {
		s.Assertions.BGPsec = []map[string]any{}
	}
}

// Validate checks the RFC 8416 rules for the members Packeteer reads:
// version 1, the four arrays present, a filter with a prefix or an AS, an
// assertion with an AS and a prefix, prefixes without host bits, and a
// maxPrefixLength between the prefix length and the address length.
func (s SLURM) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if s.Version != 1 {
		add("slurmVersion must be 1, not %d", s.Version)
	}
	for _, k := range s.unknownKeys {
		add("unknown member %q", k)
	}
	for _, k := range s.missing {
		add("%s is required", k)
	}
	for i, f := range s.Filters.Prefix {
		if f.Prefix == nil && f.ASN == nil {
			add("prefixFilters[%d]: a prefix or an asn is required", i)
		}
		if f.Prefix != nil && !canonical(*f.Prefix) {
			add("prefixFilters[%d]: prefix %s has host bits set or is not valid", i, f.Prefix)
		}
	}
	for i, a := range s.Assertions.Prefix {
		if !canonical(a.Prefix) {
			add("prefixAssertions[%d]: prefix %s has host bits set or is not valid", i, a.Prefix)
			continue
		}
		if a.MaxLength != nil && (int(*a.MaxLength) < a.Prefix.Bits() || int(*a.MaxLength) > a.Prefix.Addr().BitLen()) {
			add("prefixAssertions[%d]: maxPrefixLength %d must be between %d and %d", i, *a.MaxLength, a.Prefix.Bits(), a.Prefix.Addr().BitLen())
		}
	}
	return errors.Join(errs...)
}

func canonical(p netip.Prefix) bool { return p.IsValid() && p == p.Masked() }

// Marshal is the file text: indented, with a trailing newline.
func (s SLURM) Marshal() []byte {
	s.normalize()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		panic(err) // every field marshals
	}
	return append(b, '\n')
}

// matches reports whether filter f removes v (RFC 8416 section 3.3.1).
func (f PrefixFilter) matches(v plugin.RPKIVRP) bool {
	if f.Prefix != nil && !netpfx.CoveredBy([]netip.Prefix{*f.Prefix}, v.Prefix) {
		return false
	}
	return f.ASN == nil || *f.ASN == v.ASN
}

// VRP is the payload the assertion adds.
func (a PrefixAssertion) VRP() plugin.RPKIVRP {
	maxLen := uint8(a.Prefix.Bits())
	if a.MaxLength != nil {
		maxLen = *a.MaxLength
	}
	return plugin.RPKIVRP{Prefix: a.Prefix, MaxLen: maxLen, ASN: a.ASN}
}

// Apply is what a relying party serves with s installed: vrps without the
// filtered payloads, plus the asserted ones (RFC 8416 section 4).
func (s SLURM) Apply(vrps []plugin.RPKIVRP) []plugin.RPKIVRP {
	var out []plugin.RPKIVRP
	for _, v := range vrps {
		keep := true
		for _, f := range s.Filters.Prefix {
			if f.matches(v) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, v)
		}
	}
	for _, a := range s.Assertions.Prefix {
		out = append(out, a.VRP())
	}
	return out
}

// validity is RFC 6811 for prefix and origin against vrps.
func validity(vrps []plugin.RPKIVRP, prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	t := rpki.NewVRPs()
	changes := make([]rpki.Change, 0, len(vrps))
	for _, v := range vrps {
		changes = append(changes, rpki.Change{Prefix: v.Prefix, MaxLen: v.MaxLen, ASN: v.ASN})
	}
	t.Apply(changes)
	return t.Validate(prefix, origin)
}
