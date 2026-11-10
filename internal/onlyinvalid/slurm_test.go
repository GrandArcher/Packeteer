package onlyinvalid

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const emptyFile = `{"slurmVersion":1,"validationOutputFilters":{"prefixFilters":[],"bgpsecFilters":[]},"locallyAddedAssertions":{"prefixAssertions":[],"bgpsecAssertions":[]}}`

// #401: the RFC 8416 rules a SLURM file must meet before Packeteer reads
// or writes it.
func TestSLURMValidate(t *testing.T) {
	withAssert := func(a string) string {
		return strings.Replace(emptyFile, `"prefixAssertions":[]`, `"prefixAssertions":[`+a+`]`, 1)
	}
	withFilter := func(f string) string {
		return strings.Replace(emptyFile, `"prefixFilters":[]`, `"prefixFilters":[`+f+`]`, 1)
	}
	good := []string{
		emptyFile,
		withAssert(`{"asn":64500,"prefix":"198.51.100.0/24","maxPrefixLength":24,"comment":"x"}`),
		withAssert(`{"asn":64500,"prefix":"2001:db8::/32"}`),
		withFilter(`{"prefix":"198.51.100.0/22"}`),
		withFilter(`{"asn":0}`),
	}
	for _, s := range good {
		doc, err := ParseSLURM([]byte(s))
		if err == nil {
			err = doc.Validate()
		}
		if err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := map[string]string{
		strings.Replace(emptyFile, `"slurmVersion":1`, `"slurmVersion":2`, 1):                       "slurmVersion must be 1",
		`{"slurmVersion":1,"locallyAddedAssertions":{"prefixAssertions":[],"bgpsecAssertions":[]}}`: "validationOutputFilters is required",
		strings.Replace(emptyFile, `"bgpsecFilters":[]`, `"bgpsecFilters":null`, 1):                 "validationOutputFilters.bgpsecFilters is required",
		strings.Replace(emptyFile, `{"slurmVersion":1`, `{"slurmVersion":1,"extra":true`, 1):        `unknown member "extra"`,
		withFilter(`{"comment":"nothing"}`):                                                         "a prefix or an asn is required",
		withFilter(`{"prefix":"198.51.100.1/24"}`):                                                  "has host bits set",
		withAssert(`{"asn":64500,"prefix":"198.51.100.0/24","maxPrefixLength":23}`):                 "maxPrefixLength 23 must be between 24 and 32",
		withAssert(`{"asn":64500,"prefix":"198.51.100.0/24","maxPrefixLength":33}`):                 "maxPrefixLength 33 must be between 24 and 32",
		withAssert(`{"asn":64500,"prefix":"198.51.100.0/24","maxLength":24}`):                       `unknown member "maxLength"`,
		withAssert(`{"asn":4294967296,"prefix":"198.51.100.0/24"}`):                                 "cannot unmarshal",
		withAssert(`{"prefix":"198.51.100.0/24"}`):                                                  "prefixAssertions[0].asn is required",
		withAssert(`{"asn":64500}`):                                                                 "prefixAssertions[0].prefix is required",
	}
	for s, want := range bad {
		doc, err := ParseSLURM([]byte(s))
		if err == nil {
			err = doc.Validate()
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want %q", s, err, want)
		}
	}
}

// Apply follows RFC 8416 section 4: a filter drops payloads equal to or
// more specific than its prefix with its AS; assertions are added.
func TestSLURMApply(t *testing.T) {
	p32, p48 := netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:db8::/48")
	asn := uint32(64499)
	doc := emptySLURM()
	doc.Filters.Prefix = []PrefixFilter{{Prefix: &p48, ASN: &asn}}
	doc.Assertions.Prefix = []PrefixAssertion{{ASN: 64500, Prefix: p48}}
	in := []plugin.RPKIVRP{
		{Prefix: p48, MaxLen: 48, ASN: 64499},
		{Prefix: p32, MaxLen: 48, ASN: 64499},
		{Prefix: p48, MaxLen: 48, ASN: 64501},
	}
	out := doc.Apply(in)
	if len(out) != 3 || out[0] != in[1] || out[1] != in[2] || out[2] != (plugin.RPKIVRP{Prefix: p48, MaxLen: 48, ASN: 64500}) {
		t.Fatalf("apply = %+v", out)
	}
	if validity(out, p48, 64500) != plugin.RPKIValid || validity(in, p48, 64500) != plugin.RPKIInvalid {
		t.Fatal("validity before and after")
	}
}
