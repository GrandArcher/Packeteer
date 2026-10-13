package linkout

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func urls(ls []Link) map[string]string {
	m := map[string]string{}
	for _, l := range ls {
		m[l.Name] = l.URL
	}
	return m
}

func TestDefaultsPrefix(t *testing.T) {
	got := urls(New(Config{}).Prefix(netip.MustParsePrefix("198.51.100.0/24")))
	want := map[string]string{
		"HE BGP Toolkit":   "https://bgp.he.net/net/198.51.100.0/24",
		"HE looking glass": "https://lg.he.net/",
		"RIPEstat":         "https://stat.ripe.net/app/launchpad/198.51.100.0/24",
		"bgp.tools":        "https://bgp.tools/prefix/198.51.100.0/24",
		"IRR Explorer":     "https://irrexplorer.nlnog.net/prefix/198.51.100.0/24",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefix links = %v, want %v", got, want)
	}
}

func TestDefaultsASN(t *testing.T) {
	got := urls(New(Config{}).ASN(64496))
	want := map[string]string{
		"HE BGP Toolkit":   "https://bgp.he.net/AS64496",
		"RIPEstat":         "https://stat.ripe.net/app/launchpad/AS64496",
		"PeeringDB":        "https://www.peeringdb.com/asn/64496",
		"bgp.tools":        "https://bgp.tools/as/64496",
		"Cloudflare Radar": "https://radar.cloudflare.com/routing/as64496",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("asn links = %v, want %v", got, want)
	}
}

func TestIPv6PrefixEncoding(t *testing.T) {
	// A non-canonical input is masked first; ":" and "/" stay readable.
	got := urls(New(Config{Enabled: []string{"he", "nlnog_ring"}}).Prefix(netip.MustParsePrefix("2001:db8:0:1::5/48")))
	want := map[string]string{
		"HE BGP Toolkit":           "https://bgp.he.net/net/2001:db8::/48",
		"NLNOG RING looking glass": "https://lg.ring.nlnog.net/prefix?q=2001:db8::/48",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("links = %v, want %v", got, want)
	}
}

func TestNLNOGRingOffByDefault(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.0/24")
	for name := range urls(New(Config{}).Prefix(p)) {
		if strings.Contains(name, "NLNOG") {
			t.Fatalf("%s shown by default", name)
		}
	}
	if _, ok := urls(New(Config{Enabled: []string{"nlnog_ring"}}).Prefix(p))["NLNOG RING looking glass"]; !ok {
		t.Fatal("enabled nlnog_ring has no link")
	}
}

func TestEnabledListSelectsSites(t *testing.T) {
	s := New(Config{Enabled: []string{"bgptools"}})
	if got := urls(s.ASN(64496)); !reflect.DeepEqual(got, map[string]string{"bgp.tools": "https://bgp.tools/as/64496"}) {
		t.Fatalf("asn = %v", got)
	}
	none := New(Config{Enabled: []string{}})
	if n := len(none.ASN(64496)) + len(none.Prefix(netip.MustParsePrefix("192.0.2.0/24"))); n != 0 {
		t.Fatalf("empty enabled still shows %d links", n)
	}
}

func TestHideInternal(t *testing.T) {
	internalPrefixes := []string{"10.1.0.0/16", "172.16.0.0/12", "192.168.1.0/24", "fd00:1::/48", "127.0.0.0/8", "169.254.0.0/16", "fe80::/10"}
	on := New(Config{})
	for _, s := range internalPrefixes {
		if got := on.Prefix(netip.MustParsePrefix(s)); len(got) != 0 {
			t.Errorf("%s: hide_internal on still links %v", s, got)
		}
	}
	for _, n := range []uint32{64512, 65000, 65534, 4200000000, 4294967294} {
		if got := on.ASN(n); len(got) != 0 {
			t.Errorf("AS%d: hide_internal on still links %v", n, got)
		}
	}
	// Documentation ranges are not internal; they are what the lab uses.
	for _, s := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		if len(on.Prefix(netip.MustParsePrefix(s))) == 0 {
			t.Errorf("%s hidden", s)
		}
	}
	for _, n := range []uint32{64496, 64511, 65536, 3356} {
		if len(on.ASN(n)) == 0 {
			t.Errorf("AS%d hidden", n)
		}
	}
	off := false
	shown := New(Config{HideInternal: &off})
	if len(shown.Prefix(netip.MustParsePrefix("10.1.0.0/16"))) == 0 || len(shown.ASN(65000)) == 0 {
		t.Error("hide_internal false still hides")
	}
	if len(shown.ASN(0)) != 0 {
		t.Error("AS0 linked")
	}
}

func TestCustomTemplates(t *testing.T) {
	s := New(Config{Enabled: []string{}, Custom: []Custom{
		{Name: "internal LG", URL: "https://lg.example.net/route?prefix={prefix}&view=all"},
		{Name: "internal AS", URL: "https://whois.example.net/as/{asn}"},
	}})
	if got := urls(s.Prefix(netip.MustParsePrefix("2001:db8::/32"))); !reflect.DeepEqual(got, map[string]string{"internal LG": "https://lg.example.net/route?prefix=2001:db8::/32&view=all"}) {
		t.Fatalf("prefix = %v", got)
	}
	if got := urls(s.ASN(64496)); !reflect.DeepEqual(got, map[string]string{"internal AS": "https://whois.example.net/as/64496"}) {
		t.Fatalf("asn = %v", got)
	}
}

func TestValidateTemplate(t *testing.T) {
	good := map[string]Kind{
		"https://lg.example.net/{prefix}":          KindPrefix,
		"https://lg.example.net/?q={prefix}":       KindPrefix,
		"https://lg.example.net:8443/as/{asn}":     KindASN,
		"https://lg.example.net/{prefix}/{prefix}": KindPrefix,
	}
	for tmpl, want := range good {
		if got, err := ValidateTemplate(tmpl); err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", tmpl, got, err, want)
		}
	}
	bad := map[string]string{
		"http://lg.example.net/{prefix}":        "https",
		"ftp://lg.example.net/{prefix}":         "https",
		"//lg.example.net/{prefix}":             "https",
		"javascript:alert({prefix})":            "https",
		"https:///{prefix}":                     "host",
		"https://lg.example.net/":               "must contain",
		"https://lg.example.net/{name}":         "unknown placeholder {name}",
		"https://lg.example.net/{Prefix}":       "unknown placeholder",
		"https://lg.example.net/{prefix":        "unmatched {",
		"https://lg.example.net/prefix}":        "unmatched }",
		"https://lg.example.net/{prefix}/{asn}": "not both",
		"https://{asn}.example.net/":            "host cannot hold",
		"https://lg.example.net{prefix}":        "host cannot hold",
		"https://user:pw@lg.example.net/{asn}":  "credentials",
		"https://lg.example.net/{asn}#frag":     "fragment",
		"https://lg.example.net/%zz{asn}":       "url",
	}
	for tmpl, want := range bad {
		if _, err := ValidateTemplate(tmpl); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", tmpl, err, want)
		}
	}
}

func TestValidateConfig(t *testing.T) {
	collect := func(c Config) string {
		var msgs []string
		c.Validate(func(f string, a ...any) { msgs = append(msgs, strings.TrimSpace(fmt.Sprintf(f, a...))) })
		return strings.Join(msgs, "; ")
	}
	if got := collect(Config{Enabled: []string{"he", "ripestat"}, Custom: []Custom{{Name: "x", URL: "https://a.example.net/{asn}"}}}); got != "" {
		t.Errorf("valid block: %s", got)
	}
	cases := []struct {
		c    Config
		want string
	}{
		{Config{Enabled: []string{"bgpview"}}, `"bgpview" is not a link-out site`},
		{Config{Enabled: []string{"he", "he"}}, "listed twice"},
		{Config{Custom: []Custom{{Name: "", URL: "https://a.example.net/{asn}"}}}, "name must be"},
		{Config{Custom: []Custom{{Name: "bad\nname", URL: "https://a.example.net/{asn}"}}}, "name must be"},
		{Config{Custom: []Custom{{Name: strings.Repeat("n", MaxNameLength+1), URL: "https://a.example.net/{asn}"}}}, "name must be"},
		{Config{Custom: []Custom{{Name: "a", URL: "https://a.example.net/{asn}"}, {Name: "a", URL: "https://b.example.net/{asn}"}}}, "used twice"},
		{Config{Custom: []Custom{{Name: "a", URL: "http://a.example.net/{asn}"}}}, "linkouts.custom[0]: url"},
		{Config{Custom: make([]Custom, MaxCustom+1)}, "at most"},
	}
	for _, tc := range cases {
		if got := collect(tc.c); !strings.Contains(got, tc.want) {
			t.Errorf("%+v: %q does not contain %q", tc.c, got, tc.want)
		}
	}
}
