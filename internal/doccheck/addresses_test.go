package doccheck

import (
	"bytes"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// AGENTS.md says lab fixtures, examples and docs use documentation prefixes
// and documentation or private ASNs only. This test enforces it for the
// trees below. Known mismatch, to decide later: BOT.md asks for
// documentation ASNs only, while AGENTS.md also allows private ASNs
// (64512-65534). Private ASNs are logged here, not failed.
var scannedRoots = []string{
	"lab", "examples", "config.example.yaml", "deploy", "docs", "scripts", ".github/workflows",
}

// allowed lists legitimate exceptions. A finding is exempt when its file
// path ends with path and its matched text equals value. Every entry needs a
// reason; keep the list short.
var allowed = []struct{ path, value, reason string }{
	{"lab/chaos/check_test.go", "198.51.0.0", "supernet of a documentation range, a deliberate outside-the-allowlist test input"},
	{"lab/chaos/check_test.go", "2001::", "supernet of a documentation range, a deliberate outside-the-allowlist test input"},
	{".github/workflows/ci.yml", "198.51.0.0", "supernet of a documentation range, a looking-glass search for the covering prefix"},
	{"lab/soak/multi_test.go", "192.0.3.0", "a prefix just outside the documentation range that the table must not index"},
	{"lab/soak/shape/build/main_test.go", "203.0.112.0", "a /23 whose upper half is the documentation range, a covering-prefix test input"},
	{"scripts/demo_test.go", "14.6.1.2", "a macOS version string in a fake-platform fixture"},
	{"docs/onboarding.md", "666", "the wizard's community rule, written asn:666; 666 is the community value, not an ASN"},
	{"docs/reviews/v0.9-fable-review.md", "1", "quotes an audit finding about a test that uses a one-digit ASN"},
}

// wellKnown literals are community tag names, not ASN keys: IXP Manager
// tags a route-server-filtered route rs-asn:1101:x. They are blanked before
// the ASN keys are read.
var wellKnown = strings.NewReplacer("rs-asn:1101", "rs-tag", "asn:1101", "rs-tag")

func mustPrefixes(cidrs ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// Documentation ranges (RFC 5737, RFC 3849) plus special-purpose ranges
// that are never globally routable. 255.255.255.255 is inside 240.0.0.0/4,
// and ::/8 is the IETF-reserved block holding ::, ::1 and ::3.
var okPrefixes = mustPrefixes(
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32",
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
	"::/8", "fc00::/7", "fe80::/10", "ff00::/8",
)

func okAddr(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range okPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// A dotted quad is an address only when no letter, digit, underscore or dot
// glues it to a neighbour. That skips version strings such as v1.2.3.4 and a
// fifth dotted group. A dash or colon does not glue, so 10.0.0.1-10.0.0.9 and
// ip:8.8.8.8 are read. A netmask is a run of one bits then zero bits
// (255.255.255.0), never an address, so it is skipped too.
var (
	ipv4Re = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?`)
	// A section number such as "RFC 4271 section 9.1.2.2" is not an address.
	sectionRe = regexp.MustCompile(`(?i)(?:section|sec\.?|rfc\s*\d+)\s+$`)
	// An IPv4-mapped IPv6 literal is reported once, by the IPv6 pass.
	mappedRe = regexp.MustCompile(`(?i)::ffff:$`)
	ptrRe    = regexp.MustCompile(`^(?:/\d{1,2})?\.in-addr\.arpa\.?`)
	ipv6Re   = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
)

func isNetmask(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return v|(v-1) == 0xffffffff || v == 0
}

// glue reports a byte that makes a neighbouring dotted quad part of a
// longer token (a version string, a name) rather than an address.
func glue(c byte) bool {
	return c == '.' || c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func wordByte(c byte) bool {
	return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func ipFindings(line string) []string {
	var bad []string
	for _, m := range ipv4Re.FindAllStringIndex(line, -1) {
		start, end := m[0], m[1]
		text, _, _ := strings.Cut(line[start:end], "/")
		end = start + len(text)
		// The match consumes nothing the next one needs: the neighbours
		// are checked here, so "10.0.0.1-8.8.8.8" yields both.
		if start > 0 && glue(line[start-1]) || end < len(line) && (line[end] != '.' && glue(line[end]) || line[end] == '.' && end+1 < len(line) && line[end+1] >= '0' && line[end+1] <= '9') {
			continue
		}
		a, err := netip.ParseAddr(text)
		if err != nil || isNetmask(a) || sectionRe.MatchString(line[:start]) || mappedRe.MatchString(line[:start]) {
			continue
		}
		if ptrRe.MatchString(line[end:]) {
			// 11.2.0.192.in-addr.arpa names 192.0.2.11.
			b := a.As4()
			a = netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
		}
		if !okAddr(a) {
			bad = append(bad, text)
		}
	}
	for _, m := range ipv6Re.FindAllStringIndex(line, -1) {
		tok := strings.Trim(line[m[0]:m[1]], ".")
		// A token glued to a word is a name such as PACKETEER-MIB::oid or
		// printf's %d::warning, not an address.
		if m[0] > 0 && wordByte(line[m[0]-1]) || m[1] < len(line) && wordByte(line[m[1]]) {
			continue
		}
		if !strings.Contains(tok, "::") && strings.Count(tok, ":") < 7 {
			continue
		}
		a, err := netip.ParseAddr(tok)
		if err != nil || okAddr(a) {
			continue
		}
		bad = append(bad, tok)
	}
	return bad
}

// Key names that carry an ASN. A bare "as" key only counts before a colon or
// equals sign, so prose such as "as 5 minutes" is not read as an ASN.
var asnRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9])(?:[a-z0-9]+[_-])*(?:asn|as)["']?\s*[:=]\s*["']?(\d{1,10})\b`),
	regexp.MustCompile(`(?i)\b(?:remote|local|peer)[_-]as(?:n)?\s+(\d{1,10})\b`),
	regexp.MustCompile(`(?i)\brouter bgp\s+(\d{1,10})\b`),
	regexp.MustCompile(`(?i)\b(?:local|neighbor\s+\S+)\s+as\s+(\d{1,10})\s*;`),
}

type asnClass int

const (
	asnDoc asnClass = iota
	asnPrivate
	asnOther
)

func classifyASN(n uint64) asnClass {
	switch {
	case n >= 64496 && n <= 64511, n >= 65536 && n <= 65551:
		return asnDoc
	case n >= 64512 && n <= 65534, n >= 4200000000 && n <= 4294967294:
		return asnPrivate
	}
	return asnOther
}

func asnFindings(line string) (priv, bad []string) {
	seen := map[string]bool{}
	for _, re := range asnRes {
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			if seen[m[1]] {
				continue
			}
			seen[m[1]] = true
			n, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				bad = append(bad, m[1])
				continue
			}
			switch classifyASN(n) {
			case asnPrivate:
				priv = append(priv, m[1])
			case asnOther:
				bad = append(bad, m[1])
			}
		}
	}
	return
}

// used records which allowlist entries matched, so a stale entry fails.
var used = map[int]bool{}

func exempt(rel, value string) bool {
	for i, a := range allowed {
		if a.value == value && strings.HasSuffix(rel, a.path) {
			used[i] = true
			return true
		}
	}
	return false
}

func isText(b []byte) bool {
	n := min(len(b), 8192)
	return !bytes.Contains(b[:n], []byte{0})
}

func scanFile(rel string, b []byte) (priv, bad []string) {
	for i, line := range strings.Split(string(b), "\n") {
		at := func(v string) string { return rel + ":" + strconv.Itoa(i+1) + ": " + v }
		for _, v := range ipFindings(line) {
			if !exempt(rel, v) {
				bad = append(bad, at("address "+v))
			}
		}
		p, o := asnFindings(wellKnown.Replace(line))
		for _, v := range p {
			priv = append(priv, at("private ASN "+v))
		}
		for _, v := range o {
			if !exempt(rel, v) {
				bad = append(bad, at("ASN "+v))
			}
		}
	}
	return
}

func TestLabAndDocsUseDocumentationAddressesOnly(t *testing.T) {
	root := filepath.Join("..", "..")
	var privates, bads []string
	for _, r := range scannedRoots {
		err := filepath.WalkDir(filepath.Join(root, r), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() == "go.sum" {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if !isText(b) {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			pr, bd := scanFile(filepath.ToSlash(rel), b)
			privates = append(privates, pr...)
			bads = append(bads, bd...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, a := range allowed {
		if !used[i] {
			t.Errorf("allowlist entry %s %q (%s) matches nothing; remove it", a.path, a.value, a.reason)
		}
	}
	// One line per file and ASN, not per occurrence.
	counts := map[string]int{}
	var order []string
	for _, p := range privates {
		key := p[:strings.Index(p, ":")] + p[strings.LastIndex(p, ": ")+1:]
		if counts[key] == 0 {
			order = append(order, key)
		}
		counts[key]++
	}
	for _, k := range order {
		t.Logf("%s (%d times)", k, counts[k])
	}
	for _, b := range bads {
		t.Error(b)
	}
}

func TestAddressScannerRules(t *testing.T) {
	bad := func(line string, want ...string) {
		t.Helper()
		_, o := scanFile("x/y.conf", []byte(line))
		if len(o) != len(want) {
			t.Fatalf("%q: findings %v, want %v", line, o, want)
		}
		for i, w := range want {
			if !strings.HasSuffix(o[i], w) {
				t.Fatalf("%q: finding %q, want suffix %q", line, o[i], w)
			}
		}
	}
	bad("prefix 192.0.2.0/24 via 10.1.2.3")
	bad("  - 8.8.8.0/24", "address 8.8.8.0")
	bad("nameserver 8.8.8.8", "address 8.8.8.8")
	bad("peer 2606:4700:4700::1111", "address 2606:4700:4700::1111")
	bad("peer 2001:db8::1 fe80::1 ::1 fd00::5")
	bad("mask 255.255.255.0 and 255.255.0.0 and 0.0.0.0")
	bad("version v8.8.8.8 and 8.8.8.8.9 and frr8.8.8.8")
	bad("image frr:8.8.8.8-x", "address 8.8.8.8")
	bad("10.0.0.1-8.8.8.8", "address 8.8.8.8")
	bad("8.8.8.8 9.9.9.9", "address 8.8.8.8", "address 9.9.9.9")
	bad("[8.8.8.8,9.9.9.9/24]", "address 8.8.8.8", "address 9.9.9.9")
	bad("ends 8.8.8.8.", "address 8.8.8.8")
	bad("RFC 4271 section 9.1.2.2 and 1.3.6.1.4.1.8072")
	bad("PACKETEER-MIB::pktrProviderDown 12:30:45")
	bad("2.0.192.in-addr.arpa 11.2.0.192.in-addr.arpa")
	bad("4.4.8.8.in-addr.arpa", "address 4.4.8.8")
	bad("::ffff:8.8.8.8", "address ::ffff:8.8.8.8")
}

func TestASNScannerRules(t *testing.T) {
	cases := []struct {
		line       string
		priv, fail []string
	}{
		{"asn: 64496", nil, nil},
		{"asn: 65551", nil, nil},
		{"local_as: 65001", []string{"65001"}, nil},
		{`"asn": 4200000001`, []string{"4200000001"}, nil},
		{"neighbor 192.0.2.1 remote-as 15169", nil, []string{"15169"}},
		{"asn: 15169", nil, []string{"15169"}},
		{"peer-as = 64495", nil, []string{"64495"}},
		{"router bgp 65535", nil, []string{"65535"}},
		{"local as 3356;", nil, []string{"3356"}},
		{"neighbor 192.0.2.2 as 64511;", nil, nil},
		{"remote-as 65552", nil, []string{"65552"}},
		{`"asns": 3 and as 5 minutes`, nil, nil},
		{"community asn:1101:x", nil, nil},
	}
	for _, c := range cases {
		priv, fail := asnFindings(wellKnown.Replace(c.line))
		if strings.Join(priv, ",") != strings.Join(c.priv, ",") || strings.Join(fail, ",") != strings.Join(c.fail, ",") {
			t.Errorf("%q: private %v fail %v, want %v %v", c.line, priv, fail, c.priv, c.fail)
		}
	}
}
