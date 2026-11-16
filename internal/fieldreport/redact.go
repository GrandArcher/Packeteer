package fieldreport

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Placeholder pools, all from the documentation ranges: IPv4 (RFC 5737),
// IPv6 (RFC 3849), and AS numbers (RFC 5398).
var (
	v4Nets  = [...]string{"192.0.2.", "198.51.100.", "203.0.113."}
	asnPool = func() []uint32 {
		var p []uint32
		for a := uint32(64496); a <= 64511; a++ {
			p = append(p, a)
		}
		for a := uint32(65536); a <= 65551; a++ {
			p = append(p, a)
		}
		return p
	}()
)

// usable hosts per documentation /24 (.1 to .254).
const v4PerNet = 254

var (
	// An IPv6 candidate is any run of hex digits, colons, and dots with a
	// colon in it; it counts only when netip parses it, so a clock time is
	// left alone.
	v6Re   = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:/\d{1,3})?`)
	v4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b`)
	asnRe  = regexp.MustCompile(`(?i)\b(ASN?)(\s*[:=#]?\s*)(\d{1,10})\b`)
	hostRe = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b`)
)

// fileSuffixes are last labels that name a file, not a host, so a name such
// as config.yaml survives. md is not here: it is also a country domain, so a
// doc path such as docs/CONFIG.md is redacted like a host.
var fileSuffixes = map[string]bool{
	"yaml": true, "yml": true, "json": true, "go": true, "js": true,
	"html": true, "txt": true, "conf": true, "log": true, "sock": true, "db": true,
	"mmdb": true, "csv": true, "xlsx": true, "pem": true, "crt": true, "key": true,
}

// Redactor replaces every IPv4 and IPv6 address and prefix, AS number, and
// host name in a text with a placeholder from the documentation ranges. The
// same input always gets the same placeholder from one Redactor, and the
// numbering follows the order of first appearance, so the output is
// deterministic. A report is far smaller than the pools; past a pool's size
// the placeholders repeat, which never reveals a real value.
type Redactor struct {
	v4, v6, asn, host map[string]string
	keep              map[string]bool
}

// NewRedactor returns an empty Redactor. Use one per report.
func NewRedactor() *Redactor {
	return &Redactor{v4: map[string]string{}, v6: map[string]string{}, asn: map[string]string{}, host: map[string]string{}, keep: map[string]bool{}}
}

// Keep exempts names that read like host names but are not, such as the
// dotted event kinds of the catalog. A caller must pass only fixed names it
// owns, never text from the network or the operator.
func (r *Redactor) Keep(names ...string) {
	for _, n := range names {
		r.keep[strings.ToLower(n)] = true
	}
}

// Redact returns s with every address, prefix, AS number, and host name
// replaced. A prefix gets a placeholder address and keeps its length, except
// that a length shorter than /24 (IPv4) or /32 (IPv6) is raised to that.
func (r *Redactor) Redact(s string) string {
	s = v6Re.ReplaceAllStringFunc(s, r.redactV6)
	s = v4Re.ReplaceAllStringFunc(s, r.redactV4)
	s = asnRe.ReplaceAllStringFunc(s, r.redactASN)
	return hostRe.ReplaceAllStringFunc(s, r.redactHost)
}

// splitLen separates a trailing /length.
func splitLen(s string) (addr, length string) {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// floorLen raises a prefix length shorter than the documentation block's own
// (/24 for IPv4, /32 for IPv6), so a placeholder never claims more than that
// block.
func floorLen(length string, min int) string {
	n, err := strconv.Atoi(strings.TrimPrefix(length, "/"))
	if length == "" || err != nil || n >= min {
		return length
	}
	return "/" + strconv.Itoa(min)
}

func (r *Redactor) redactV6(m string) string {
	addr, length := splitLen(m)
	suffix := ""
	a, err := netip.ParseAddr(addr)
	if err != nil {
		// A sentence can end the address with a dot or a colon.
		trimmed := strings.TrimRight(addr, ".:")
		if length != "" || trimmed == addr {
			return m
		}
		if a, err = netip.ParseAddr(trimmed); err != nil {
			return m
		}
		suffix = addr[len(trimmed):]
	}
	if !a.Is6() {
		return m
	}
	key := a.String()
	p, ok := r.v6[key]
	if !ok {
		p = fmt.Sprintf("2001:db8::%x", len(r.v6)%0xffff+1)
		r.v6[key] = p
	}
	return p + floorLen(length, 32) + suffix
}

func (r *Redactor) redactV4(m string) string {
	addr, length := splitLen(m)
	p, ok := r.v4[addr]
	if !ok {
		i := len(r.v4) % (v4PerNet * len(v4Nets))
		p = fmt.Sprintf("%s%d", v4Nets[i/v4PerNet], i%v4PerNet+1)
		r.v4[addr] = p
	}
	return p + floorLen(length, 24)
}

func (r *Redactor) redactASN(m string) string {
	sub := asnRe.FindStringSubmatch(m)
	p, ok := r.asn[sub[3]]
	if !ok {
		p = fmt.Sprint(asnPool[len(r.asn)%len(asnPool)])
		r.asn[sub[3]] = p
	}
	return sub[1] + sub[2] + p
}

func (r *Redactor) redactHost(m string) string {
	last := m[strings.LastIndexByte(m, '.')+1:]
	key := strings.ToLower(m)
	if fileSuffixes[strings.ToLower(last)] || r.keep[key] {
		return m
	}
	p, ok := r.host[key]
	if !ok {
		p = fmt.Sprintf("router-%d.example", len(r.host)+1)
		r.host[key] = p
	}
	return p
}
