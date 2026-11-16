package fieldreport

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// realLooking is text an operator's error or checklist line could carry:
// public-looking addresses and prefixes, AS numbers, and host names. None of
// it may survive.
const realLooking = `session to 10.20.30.40 down; neighbor 172.16.5.6:179 refused
prefix 100.64.0.0/10 and 198.18.33.0/24 learned from AS64600 via as 64601 (asn=4200000002)
v6 peer fd00:1234:5678::1111 and prefix fd12:3456::/32, mapped ::ffff:100.64.7.8
dial tcp edge1.transit.example.net: lookup failed; rr-1.corp.isp.test answered
mail ops@noc.bigisp.test. Ends with fd00:abcd::8888.
time 12:30:45 and config.yaml stay as they are; docs/CONFIG.md is redacted like a host`

var (
	anyV4   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	anyV6   = regexp.MustCompile(`[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*`)
	anyASN  = regexp.MustCompile(`(?i)\bASN?\s*[:=#]?\s*(\d+)\b`)
	anyHost = regexp.MustCompile(`(?i)\b(?:[a-z0-9_-]+\.)+[a-z]{2,24}\b`)
	docV4   = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")}
	docV6   = netip.MustParsePrefix("2001:db8::/32")
)

// onlyDocumentation fails the test for any address, AS number, or host name
// in s that is not from a documentation range.
func onlyDocumentation(t *testing.T, s string) {
	t.Helper()
	for _, m := range anyV4.FindAllString(s, -1) {
		a, err := netip.ParseAddr(m)
		if err != nil || !(docV4[0].Contains(a) || docV4[1].Contains(a) || docV4[2].Contains(a)) {
			t.Errorf("IPv4 %q is not a documentation address", m)
		}
	}
	for _, m := range anyV6.FindAllString(s, -1) {
		if a, err := netip.ParseAddr(strings.TrimRight(m, ".:")); err == nil && a.Is6() && !docV6.Contains(a) {
			t.Errorf("IPv6 %q is not a documentation address", m)
		}
	}
	for _, m := range anyASN.FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(m[1])
		if !(n >= 64496 && n <= 64511 || n >= 65536 && n <= 65551) {
			t.Errorf("AS number %q is not a documentation ASN", m[0])
		}
	}
	for _, m := range anyHost.FindAllString(s, -1) {
		last := m[strings.LastIndexByte(m, '.')+1:]
		if !strings.HasSuffix(m, ".example") && !fileSuffixes[strings.ToLower(last)] && !anyV4.MatchString(m) {
			t.Errorf("host name %q was not replaced", m)
		}
	}
}

func TestRedactLeavesOnlyDocumentationValues(t *testing.T) {
	got := NewRedactor().Redact(realLooking)
	onlyDocumentation(t, got)
	for _, real := range []string{"10.20.30.40", "172.16.5.6", "100.64.0.0", "198.18.33", "100.64.7.8", "fd00:1234", "fd12:3456", "fd00:abcd", "64600", "64601", "4200000002", "transit", "corp.isp", "bigisp", "noc.", "CONFIG.md"} {
		if strings.Contains(got, real) {
			t.Errorf("%q survived:\n%s", real, got)
		}
	}
	for _, kept := range []string{"12:30:45", "config.yaml", "/10", "/24", "/32", "ops@", "Ends with"} {
		if !strings.Contains(got, kept) {
			t.Errorf("%q was changed:\n%s", kept, got)
		}
	}
}

func TestRedactIsStableAndDeterministic(t *testing.T) {
	text := "a 10.20.30.40 b 10.20.30.40/24 c 172.16.5.6 d AS64600 e as64600 f AS64601 g h1.net.example.org h2.net.example.org h1.net.example.org i fd00:1234::1 j fd00:1234:0:0:0:0:0:1"
	r := NewRedactor()
	first := r.Redact(text)
	if again := r.Redact(text); again != first {
		t.Errorf("the same Redactor changed its answer:\n%s\n%s", first, again)
	}
	if other := NewRedactor().Redact(text); other != first {
		t.Errorf("two Redactors differ:\n%s\n%s", first, other)
	}
	want := "a 192.0.2.1 b 192.0.2.1/24 c 192.0.2.2 d AS64496 e as64496 f AS64497 g router-1.example router-2.example router-1.example i 2001:db8::1 j 2001:db8::1"
	if first != want {
		t.Errorf("got  %s\nwant %s", first, want)
	}
}

func TestRedactPlaceholderPoolsWrapInsideDocumentationRanges(t *testing.T) {
	r := NewRedactor()
	var b strings.Builder
	for i := 0; i < 800; i++ {
		b.WriteString("10." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250) + ".1 ")
	}
	for i := 0; i < 40; i++ {
		b.WriteString("AS" + strconv.Itoa(64512+i) + " ")
	}
	got := r.Redact(b.String())
	onlyDocumentation(t, got)
	if !strings.Contains(got, "198.51.100.1 ") || !strings.Contains(got, "203.0.113.254 ") {
		t.Errorf("the three documentation /24s are used in turn:\n%.200s", got)
	}
}

func TestRenderRedactsAFieldThatCarriesRealValues(t *testing.T) {
	loss, rtt := 1.25, 12.5
	in := Input{
		Version: "v1.4.0", Mode: "observe",
		Facts:     Facts{Providers: 2, BGPNeighbors: 1, AddPath: true, BMP: true, ProbeTypes: []string{"tcp", "icmp"}, SourceTypes: []string{"flow"}},
		Checklist: []Item{{ID: "bgp-down", Level: "warn"}, {ID: "rib 203.0.113.9 AS64600 gw.isp.test", Level: "todo"}},
		Events:    &Events{Total: 40, Warning: 3, Critical: 1, Kinds: map[string]int{"bgp.session_down": 1, "provider.down 10.20.30.41": 3}},
		ValueDays: 30,
		Value:     []Value{{Basis: "estimate", Improvements: 4, Measured: 3, SteeredHours: 12.34, LossAvoidedPct: &loss, RTTAvoidedMs: &rtt}, {Basis: "announced"}},
	}
	got := Render(in)
	onlyDocumentation(t, got)
	for _, want := range []string{
		"mode: observe", "providers: 2", "ibgp sessions: 1 (add-path: yes)", "bmp: yes", "probers: icmp, tcp", "target sources: flow",
		"- warn: bgp-down", "events (newest 1000 at most): 40 total, 3 warning, 1 critical", "- bgp.session_down: 1", "- other kinds: 3",
		"value report, last 30 days:", "estimate: 4 improvements, 3 measured, 12.3 steered hours, loss avoided 1.250%, rtt avoided 12.500 ms",
		"announced: 0 improvements, 0 measured, 0.0 steered hours, loss avoided not measured, rtt avoided not measured",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	for _, real := range []string{"10.20.30.41", "64600", "isp.test", "203.0.113.9"} {
		if strings.Contains(got, real) {
			t.Errorf("%q survived:\n%s", real, got)
		}
	}
	if Render(in) != got {
		t.Error("Render is not deterministic")
	}
}

func TestRenderWithoutEventsOrValue(t *testing.T) {
	got := Render(Input{Version: "dev", Mode: "observe"})
	for _, want := range []string{"events: not kept", "value report: not available", "probers: none", "setup checklist (0):"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}
