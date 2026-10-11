package troubleshoot

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

// fakeRIB is a simulated learned RIB with documentation prefixes.
type fakeRIB struct{ routes, inactive []rib.Route }

func (f fakeRIB) Ready() bool { return true }
func (f fakeRIB) Exact(p netip.Prefix) (rib.Route, bool) {
	for _, r := range f.routes {
		if r.Prefix == p.Masked() {
			return r, true
		}
	}
	return rib.Route{}, false
}
func (f fakeRIB) Covering(p netip.Prefix) (rib.Route, bool) {
	best := -1
	for i, r := range f.routes {
		if r.Prefix.Bits() <= p.Bits() && r.Prefix.Contains(p.Addr()) && (best < 0 || r.Prefix.Bits() > f.routes[best].Prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return rib.Route{}, false
	}
	return f.routes[best], true
}
func (f fakeRIB) Routes() []rib.Route { return f.routes }
func (f fakeRIB) Paths(p netip.Prefix) []rib.Route {
	var out []rib.Route
	for _, r := range f.routes {
		if r.Prefix == p.Masked() {
			out = append(out, r)
		}
	}
	for _, r := range f.inactive {
		if r.Prefix == p.Masked() {
			out = append(out, r)
		}
	}
	return out
}

func testRIB() fakeRIB {
	return fakeRIB{routes: []rib.Route{
		{Prefix: pfx("198.51.100.0/24"), NextHop: addr("192.0.2.1"), Provider: "transit-a", ASPath: []uint32{64496, 64500}},
		{Prefix: pfx("198.51.100.128/25"), NextHop: addr("192.0.2.2"), Provider: "transit-b", ASPath: []uint32{64497, 64500}},
		{Prefix: pfx("203.0.113.0/24"), NextHop: addr("192.0.2.1"), Provider: "transit-a", ASPath: []uint32{64496}},
	}}
}

var provs = []probe.Provider{
	{Name: "transit-a", Source: addr("192.0.2.10")},
	{Name: "transit-b", Source: addr("192.0.2.11")},
}

// fakeProber answers per source address: loss for transit-b.
type fakeProber struct {
	plugin.Base
	mu   sync.Mutex
	reqs []plugin.ProbeRequest
	fail map[netip.Addr]error
}

func (f *fakeProber) Probe(_ context.Context, r plugin.ProbeRequest) (plugin.ProbeResult, error) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.mu.Unlock()
	if err := f.fail[r.Source]; err != nil {
		return plugin.ProbeResult{}, err
	}
	res := plugin.ProbeResult{Sent: r.Count}
	n := r.Count
	if r.Source == addr("192.0.2.11") {
		n = r.Count / 2
	}
	for i := 0; i < n; i++ {
		res.RTTs = append(res.RTTs, 10*time.Millisecond)
	}
	return res, nil
}

type allow struct{ n int }

func (a *allow) Allow() bool { a.n--; return a.n >= 0 }

func TestLookingGlass(t *testing.T) {
	tl := New(Options{})
	if _, err := tl.LookingGlass(pfx("198.51.100.0/24")); !errors.Is(err, ErrNoRIB) {
		t.Fatalf("no rib: %v", err)
	}
	tl.SetRIB(testRIB())
	g, err := tl.LookingGlass(pfx("198.51.100.7/24"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Query != pfx("198.51.100.0/24") || g.Exact == nil || g.Exact.Provider != "transit-a" || len(g.MoreSpecifics) != 1 || g.MoreSpecifics[0].Prefix != pfx("198.51.100.128/25") {
		t.Fatalf("glass: %+v", g)
	}
	// An inactive add-path path is listed with the best one.
	r := testRIB()
	r.inactive = []rib.Route{{Prefix: pfx("198.51.100.0/24"), NextHop: addr("192.0.2.2"), Provider: "transit-b", Source: rib.SourceIBGP, PathID: 2}}
	tl.SetRIB(r)
	g, _ = tl.LookingGlass(pfx("198.51.100.0/24"))
	if len(g.Paths) != 2 || g.Paths[1].Provider != "transit-b" || g.Paths[1].PathID != 2 || g.Exact.Provider != "transit-a" {
		t.Fatalf("paths: %+v", g.Paths)
	}
	g, _ = tl.LookingGlass(pfx("198.51.100.200/32"))
	if g.Exact != nil || g.Covering == nil || g.Covering.Prefix != pfx("198.51.100.128/25") {
		t.Fatalf("covering: %+v", g)
	}
	g, _ = tl.LookingGlass(pfx("192.0.2.0/24"))
	if g.Exact != nil || g.Covering != nil || len(g.MoreSpecifics) != 0 {
		t.Fatalf("unknown: %+v", g)
	}
}

func TestProbeAllProviders(t *testing.T) {
	fp := &fakeProber{}
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: fp}}, Packets: 4, Timeout: 10 * time.Millisecond})
	tl.SetRIB(testRIB())
	ans, err := tl.Probe(context.Background(), addr("203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	if ans.Route == nil || ans.Route.Prefix != pfx("203.0.113.0/24") || len(ans.Results) != 2 {
		t.Fatalf("answer: %+v", ans)
	}
	if ans.Results[0].Provider != "transit-a" || ans.Results[0].Stats.LossPct != 0 || ans.Results[1].Stats.LossPct != 50 {
		t.Fatalf("results: %+v", ans.Results)
	}
	for _, r := range fp.reqs {
		if r.Target != addr("203.0.113.9") || r.Count != 4 {
			t.Fatalf("request: %+v", r)
		}
	}
}

func TestProbeSourceDownAndErrors(t *testing.T) {
	fp := &fakeProber{fail: map[netip.Addr]error{addr("192.0.2.11"): fmt.Errorf("bind: %w", plugin.ErrSourceUnavailable)}}
	tl := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: fp}}})
	ans, err := tl.Probe(context.Background(), addr("198.51.100.1"))
	if err != nil {
		t.Fatal(err)
	}
	if ans.Results[1].OK() || !strings.Contains(ans.Results[1].Err, "source") || !ans.Results[0].OK() {
		t.Fatalf("results: %+v", ans.Results)
	}
	for _, a := range []string{"127.0.0.1", "0.0.0.0", "224.0.0.1", "fe80::1", "255.255.255.255", "::1"} {
		if _, err := tl.Probe(context.Background(), addr(a)); err == nil {
			t.Errorf("%s: expected refusal", a)
		}
	}
}

func TestDisabledAndRateLimit(t *testing.T) {
	fp := &fakeProber{}
	off := New(Options{Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: fp}}, Hop: func(context.Context, netip.Addr, netip.Addr, int, int, time.Duration) (netip.Addr, bool, error) {
		t.Fatal("hop while disabled")
		return netip.Addr{}, false, nil
	}})
	if _, err := off.Probe(context.Background(), addr("198.51.100.1")); !errors.Is(err, ErrDisabled) {
		t.Fatalf("probe: %v", err)
	}
	if _, err := off.Traceroute(context.Background(), addr("198.51.100.1"), ""); !errors.Is(err, ErrDisabled) {
		t.Fatalf("trace: %v", err)
	}
	if _, err := off.Whois(context.Background(), "AS64496"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("whois: %v", err)
	}
	if len(fp.reqs) != 0 {
		t.Fatal("probes sent while disabled")
	}
	on := New(Options{Enabled: true, Providers: provs, Probers: []probe.NamedProber{{Name: "fake", Prober: fp}}, Limiter: &allow{n: 1}})
	if _, err := on.Probe(context.Background(), addr("198.51.100.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := on.Probe(context.Background(), addr("198.51.100.1")); !errors.Is(err, ErrBusy) {
		t.Fatalf("second: %v", err)
	}
}

// fakeNet is a simulated path: hop n answers from 192.0.2.(100+n), the
// destination answers at ttl reach, and ttl silent never answers.
func fakeNet(reach, silent int) HopFunc {
	return func(_ context.Context, src, dst netip.Addr, ttl, port int, _ time.Duration) (netip.Addr, bool, error) {
		if port != tracePort+ttl-1 {
			return netip.Addr{}, false, fmt.Errorf("port %d", port)
		}
		if src == addr("192.0.2.11") {
			return netip.Addr{}, false, fmt.Errorf("bind: %w", plugin.ErrSourceUnavailable)
		}
		switch {
		case ttl == silent:
			return netip.Addr{}, false, nil
		case ttl >= reach:
			return dst, true, nil
		}
		return netip.AddrFrom4([4]byte{192, 0, 2, byte(100 + ttl)}), false, nil
	}
}

func TestTraceroute(t *testing.T) {
	tl := New(Options{Enabled: true, Providers: provs, Hop: fakeNet(4, 2), MaxHops: 10})
	ans, err := tl.Traceroute(context.Background(), addr("203.0.113.5"), "")
	if err != nil {
		t.Fatal(err)
	}
	a := ans.Traces[0]
	if !a.Reached || len(a.Hops) != 4 || a.Hops[1].Address.IsValid() || a.Hops[0].Address != addr("192.0.2.101") || a.Hops[3].Address != addr("203.0.113.5") {
		t.Fatalf("trace a: %+v", a)
	}
	if b := ans.Traces[1]; b.Reached || !strings.Contains(b.Error, "source") {
		t.Fatalf("trace b: %+v", b)
	}
	one, err := tl.Traceroute(context.Background(), addr("203.0.113.5"), "transit-a")
	if err != nil || len(one.Traces) != 1 {
		t.Fatalf("one provider: %+v %v", one, err)
	}
	if _, err := tl.Traceroute(context.Background(), addr("203.0.113.5"), "nope"); err == nil {
		t.Fatal("unknown provider accepted")
	}
	// Silence stops the trace before max_hops.
	quiet := New(Options{Enabled: true, Providers: provs[:1], MaxHops: 30, Hop: func(context.Context, netip.Addr, netip.Addr, int, int, time.Duration) (netip.Addr, bool, error) {
		return netip.Addr{}, false, nil
	}})
	ans, _ = quiet.Traceroute(context.Background(), addr("203.0.113.5"), "")
	if n := len(ans.Traces[0].Hops); n != 2*gapHops {
		t.Fatalf("silent hops: %d", n)
	}
	// Mixed families are refused per provider.
	ans, _ = tl.Traceroute(context.Background(), addr("2001:db8::1"), "transit-a")
	if ans.Traces[0].Error == "" {
		t.Fatal("v4 source traced a v6 target")
	}
}

// TestTracerouteHopAnnotations checks the origin AS comes from the learned
// RIB (longest match, last ASN, no default route) and that reverse names
// are attached per hop.
func TestTracerouteHopAnnotations(t *testing.T) {
	r := testRIB()
	r.routes = append(r.routes,
		rib.Route{Prefix: pfx("0.0.0.0/0"), NextHop: addr("192.0.2.1"), ASPath: []uint32{64499}},
		rib.Route{Prefix: pfx("192.0.2.96/28"), NextHop: addr("192.0.2.1"), ASPath: []uint32{64496, 0}},
		rib.Route{Prefix: pfx("192.0.2.112/28"), NextHop: addr("192.0.2.1")},
	)
	hop := func(_ context.Context, _, dst netip.Addr, ttl, _ int, _ time.Duration) (netip.Addr, bool, error) {
		switch ttl {
		case 1:
			return addr("198.51.100.200"), false, nil // inside 198.51.100.128/25: AS64500, not the /24's
		case 2:
			return netip.Addr{}, false, nil
		case 3:
			return addr("192.0.2.5"), false, nil // only the default route covers it
		case 4:
			return addr("192.0.2.100"), false, nil // trailing zero ASN is skipped
		case 5:
			return addr("192.0.2.120"), false, nil // learned route with an empty AS path
		}
		return dst, true, nil
	}
	rev := func(_ context.Context, a netip.Addr) string {
		if a == addr("198.51.100.200") {
			return "edge1.example.net"
		}
		return ""
	}
	tl := New(Options{Enabled: true, Providers: provs[:1], Hop: hop, Reverse: rev, MaxHops: 10})
	tl.SetRIB(r)
	ans, err := tl.Traceroute(context.Background(), addr("203.0.113.5"), "")
	if err != nil {
		t.Fatal(err)
	}
	got := ans.Traces[0].Hops
	if len(got) != 6 {
		t.Fatalf("hops: %+v", got)
	}
	for i, want := range []struct {
		as   uint32
		name string
	}{{64500, "edge1.example.net"}, {0, ""}, {0, ""}, {64496, ""}, {0, ""}, {64496, ""}} {
		if got[i].OriginAS != want.as || got[i].Name != want.name {
			t.Errorf("hop %d: origin %d name %q, want %d %q", got[i].TTL, got[i].OriginAS, got[i].Name, want.as, want.name)
		}
	}

	// Without a RIB view or a resolver the hops carry neither.
	bare := New(Options{Enabled: true, Providers: provs[:1], Hop: hop, MaxHops: 10})
	ans, _ = bare.Traceroute(context.Background(), addr("203.0.113.5"), "")
	for _, h := range ans.Traces[0].Hops {
		if h.OriginAS != 0 || h.Name != "" {
			t.Errorf("bare hop %d annotated: %+v", h.TTL, h)
		}
	}
}

// TestTracerouteSlowResolver checks one slow resolver cannot hold the
// answer past the shared reverse-lookup deadline.
func TestTracerouteSlowResolver(t *testing.T) {
	tl := New(Options{Enabled: true, Providers: provs[:1], Hop: fakeNet(2, 99), MaxHops: 4,
		Reverse: func(ctx context.Context, _ netip.Addr) string {
			<-ctx.Done()
			return ""
		}})
	start := time.Now()
	ans, err := tl.Traceroute(context.Background(), addr("203.0.113.5"), "")
	if err != nil || !ans.Traces[0].Reached {
		t.Fatalf("trace: %+v %v", ans, err)
	}
	if d := time.Since(start); d > reverseTimeout+2*time.Second {
		t.Fatalf("answer took %v", d)
	}
}

type fakeWhois struct {
	plugin.Base
	got []string
}

func (f *fakeWhois) Lookup(_ context.Context, q string) (plugin.WhoisResult, error) {
	f.got = append(f.got, q)
	return plugin.WhoisResult{Query: q, Kind: "asn", Name: "DOC-ASN"}, nil
}

func TestWhois(t *testing.T) {
	if _, err := New(Options{Enabled: true}).Whois(context.Background(), "AS64496"); !errors.Is(err, ErrNoWhois) {
		t.Fatalf("no plugin: %v", err)
	}
	fw := &fakeWhois{}
	tl := New(Options{Enabled: true, Whois: fw})
	for _, q := range []string{"AS64496", "64500", "192.0.2.0/24", "2001:db8::1"} {
		if _, err := tl.Whois(context.Background(), q); err != nil {
			t.Errorf("%q: %v", q, err)
		}
	}
	for _, q := range []string{"", "example.com", "https://rdap.example/ip/1", "AS", "192.0.2.0/24; rm"} {
		if _, err := tl.Whois(context.Background(), q); err == nil {
			t.Errorf("%q accepted", q)
		}
	}
	if len(fw.got) != 4 {
		t.Fatalf("plugin saw %v", fw.got)
	}
}
