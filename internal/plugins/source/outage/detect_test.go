package outage

import (
	"net/netip"
	"testing"
	"time"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func baseCfg() Config {
	return Config{
		MinPrefixes: 3,
		Window:      time.Minute,
		LossPct:     20,
		Interval:    5 * time.Second,
		MaxTargets:  100,
	}.normalized()
}

func at(now time.Time, prov, cidr string, loss float64) Sample {
	return Sample{Provider: prov, Prefix: pfx(cidr), LossPct: loss, RTT: 10 * time.Millisecond, Time: now}
}

func failed(now time.Time, prov, cidr string) Sample {
	return Sample{Provider: prov, Prefix: pfx(cidr), Failed: true, Time: now}
}

type detectCase struct {
	name       string
	cfg        Config
	samples    []Sample
	routes     []Route
	wantAS     []uint32
	wantCirc   []string
	wantTarget []string
	forbid     []string
	truncated  bool
}

func TestDetect(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := baseCfg()
	shared := []Route{
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64500, 64496}, Provider: "transit-a"},
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64500, 64497}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64500, 64498}, Provider: "transit-b"},
		{Prefix: pfx("203.0.113.0/25"), ASPath: []uint32{64501, 64499}, Provider: "transit-b"},
		{Prefix: pfx("2001:db8::/32"), ASPath: []uint32{64500, 64496}}, // crosses 64500, not yet probed
		{Prefix: pfx("0.0.0.0/0"), ASPath: []uint32{64500}},
	}
	diverse := []Route{
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64496}, Provider: "transit-a"},
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64497}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64498}, Provider: "transit-a"},
		{Prefix: pfx("192.0.2.0/25"), ASPath: []uint32{64499}, Provider: "transit-b"},
	}
	bothBad := func(cidr string) []Sample {
		return []Sample{at(now, "transit-a", cidr, 80), at(now, "transit-b", cidr, 90)}
	}
	onlyA := func(cidr string) []Sample {
		return []Sample{at(now, "transit-a", cidr, 80), at(now, "transit-b", cidr, 0)}
	}

	cases := []detectCase{
		{
			name: "as pattern requeues every learned prefix crossing the asn",
			cfg:  cfg,
			samples: append(append(append(
				bothBad("192.0.2.0/24"),
				bothBad("198.51.100.0/24")...),
				bothBad("203.0.113.0/24")...),
				at(now, "transit-a", "203.0.113.0/25", 0)),
			routes:     shared,
			wantAS:     []uint32{64500},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"},
			forbid:     []string{"203.0.113.0/25", "0.0.0.0/0"},
		},
		{
			name: "single noisy prefix",
			cfg:  cfg,
			samples: append(bothBad("192.0.2.0/24"),
				at(now, "transit-a", "198.51.100.0/24", 0),
				at(now, "transit-a", "203.0.113.0/24", 1)),
			routes: shared,
		},
		{
			name: "two prefixes stay under the minimum",
			cfg:  cfg,
			samples: append(append(
				bothBad("192.0.2.0/24"),
				bothBad("198.51.100.0/24")...),
				at(now, "transit-a", "203.0.113.0/24", 0)),
			routes: shared,
		},
		{
			name: "provider-specific loss is a circuit, not an as",
			cfg:  cfg,
			samples: append(append(append(
				onlyA("192.0.2.0/24"),
				onlyA("198.51.100.0/24")...),
				onlyA("203.0.113.0/24")...),
				at(now, "transit-b", "192.0.2.0/25", 0)),
			routes:     shared,
			wantCirc:   []string{"transit-a"},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
			forbid:     []string{"2001:db8::/32", "203.0.113.0/25", "0.0.0.0/0"},
		},
		{
			name: "diverse asns on one provider are a circuit",
			cfg:  cfg,
			samples: []Sample{
				at(now, "transit-a", "192.0.2.0/24", 100),
				at(now, "transit-a", "198.51.100.0/24", 40),
				failed(now, "transit-a", "203.0.113.0/24"),
			},
			routes:     diverse,
			wantCirc:   []string{"transit-a"},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
		},
		{
			name: "single provider shared asn is an as incident",
			cfg:  cfg,
			samples: []Sample{
				at(now, "transit-a", "192.0.2.0/24", 50),
				at(now, "transit-a", "198.51.100.0/24", 50),
				at(now, "transit-a", "203.0.113.0/24", 50),
			},
			routes:     shared,
			wantAS:     []uint32{64500},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"},
			forbid:     []string{"203.0.113.0/25"},
		},
		{
			name: "both providers bad with no shared asn is not a circuit",
			cfg:  cfg,
			samples: append(append(
				bothBad("192.0.2.0/24"),
				bothBad("198.51.100.0/24")...),
				bothBad("203.0.113.0/24")...),
			routes: diverse,
		},
		{
			name: "sample outside the window does not count",
			cfg:  cfg,
			samples: []Sample{
				at(now.Add(-cfg.Window), "transit-a", "192.0.2.0/24", 100),
				at(now.Add(-cfg.Window), "transit-b", "192.0.2.0/24", 100),
				at(now.Add(-cfg.Window-time.Nanosecond), "transit-a", "198.51.100.0/24", 100),
				at(now.Add(-cfg.Window-time.Nanosecond), "transit-b", "198.51.100.0/24", 100),
				at(now, "transit-a", "203.0.113.0/24", 100),
				at(now, "transit-b", "203.0.113.0/24", 100),
			},
			routes: shared,
		},
		{
			name: "newer healthy sample inside the window clears the failure",
			cfg:  cfg,
			samples: []Sample{
				at(now.Add(-30*time.Second), "transit-a", "192.0.2.0/24", 100),
				at(now.Add(-30*time.Second), "transit-b", "192.0.2.0/24", 100),
				at(now, "transit-a", "192.0.2.0/24", 0),
				at(now, "transit-b", "192.0.2.0/24", 0),
				at(now, "transit-a", "198.51.100.0/24", 100),
				at(now, "transit-b", "198.51.100.0/24", 100),
				at(now, "transit-a", "203.0.113.0/24", 100),
				at(now, "transit-b", "203.0.113.0/24", 100),
			},
			routes: shared,
		},
		{
			name: "congestion by rtt on one provider",
			cfg:  Config{MinPrefixes: 3, Window: time.Minute, LossPct: 20, RTTMs: 200, Interval: 5 * time.Second, MaxTargets: 100},
			samples: []Sample{
				{Provider: "transit-a", Prefix: pfx("192.0.2.0/24"), RTT: 250 * time.Millisecond, Time: now},
				{Provider: "transit-b", Prefix: pfx("192.0.2.0/24"), RTT: 10 * time.Millisecond, Time: now},
				{Provider: "transit-a", Prefix: pfx("198.51.100.0/24"), RTT: 200 * time.Millisecond, Time: now},
				{Provider: "transit-b", Prefix: pfx("198.51.100.0/24"), RTT: 10 * time.Millisecond, Time: now},
				{Provider: "transit-a", Prefix: pfx("203.0.113.0/24"), LossPct: 5, RTT: 400 * time.Millisecond, Time: now},
				{Provider: "transit-b", Prefix: pfx("203.0.113.0/24"), RTT: 10 * time.Millisecond, Time: now},
			},
			routes:     shared,
			wantCirc:   []string{"transit-a"},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
			forbid:     []string{"2001:db8::/32"},
		},
		{
			name: "rtt below the threshold is healthy",
			cfg:  Config{MinPrefixes: 3, Window: time.Minute, LossPct: 50, RTTMs: 200, Interval: 5 * time.Second, MaxTargets: 100},
			samples: []Sample{
				{Provider: "transit-a", Prefix: pfx("192.0.2.0/24"), RTT: 199 * time.Millisecond, Time: now},
				{Provider: "transit-a", Prefix: pfx("198.51.100.0/24"), RTT: 199 * time.Millisecond, Time: now},
				{Provider: "transit-a", Prefix: pfx("203.0.113.0/24"), RTT: 199 * time.Millisecond, Time: now},
			},
			routes: shared,
		},
		{
			name: "ignore local asn that sits on every path",
			cfg:  Config{MinPrefixes: 3, Window: time.Minute, LossPct: 20, Interval: 5 * time.Second, MaxTargets: 100, IgnoreASNs: []uint32{64512}},
			samples: []Sample{
				at(now, "transit-a", "192.0.2.0/24", 80),
				at(now, "transit-a", "198.51.100.0/24", 80),
				at(now, "transit-a", "203.0.113.0/24", 80),
			},
			routes: []Route{
				{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64512, 64496}},
				{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64512, 64497}},
				{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64512, 64498}},
			},
			wantCirc:   []string{"transit-a"},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
		},
		{
			name: "max targets keeps degraded prefixes first",
			cfg:  Config{MinPrefixes: 3, Window: time.Minute, LossPct: 20, Interval: 5 * time.Second, MaxTargets: 3},
			samples: append(append(
				bothBad("192.0.2.0/24"),
				bothBad("198.51.100.0/24")...),
				bothBad("203.0.113.0/24")...),
			routes:     shared,
			wantAS:     []uint32{64500},
			wantTarget: []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"},
			forbid:     []string{"2001:db8::/32"},
			truncated:  true,
		},
		{
			name: "zero timestamp is outside the window",
			cfg:  cfg,
			samples: []Sample{
				{Provider: "transit-a", Prefix: pfx("192.0.2.0/24"), LossPct: 100},
				{Provider: "transit-b", Prefix: pfx("192.0.2.0/24"), LossPct: 100},
				at(now, "transit-a", "198.51.100.0/24", 100),
				at(now, "transit-b", "198.51.100.0/24", 100),
				at(now, "transit-a", "203.0.113.0/24", 100),
				at(now, "transit-b", "203.0.113.0/24", 100),
			},
			routes: shared,
		},
		{
			name: "future sample is ignored",
			cfg:  cfg,
			samples: []Sample{
				at(now.Add(time.Second), "transit-a", "192.0.2.0/24", 100),
				at(now.Add(time.Second), "transit-b", "192.0.2.0/24", 100),
				at(now, "transit-a", "198.51.100.0/24", 100),
				at(now, "transit-b", "198.51.100.0/24", 100),
				at(now, "transit-a", "203.0.113.0/24", 100),
				at(now, "transit-b", "203.0.113.0/24", 100),
			},
			routes: shared,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(now, tc.samples, tc.routes, tc.cfg)
			var asns []uint32
			var circ []string
			for _, inc := range got.Incidents {
				switch inc.Kind {
				case IncidentAS:
					asns = append(asns, inc.ASN)
					if len(inc.Prefixes) < tc.cfg.normalized().MinPrefixes {
						t.Errorf("AS %d counted %d prefixes", inc.ASN, len(inc.Prefixes))
					}
				case IncidentCircuit:
					circ = append(circ, inc.Provider)
					if len(inc.Prefixes) < tc.cfg.normalized().MinPrefixes {
						t.Errorf("circuit %s counted %d prefixes", inc.Provider, len(inc.Prefixes))
					}
				default:
					t.Errorf("kind %q", inc.Kind)
				}
			}
			if !sameU32(asns, tc.wantAS) {
				t.Errorf("AS incidents %v, want %v", asns, tc.wantAS)
			}
			if !sameStr(circ, tc.wantCirc) {
				t.Errorf("circuit incidents %v, want %v", circ, tc.wantCirc)
			}
			have := map[string]pluginInterval{}
			for _, tg := range got.Targets {
				have[tg.Prefix.String()] = pluginInterval{tg.Interval, tg.Urgent}
				if tg.Prefix.Bits() == 0 {
					t.Errorf("default route requeued: %s", tg.Prefix)
				}
			}
			for _, want := range tc.wantTarget {
				iv, ok := have[want]
				if !ok {
					t.Errorf("missing target %s in %v", want, keys(have))
					continue
				}
				if iv.d != tc.cfg.normalized().Interval {
					t.Errorf("%s interval %s", want, iv.d)
				}
			}
			for _, bad := range tc.forbid {
				if _, ok := have[bad]; ok {
					t.Errorf("requeued %s", bad)
				}
			}
			if len(tc.wantTarget) == 0 && len(got.Targets) != 0 {
				t.Errorf("targets = %v", keys(have))
			}
			if len(tc.wantTarget) != 0 && len(have) != len(tc.wantTarget) {
				t.Errorf("targets = %v, want %v", keys(have), tc.wantTarget)
			}
			if got.Truncated != tc.truncated {
				t.Errorf("truncated = %v, want %v", got.Truncated, tc.truncated)
			}
			for _, inc := range got.Incidents {
				if inc.Requeued < len(inc.Prefixes) {
					t.Errorf("%s requeued %d, triggering %d", incidentKey(inc), inc.Requeued, len(inc.Prefixes))
				}
			}
		})
	}
}

type pluginInterval struct {
	d      time.Duration
	urgent bool
}

func atHops(now time.Time, prov, cidr string, loss float64, hops ...string) Sample {
	s := at(now, prov, cidr, loss)
	for _, h := range hops {
		s.Hops = append(s.Hops, netip.MustParseAddr(h))
	}
	return s
}

func incidentAS(out Outcome, asn uint32) (Incident, bool) {
	for _, inc := range out.Incidents {
		if inc.Kind == IncidentAS && inc.ASN == asn {
			return inc, true
		}
	}
	return Incident{}, false
}

func targetSet(out Outcome) map[string]bool {
	m := map[string]bool{}
	for _, tg := range out.Targets {
		m[tg.Prefix.String()] = true
	}
	return m
}

// TestHopASNOpensIncident: an origin ASN that appears only in traceroute
// hops, not on the BGP path, is enough to open an incident.
func TestHopASNOpensIncident(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := baseCfg()
	routes := []Route{
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64496}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64497}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.128/25"), ASPath: []uint32{64498}, Provider: "transit-b"},
		// 192.0.2.1 is inside the /25, so the origin is 64503, not 64502.
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64510, 64502}},
		{Prefix: pfx("192.0.2.0/25"), ASPath: []uint32{64511, 64503}},
	}
	hop := "192.0.2.1"
	samples := []Sample{
		atHops(now, "transit-a", "198.51.100.0/24", 80, hop),
		atHops(now, "transit-b", "198.51.100.0/24", 90, hop),
		atHops(now, "transit-a", "203.0.113.0/24", 80, hop),
		atHops(now, "transit-b", "203.0.113.0/24", 90, hop),
		atHops(now, "transit-a", "203.0.113.128/25", 80, hop),
		atHops(now, "transit-b", "203.0.113.128/25", 90, hop),
	}
	got := Detect(now, samples, routes, cfg)
	inc, ok := incidentAS(got, 64503)
	if !ok {
		t.Fatalf("incidents = %+v, want AS 64503", got.Incidents)
	}
	if _, other := incidentAS(got, 64502); other {
		t.Fatal("longer prefix lost to the covering /24")
	}
	if len(got.Incidents) != 1 {
		t.Fatalf("incidents = %+v", got.Incidents)
	}
	have := targetSet(got)
	for _, want := range []string{"192.0.2.0/25", "198.51.100.0/24", "203.0.113.0/24", "203.0.113.128/25"} {
		if !have[want] {
			t.Errorf("missing %s in %v", want, have)
		}
	}
	if have["192.0.2.0/24"] {
		t.Errorf("covering /24 does not contain 64503: %v", have)
	}
	if inc.Requeued < len(inc.Prefixes) {
		t.Errorf("requeued %d, triggering %d", inc.Requeued, len(inc.Prefixes))
	}

	// Two prefixes stay under min_prefixes.
	short := Detect(now, samples[:4], routes, cfg)
	if len(short.Incidents) != 0 || len(short.Targets) != 0 {
		t.Fatalf("two hop prefixes fired: %+v", short.Incidents)
	}

	// An ignored origin is not an incident.
	ignored := cfg
	ignored.IgnoreASNs = []uint32{64503}
	if out := Detect(now, samples, routes, ignored); len(out.Incidents) != 0 {
		t.Fatalf("ignored hop origin opened %+v", out.Incidents)
	}

	// The same samples with the hops removed do not share an ASN.
	for i := range samples {
		samples[i].Hops = nil
	}
	plain := Detect(now, samples, routes, cfg)
	if len(plain.Incidents) != 0 || len(plain.Targets) != 0 {
		t.Fatalf("no traces changed the result: %+v targets %v", plain.Incidents, plain.Targets)
	}
}

// TestAltPathASNAttributedToProvider: a sick ASN that exists only on a
// non-native provider's learned path is that provider's incident, not a
// circuit and not the native exit.
func TestAltPathASNAttributedToProvider(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := baseCfg()
	alt := func(origin uint32) []Alt {
		return []Alt{{Provider: "transit-b", ASPath: []uint32{64501, origin}}}
	}
	routes := []Route{
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64496}, Provider: "transit-a", Alts: alt(64496)},
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64497}, Provider: "transit-a", Alts: alt(64497)},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64498}, Provider: "transit-a", Alts: alt(64498)},
		{Prefix: pfx("2001:db8:1::/48"), ASPath: []uint32{64499}, Provider: "transit-a", Alts: alt(64499)},
		{Prefix: pfx("2001:db8::/32"), ASPath: []uint32{64499}, Provider: "transit-a"},
	}
	samples := []Sample{
		at(now, "transit-a", "192.0.2.0/24", 0), at(now, "transit-b", "192.0.2.0/24", 80),
		at(now, "transit-a", "198.51.100.0/24", 0), at(now, "transit-b", "198.51.100.0/24", 80),
		at(now, "transit-a", "203.0.113.0/24", 0), at(now, "transit-b", "203.0.113.0/24", 80),
	}
	got := Detect(now, samples, routes, cfg)
	inc, ok := incidentAS(got, 64501)
	if !ok || len(got.Incidents) != 1 {
		t.Fatalf("incidents = %+v", got.Incidents)
	}
	if !sameStr(inc.Providers, []string{"transit-b"}) {
		t.Fatalf("providers = %v, want transit-b", inc.Providers)
	}
	if inc.Provider != "" {
		t.Fatalf("AS incident stored a circuit provider %q", inc.Provider)
	}
	have := targetSet(got)
	for _, want := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8:1::/48"} {
		if !have[want] {
			t.Errorf("missing %s in %v", want, have)
		}
	}
	if have["2001:db8::/32"] {
		t.Errorf("prefix without 64501 was requeued: %v", have)
	}
}

// TestHopASNAttributedToProvider: the degraded provider's trace, not the
// native BGP path, names the ASN.
func TestHopASNAttributedToProvider(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := baseCfg()
	routes := []Route{
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64496}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64497}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.128/25"), ASPath: []uint32{64498}, Provider: "transit-a"},
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64504}},
	}
	bad := func(cidr string) Sample {
		return atHops(now, "transit-b", cidr, 90, "192.0.2.50")
	}
	got := Detect(now, []Sample{
		at(now, "transit-a", "198.51.100.0/24", 0), bad("198.51.100.0/24"),
		at(now, "transit-a", "203.0.113.0/24", 0), bad("203.0.113.0/24"),
		at(now, "transit-a", "203.0.113.128/25", 0), bad("203.0.113.128/25"),
	}, routes, cfg)
	inc, ok := incidentAS(got, 64504)
	if !ok || len(got.Incidents) != 1 {
		t.Fatalf("incidents = %+v", got.Incidents)
	}
	if !sameStr(inc.Providers, []string{"transit-b"}) {
		t.Fatalf("providers = %v", inc.Providers)
	}
	if !targetSet(got)["192.0.2.0/24"] {
		t.Fatalf("targets = %v", targetSet(got))
	}
}

// TestNoTracesLeavesBGPCorrelationUnchanged compares a native-path case
// with the same inputs carrying empty hop lists and no alternate paths.
func TestNoTracesLeavesBGPCorrelationUnchanged(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	cfg := baseCfg()
	routes := []Route{
		{Prefix: pfx("192.0.2.0/24"), ASPath: []uint32{64500, 64496}, Provider: "transit-a"},
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64500, 64497}, Provider: "transit-a"},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64500, 64498}, Provider: "transit-b"},
		{Prefix: pfx("2001:db8::/32"), ASPath: []uint32{64500, 64496}},
	}
	samples := []Sample{
		at(now, "transit-a", "192.0.2.0/24", 80), at(now, "transit-b", "192.0.2.0/24", 90),
		at(now, "transit-a", "198.51.100.0/24", 80), at(now, "transit-b", "198.51.100.0/24", 90),
		at(now, "transit-a", "203.0.113.0/24", 80), at(now, "transit-b", "203.0.113.0/24", 90),
	}
	base := Detect(now, samples, routes, cfg)
	withEmpty := append([]Sample(nil), samples...)
	for i := range withEmpty {
		withEmpty[i].Hops = []netip.Addr{}
	}
	got := Detect(now, withEmpty, routes, cfg)
	if !sameU32(asnsOf(base), asnsOf(got)) || !sameStr(circOf(base), circOf(got)) {
		t.Fatalf("base %+v vs empty hops %+v", base.Incidents, got.Incidents)
	}
	if len(base.Targets) != len(got.Targets) {
		t.Fatalf("targets %v vs %v", targetSet(base), targetSet(got))
	}

	// Hops that resolve to the native ASN do not turn a one-provider
	// failure into an AS incident.
	circuit := []Sample{
		atHops(now, "transit-a", "192.0.2.0/24", 80, "192.0.2.1"), at(now, "transit-b", "192.0.2.0/24", 0),
		atHops(now, "transit-a", "198.51.100.0/24", 80, "192.0.2.1"), at(now, "transit-b", "198.51.100.0/24", 0),
		atHops(now, "transit-a", "203.0.113.0/24", 80, "192.0.2.1"), at(now, "transit-b", "203.0.113.0/24", 0),
	}
	cover := append(routes, Route{Prefix: pfx("192.0.2.0/25"), ASPath: []uint32{64500}})
	hopCirc := Detect(now, circuit, cover, cfg)
	if len(asnsOf(hopCirc)) != 0 || !sameStr(circOf(hopCirc), []string{"transit-a"}) {
		t.Fatalf("native hop ASN changed the circuit: %+v", hopCirc.Incidents)
	}

	// An address no learned prefix covers does not invent an ASN.
	// 192.0.2.9 is only inside the default, which is not a match.
	nowhere := []Sample{
		atHops(now, "transit-a", "198.51.100.0/24", 100, "192.0.2.9"),
		atHops(now, "transit-b", "198.51.100.0/24", 100, "192.0.2.9"),
		atHops(now, "transit-a", "203.0.113.0/24", 100, "192.0.2.9"),
		atHops(now, "transit-b", "203.0.113.0/24", 100, "192.0.2.9"),
		atHops(now, "transit-a", "203.0.113.128/25", 100, "192.0.2.9"),
		atHops(now, "transit-b", "203.0.113.128/25", 100, "192.0.2.9"),
	}
	div := []Route{
		{Prefix: pfx("198.51.100.0/24"), ASPath: []uint32{64496}},
		{Prefix: pfx("203.0.113.0/24"), ASPath: []uint32{64497}},
		{Prefix: pfx("203.0.113.128/25"), ASPath: []uint32{64498}},
		{Prefix: pfx("0.0.0.0/0"), ASPath: []uint32{64509}},
	}
	if out := Detect(now, nowhere, div, cfg); len(out.Incidents) != 0 {
		t.Fatalf("unmatched hops opened %+v", out.Incidents)
	}
}

func asnsOf(out Outcome) []uint32 {
	var asns []uint32
	for _, inc := range out.Incidents {
		if inc.Kind == IncidentAS {
			asns = append(asns, inc.ASN)
		}
	}
	return asns
}

func circOf(out Outcome) []string {
	var s []string
	for _, inc := range out.Incidents {
		if inc.Kind == IncidentCircuit {
			s = append(s, inc.Provider)
		}
	}
	return s
}

func keys(m map[string]pluginInterval) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func sameU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
