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
