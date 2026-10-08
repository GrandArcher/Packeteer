package policy

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
)

// withSubranges adds two measured /24s to each result: rtt1 and rtt2 ms
// per provider, weights 3 and 1.
func withSubranges(res []probe.Result, rtt map[string][2]float64) []probe.Result {
	s1 := netip.MustParsePrefix("198.51.100.0/24")
	s2 := netip.MustParsePrefix("198.51.200.0/24")
	out := make([]probe.Result, len(res))
	for i, r := range res {
		v := rtt[r.Provider]
		r.Subranges = []probe.SubrangeResult{
			{Prefix: s1, Weight: 3, Time: r.Time, Stats: probe.Stats{Sent: 5, Received: 5, RTTAvg: time.Duration(v[0] * float64(time.Millisecond))}},
			{Prefix: s2, Weight: 1, Time: r.Time, Stats: probe.Stats{Sent: 5, Received: 5, RTTAvg: time.Duration(v[1] * float64(time.Millisecond))}},
		}
		out[i] = r
	}
	return out
}

func TestSubrangeFlagAndUnchangedDecision(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	wide := netip.MustParsePrefix("198.51.0.0/16")
	// The prefix rows are the weighted aggregate the engine would build.
	base := results(now, wide, m{"a", 0, 25}, m{"b", 0, 70}, m{"c", 0, 90})
	native := map[netip.Prefix]string{wide: "b"}

	_, plain := Decide(NewState(), in(base, native), cfg(), scorer(t), now)

	t.Run("heterogeneous", func(t *testing.T) {
		res := withSubranges(base, map[string][2]float64{"a": {10, 70}, "b": {80, 40}, "c": {90, 90}})
		_, out := Decide(NewState(), in(res, native), cfg(), scorer(t), now)
		d := decision(t, out, wide)
		if !d.Heterogeneous || len(d.Subranges) != 2 || d.Subranges[0].Best != "a" || d.Subranges[1].Best != "b" {
			t.Fatalf("decision = %+v", d)
		}
		if d.Subranges[0].Weight != 3 || len(d.Subranges[0].Candidates) != 3 {
			t.Fatalf("sub-range = %+v", d.Subranges[0])
		}
		// The flag and sub-range table change nothing else.
		p := decision(t, plain, wide)
		d.Subranges, d.Heterogeneous = nil, false
		if !reflect.DeepEqual(d, p) || !reflect.DeepEqual(out.Changes, plain.Changes) {
			t.Fatalf("decision changed by sub-ranges:\n%+v\n%+v\n%+v\n%+v", d, p, out.Changes, plain.Changes)
		}
	})

	t.Run("homogeneous", func(t *testing.T) {
		res := withSubranges(base, map[string][2]float64{"a": {10, 20}, "b": {80, 40}, "c": {90, 90}})
		_, out := Decide(NewState(), in(res, native), cfg(), scorer(t), now)
		d := decision(t, out, wide)
		if d.Heterogeneous || len(d.Subranges) != 2 || d.Subranges[0].Best != "a" || d.Subranges[1].Best != "a" {
			t.Fatalf("decision = %+v", d)
		}
	})

	t.Run("unusable provider is not a sub-range best", func(t *testing.T) {
		res := withSubranges(base, map[string][2]float64{"a": {10, 70}, "b": {80, 40}, "c": {90, 5}})
		c := cfg()
		c.Excluded = map[string]bool{"c": true}
		up := map[string]bool{"a": true, "b": false, "c": true}
		input := in(res, native)
		input.ProviderUp = up
		_, out := Decide(NewState(), input, c, scorer(t), now)
		d := decision(t, out, wide)
		if d.Heterogeneous || d.Subranges[0].Best != "a" || d.Subranges[1].Best != "a" {
			t.Fatalf("decision = %+v", d)
		}
		for _, sc := range d.Subranges[1].Candidates {
			if sc.Provider == "b" && (sc.Usable || sc.Why != "provider down") {
				t.Fatalf("down provider usable for a sub-range: %+v", sc)
			}
		}
	})
}
