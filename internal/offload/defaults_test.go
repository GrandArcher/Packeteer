package offload

import (
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func q(provider string, score float64) ProviderQuality {
	return ProviderQuality{Provider: provider, Score: score}
}

func order(r []RankedProvider) []string {
	var out []string
	for _, p := range r {
		out = append(out, p.Provider)
	}
	return out
}

func TestWeighQualityWeightsByVolume(t *testing.T) {
	a, b := netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24")
	idle := netip.MustParsePrefix("203.0.113.0/24")
	samples := []QualitySample{
		{Prefix: a, Provider: "transit-a", Score: 10, LossPct: 0, RTT: 20 * time.Millisecond},
		{Prefix: b, Provider: "transit-a", Score: 40, LossPct: 2, RTT: 80 * time.Millisecond},
		{Prefix: idle, Provider: "transit-a", Score: 1000, LossPct: 90, RTT: time.Second},
		{Prefix: a, Provider: "transit-b", Score: 30},
	}
	// 300 Mbps to a, 100 to b, a rate of 0 for idle.
	got := WeighQuality(samples, map[netip.Prefix]float64{a: 300, b: 100, idle: 0})
	if len(got) != 2 || got[0].Provider != "transit-a" || got[1].Provider != "transit-b" {
		t.Fatalf("got %+v", got)
	}
	ta := got[0]
	if math.Abs(ta.Score-17.5) > 1e-9 || math.Abs(ta.LossPct-0.5) > 1e-9 || math.Abs(ta.RTTMs-35) > 1e-9 || ta.Prefixes != 2 || ta.VolumeMbps != 400 {
		t.Errorf("transit-a = %+v, want score 17.5 loss 0.5 rtt 35 over 2 prefixes and 400 Mbps", ta)
	}
}

func TestWeighQualityWithoutRatesWeighsEqually(t *testing.T) {
	a, b := netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24")
	got := WeighQuality([]QualitySample{
		{Prefix: a, Provider: "transit-a", Score: 10},
		{Prefix: b, Provider: "transit-a", Score: 40},
	}, nil)
	if len(got) != 1 || got[0].Score != 25 || got[0].Prefixes != 2 {
		t.Errorf("got %+v", got)
	}
}

// A provider with no sample that carries traffic is absent: unknown, not zero.
func TestWeighQualityDropsProvidersWithoutTraffic(t *testing.T) {
	a, b := netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24")
	got := WeighQuality([]QualitySample{
		{Prefix: a, Provider: "transit-a", Score: 10},
		{Prefix: b, Provider: "transit-b", Score: 5},
		{Prefix: a, Provider: "transit-c", Score: math.NaN()},
	}, map[netip.Prefix]float64{a: 10})
	if len(got) != 1 || got[0].Provider != "transit-a" {
		t.Errorf("got %+v", got)
	}
}

func TestNewRankerRejectsBadConfig(t *testing.T) {
	for _, c := range []RankerConfig{{Margin: -0.1}, {Margin: math.NaN()}, {Margin: math.Inf(1)}, {Cooldown: -time.Second}} {
		if _, err := NewRanker(c); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
}

func TestRankFirstOrderIsByScore(t *testing.T) {
	r, _ := NewRanker(RankerConfig{Margin: 0.25, Cooldown: time.Hour})
	got := r.Rank(time.Unix(0, 0), []string{"transit-a", "transit-b", "ix-c"}, []ProviderQuality{q("transit-a", 30), q("transit-b", 10)})
	// ix-c has no measurement: it ranks last and is not Known.
	if !slices.Equal(order(got), []string{"transit-b", "transit-a", "ix-c"}) {
		t.Fatalf("order = %v", order(got))
	}
	if got[0].Rank != 1 || got[2].Rank != 3 || !got[0].Known || got[2].Known {
		t.Errorf("got %+v", got)
	}
}

// A provider that is only a little better does not pass the one above it.
func TestRankHysteresisHoldsInsideTheMargin(t *testing.T) {
	r, _ := NewRanker(RankerConfig{Margin: 0.25})
	t0 := time.Unix(0, 0)
	r.Rank(t0, []string{"transit-a", "transit-b"}, []ProviderQuality{q("transit-a", 10), q("transit-b", 12)})

	// transit-b is now 20% better than transit-a: inside the 25% margin.
	got := r.Rank(t0.Add(time.Minute), []string{"transit-a", "transit-b"}, []ProviderQuality{q("transit-a", 10), q("transit-b", 8)})
	if !slices.Equal(order(got), []string{"transit-a", "transit-b"}) {
		t.Errorf("inside the margin: %v", order(got))
	}
	// 40% better: past the margin.
	got = r.Rank(t0.Add(2*time.Minute), []string{"transit-a", "transit-b"}, []ProviderQuality{q("transit-a", 10), q("transit-b", 6)})
	if !slices.Equal(order(got), []string{"transit-b", "transit-a"}) {
		t.Errorf("past the margin: %v", order(got))
	}
}

// After a change the order stays for the cooldown, however large the swing.
func TestRankCooldownHoldsTheOrder(t *testing.T) {
	r, _ := NewRanker(RankerConfig{Margin: 0.1, Cooldown: 10 * time.Minute})
	t0 := time.Unix(0, 0)
	set := []string{"transit-a", "transit-b"}
	r.Rank(t0, set, []ProviderQuality{q("transit-a", 10), q("transit-b", 20)})

	got := r.Rank(t0.Add(time.Minute), set, []ProviderQuality{q("transit-a", 20), q("transit-b", 10)})
	if !slices.Equal(order(got), []string{"transit-b", "transit-a"}) {
		t.Fatalf("first change: %v", order(got))
	}
	swung := []ProviderQuality{q("transit-a", 5), q("transit-b", 10)}
	got = r.Rank(t0.Add(5*time.Minute), set, swung)
	if !slices.Equal(order(got), []string{"transit-b", "transit-a"}) {
		t.Errorf("inside the cooldown: %v", order(got))
	}
	got = r.Rank(t0.Add(12*time.Minute), set, swung)
	if !slices.Equal(order(got), []string{"transit-a", "transit-b"}) {
		t.Errorf("after the cooldown: %v", order(got))
	}
}

// An unmeasured provider never passes a measured one, and a measured one
// passes it at once.
func TestRankUnknownNeverOutranksKnown(t *testing.T) {
	r, _ := NewRanker(RankerConfig{Margin: 0.25, Cooldown: time.Hour})
	t0 := time.Unix(0, 0)
	set := []string{"transit-a", "transit-b"}
	got := r.Rank(t0, set, []ProviderQuality{q("transit-b", 50)})
	if !slices.Equal(order(got), []string{"transit-b", "transit-a"}) {
		t.Fatalf("order = %v", order(got))
	}
	got = r.Rank(t0.Add(time.Minute), set, []ProviderQuality{q("transit-a", 1)})
	if !slices.Equal(order(got), []string{"transit-a", "transit-b"}) {
		t.Errorf("order = %v", order(got))
	}
}

// A provider that leaves the set drops out. One that joins starts last and
// moves up only past the margin.
func TestRankSetChange(t *testing.T) {
	r, _ := NewRanker(RankerConfig{Margin: 0.25, Cooldown: time.Hour})
	t0 := time.Unix(0, 0)
	qs := []ProviderQuality{q("transit-a", 10), q("transit-b", 20), q("transit-c", 18)}
	r.Rank(t0, []string{"transit-a", "transit-b"}, qs)
	got := r.Rank(t0.Add(time.Minute), []string{"transit-b", "transit-c"}, qs)
	if !slices.Equal(order(got), []string{"transit-b", "transit-c"}) {
		t.Errorf("inside the margin: %v", order(got))
	}
	qs[2] = q("transit-c", 10)
	got = r.Rank(t0.Add(2*time.Minute), []string{"transit-b", "transit-c"}, qs)
	if !slices.Equal(order(got), []string{"transit-c", "transit-b"}) {
		t.Errorf("past the margin: %v", order(got))
	}
}
