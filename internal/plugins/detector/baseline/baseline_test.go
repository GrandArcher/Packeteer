package baseline

import (
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var (
	web = plugin.TrafficKey{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Protocol: 6}
	dns = plugin.TrafficKey{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Protocol: 17}
	doc = plugin.TrafficKey{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Protocol: 17}
)

func build(t *testing.T, yaml string) *Detector {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(c, plugin.Env{})
	if err != nil {
		t.Fatalf("New(%q): %v", yaml, err)
	}
	return d.(*Detector)
}

// feed runs rounds of synthetic traffic: rate(i) per key, with seeded
// noise of +-jitter (fraction). It returns the anomalies after each round.
func feed(d *Detector, start time.Time, rounds int, jitter float64, rng *rand.Rand, rate func(i int) map[plugin.TrafficKey]float64) [][]plugin.Anomaly {
	var out [][]plugin.Anomaly
	for i := range rounds {
		var s []plugin.TrafficSample
		for k, v := range rate(i) {
			if jitter > 0 {
				v *= 1 + jitter*(2*rng.Float64()-1)
			}
			s = append(s, plugin.TrafficSample{Key: k, Mbps: v})
		}
		out = append(out, d.Observe(start.Add(time.Duration(i)*10*time.Second), s))
	}
	return out
}

func steady(m map[plugin.TrafficKey]float64) func(int) map[plugin.TrafficKey]float64 {
	return func(int) map[plugin.TrafficKey]float64 { return m }
}

func TestConfigDefaultsAndBounds(t *testing.T) {
	d := build(t, "")
	c := d.cfg
	if c.Sensitivity != DefaultSensitivity || c.MinRatio != DefaultMinRatio || c.MinMbps != DefaultMinMbps || c.Alpha != DefaultAlpha ||
		c.Warmup != DefaultWarmup || c.TriggerRounds != DefaultTriggerRounds || c.ClearRounds != DefaultClearRounds || c.MaxKeys != DefaultMaxKeys || c.MaxMbps != 0 {
		t.Fatalf("defaults = %+v", c)
	}
	for _, bad := range []string{
		"sensitivity: -1", "sensitivity: 101", "sensitivity: .nan", "min_ratio: 0.5", "min_mbps: -2", "max_mbps: 5",
		"alpha: 1.5", "alpha: -0.1", "warmup: -1", "trigger_rounds: 1001", "clear_rounds: -3", "max_keys: 100001", "nope: 1",
	} {
		c, _ := plugin.ConfigFromYAML(bad)
		if _, err := New(c, plugin.Env{}); err == nil {
			t.Errorf("config %q accepted", bad)
		}
	}
	if !plugin.Detectors.Has(TypeName) {
		t.Fatal("baseline is not registered")
	}
}

// Steady noisy traffic never fires, and a flood 20x the baseline fires on
// the flooded key only, after trigger_rounds, and clears after
// clear_rounds of normal traffic.
func TestFloodDetectedAndCleared(t *testing.T) {
	d := build(t, "warmup: 20\ntrigger_rounds: 2\nclear_rounds: 3\nmin_mbps: 10")
	rng := rand.New(rand.NewPCG(1, 2))
	start := time.Unix(1_700_000_000, 0)
	base := map[plugin.TrafficKey]float64{web: 80, dns: 5}
	for i, a := range feed(d, start, 200, 0.2, rng, steady(base)) {
		if len(a) != 0 {
			t.Fatalf("round %d: steady traffic with 20%% noise raised %+v", i, a)
		}
	}
	flood := map[plugin.TrafficKey]float64{web: 80, dns: 100}
	got := feed(d, start.Add(2000*time.Second), 5, 0.2, rng, steady(flood))
	if len(got[0]) != 0 {
		t.Fatalf("fired on the first flood round (trigger_rounds 2): %+v", got[0])
	}
	a := got[1]
	if len(a) != 1 || a[0].Key != dns {
		t.Fatalf("second flood round = %+v, want one anomaly on %s", a, dns)
	}
	if a[0].BaselineMbps < 4 || a[0].BaselineMbps > 6 || a[0].Mbps < 79 || !strings.Contains(a[0].Reason, "above the") {
		t.Fatalf("anomaly = %+v", a[0])
	}
	since := a[0].Since
	if last := got[4]; len(last) != 1 || last[0].Since != since || last[0].BaselineMbps > 6 {
		t.Fatalf("the flood must not become the baseline: %+v", last)
	}
	after := feed(d, start.Add(3000*time.Second), 4, 0.2, rng, steady(base))
	if len(after[0]) != 1 || len(after[1]) != 1 || len(after[2]) != 0 || len(after[3]) != 0 {
		t.Fatalf("clear_rounds 3: %v", after)
	}
	// Reset forgets baselines and open anomalies: the flood is learned
	// again during warmup, not reported.
	feed(d, start.Add(4000*time.Second), 3, 0, rng, steady(flood))
	d.Reset()
	if d.Tracked() != 0 {
		t.Fatalf("tracked after Reset = %d", d.Tracked())
	}
	if a := feed(d, start.Add(5000*time.Second), 3, 0, rng, steady(flood)); len(a[2]) != 0 {
		t.Fatalf("anomaly after Reset during warmup: %+v", a[2])
	}
}

// Sensitivity is tunable: a 6x rise on a noisy key fires at sensitivity 3
// and not at sensitivity 40.
func TestSensitivity(t *testing.T) {
	run := func(sens string) bool {
		d := build(t, "warmup: 20\ntrigger_rounds: 1\nmin_ratio: 1\nsensitivity: "+sens)
		rng := rand.New(rand.NewPCG(7, 7))
		start := time.Unix(1_700_000_000, 0)
		feed(d, start, 100, 0.3, rng, steady(map[plugin.TrafficKey]float64{dns: 20}))
		a := feed(d, start.Add(time.Hour), 1, 0, rng, steady(map[plugin.TrafficKey]float64{dns: 120}))
		return len(a[0]) == 1
	}
	if !run("3") {
		t.Fatal("sensitivity 3 missed a 6x rise")
	}
	if run("40") {
		t.Fatal("sensitivity 40 fired on a 6x rise")
	}
}

// min_ratio, min_mbps, and warmup hold small or early rises back.
func TestFloors(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	rng := rand.New(rand.NewPCG(3, 4))
	t.Run("min_ratio", func(t *testing.T) {
		d := build(t, "warmup: 10\ntrigger_rounds: 1\nmin_ratio: 3\nsensitivity: 1")
		feed(d, start, 50, 0.05, rng, steady(map[plugin.TrafficKey]float64{web: 100}))
		if a := feed(d, start.Add(time.Hour), 3, 0, rng, steady(map[plugin.TrafficKey]float64{web: 250})); len(a[2]) != 0 {
			t.Fatalf("2.5x fired with min_ratio 3: %+v", a[2])
		}
	})
	t.Run("min_mbps", func(t *testing.T) {
		d := build(t, "warmup: 10\ntrigger_rounds: 1\nmin_mbps: 50")
		feed(d, start, 50, 0, rng, steady(map[plugin.TrafficKey]float64{web: 1}))
		if a := feed(d, start.Add(time.Hour), 1, 0, rng, steady(map[plugin.TrafficKey]float64{web: 40})); len(a[0]) != 0 {
			t.Fatalf("40x under min_mbps fired: %+v", a[0])
		}
		if a := feed(d, start.Add(2*time.Hour), 1, 0, rng, steady(map[plugin.TrafficKey]float64{web: 60})); len(a[0]) != 1 {
			t.Fatal("60x over min_mbps missed")
		}
	})
	t.Run("warmup", func(t *testing.T) {
		d := build(t, "warmup: 30\ntrigger_rounds: 1")
		feed(d, start, 10, 0, rng, steady(map[plugin.TrafficKey]float64{web: 10}))
		if a := feed(d, start.Add(time.Hour), 1, 0, rng, steady(map[plugin.TrafficKey]float64{web: 1000})); len(a[0]) != 0 {
			t.Fatalf("fired before warmup: %+v", a[0])
		}
	})
	t.Run("max_mbps", func(t *testing.T) {
		d := build(t, "warmup: 30\ntrigger_rounds: 1\nmax_mbps: 500")
		if a := feed(d, start, 1, 0, rng, steady(map[plugin.TrafficKey]float64{doc: 900})); len(a[0]) != 1 || !strings.Contains(a[0][0].Reason, "max_mbps") {
			t.Fatalf("max_mbps ceiling on a new key: %+v", a[0])
		}
	})
}

// max_keys bounds tracking, an idle key is forgotten, and invalid samples
// are ignored.
func TestQuietKeyAndLimits(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	rng := rand.New(rand.NewPCG(5, 6))
	d := build(t, "warmup: 5\ntrigger_rounds: 1\nmax_keys: 2")
	feed(d, start, 5, 0, rng, steady(map[plugin.TrafficKey]float64{web: 0.5, dns: 0.5, doc: 0.5}))
	if d.Tracked() != 2 {
		t.Fatalf("tracked = %d, want 2 (max_keys)", d.Tracked())
	}
	feed(d, start.Add(time.Hour), 400, 0, rng, steady(nil))
	if d.Tracked() != 0 {
		t.Fatalf("idle keys kept: %d", d.Tracked())
	}
	// Invalid samples are ignored.
	if a := d.Observe(start, []plugin.TrafficSample{{Key: plugin.TrafficKey{}, Mbps: 1e9}, {Key: web, Mbps: -5}}); len(a) != 0 || d.Tracked() != 0 {
		t.Fatalf("invalid samples tracked: %v %d", a, d.Tracked())
	}
}
