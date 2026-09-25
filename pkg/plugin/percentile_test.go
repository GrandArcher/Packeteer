package plugin

import "testing"

func TestPercentile95(t *testing.T) {
	if v, ok := Percentile95(nil); ok || v != 0 {
		t.Fatalf("empty = %v %v", v, ok)
	}
	if v, ok := Percentile95([]float64{10}); !ok || v != 10 {
		t.Fatalf("single = %v %v", v, ok)
	}
	asc := make([]float64, 100)
	for i := range asc {
		asc[i] = float64(i + 1)
	}
	if v, _ := Percentile95(asc); v != 95 {
		t.Fatalf("N=100 rank = %v, want 95", v)
	}
	twenty := make([]float64, 20)
	for i := range twenty {
		twenty[i] = float64(i + 1)
	}
	if v, _ := Percentile95(twenty); v != 19 {
		t.Fatalf("N=20 rank = %v, want 19 (top 5%% discarded)", v)
	}
	// 5% of 10 is not a whole sample. Nearest rank keeps the maximum.
	ten := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if v, _ := Percentile95(ten); v != 10 {
		t.Fatalf("N=10 rank = %v, want 10", v)
	}
	if v, _ := Percentile95([]float64{100, 10}); v != 100 {
		t.Fatalf("N=2 rank = %v, want 100", v)
	}
	// Input order must not matter, and the caller's slice stays put.
	raw := []float64{4, 1, 3, 2}
	if v, _ := Percentile95(raw); v != 4 {
		t.Fatalf("unsorted = %v, want 4", v)
	}
	if raw[0] != 4 {
		t.Fatal("Percentile95 modified the input")
	}
}

func TestSummarizeModes(t *testing.T) {
	// 18 quiet samples, one inbound spike, one outbound spike.
	// N=20 drops the single highest sample of each series.
	// separate: both 95ths are the quiet baseline.
	// greater: max(in, out) still has two spikes, so its 95th is the
	// smaller spike.
	// greater_separate: max of the two quiet 95ths, which is the baseline.
	samples := make([]RateSample, 0, 20)
	for i := 0; i < 18; i++ {
		samples = append(samples, RateSample{In: 10, Out: 10})
	}
	samples = append(samples, RateSample{In: 1000, Out: 10}, RateSample{In: 10, Out: 500})

	sep := Summarize(PercentileSeparate, samples)
	if sep.Single || sep.In95 != 10 || sep.Out95 != 10 || sep.Usage != 0 || sep.Samples != 20 {
		t.Fatalf("separate = %+v", sep)
	}
	gr := Summarize(PercentileGreater, samples)
	if !gr.Single || gr.Usage != 500 || gr.In95 != 10 || gr.Out95 != 10 {
		t.Fatalf("greater = %+v, want usage 500", gr)
	}
	gs := Summarize(PercentileGreaterSeparate, samples)
	if !gs.Single || gs.Usage != 10 || gs.In95 != 10 || gs.Out95 != 10 {
		t.Fatalf("greater_separate = %+v, want usage 10", gs)
	}
	if got := Summarize(PercentileGreater, nil); got.Samples != 0 || got.Single {
		t.Fatalf("empty = %+v", got)
	}
	// An unknown mode still reports both directions and does not invent
	// a single billable figure.
	unk := Summarize("nope", samples)
	if unk.Single || unk.In95 != 10 || unk.Out95 != 10 {
		t.Fatalf("unknown mode = %+v", unk)
	}
}
