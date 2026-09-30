package weights

import (
	"math"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func f(v float64) *float64 { return &v }

func TestOffByDefault(t *testing.T) {
	w, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if on, vol := w.ImprovementWeights(); on || vol {
		t.Fatalf("nil config: on=%v volume=%v", on, vol)
	}
}

func TestWeight(t *testing.T) {
	w, err := New(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if on, vol := w.ImprovementWeights(); !on || vol {
		t.Fatalf("defaults: on=%v volume=%v", on, vol)
	}
	if got := w.ImprovementWeight(plugin.WeightInput{Gain: 30, VolumeMbps: 900}); got != 30 {
		t.Fatalf("default weight = %v, want gain only", got)
	}
	w, err = New(&Config{Performance: f(0.5), Volume: f(2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, vol := w.ImprovementWeights(); !vol {
		t.Fatal("volume weight must ask for volumes")
	}
	if got := w.ImprovementWeight(plugin.WeightInput{Gain: 10, VolumeMbps: 100}); got != 205 {
		t.Fatalf("weight = %v", got)
	}
	if got := w.ImprovementWeight(plugin.WeightInput{Gain: 10, VolumeMbps: math.NaN()}); got != 5 {
		t.Fatalf("NaN volume weight = %v", got)
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct {
		c    Config
		want string
	}{
		{Config{Performance: f(-1)}, "performance -1"},
		{Config{Volume: f(math.NaN())}, "volume NaN"},
		{Config{Volume: f(2e6)}, "between 0 and"},
		{Config{Performance: f(0)}, "must be positive"},
	} {
		if _, err := New(&tc.c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want %q", tc.c, err, tc.want)
		}
	}
}
