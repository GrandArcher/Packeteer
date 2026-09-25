package weighted

import (
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, y string) (plugin.Scorer, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(y)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Scorers.New(TypeName, c, plugin.Env{})
}

func TestScore(t *testing.T) {
	s, err := build(t, "")
	if err != nil {
		t.Fatal(err)
	}
	got := s.Score(plugin.PathStats{LossPct: 2, RTTAvg: 30 * time.Millisecond, Jitter: 4 * time.Millisecond})
	if got != 2*100+30+2 {
		t.Fatalf("score = %v", got)
	}
	slow := s.Score(plugin.PathStats{RTTAvg: 100 * time.Millisecond})
	if !(s.Score(plugin.PathStats{LossPct: 2, RTTAvg: 10 * time.Millisecond}) > slow) {
		t.Fatal("2% loss must be worse than 100ms latency")
	}
	c, _ := build(t, "loss_weight: 0\nrtt_weight: 2\njitter_weight: 0")
	if c.Score(plugin.PathStats{LossPct: 50, RTTAvg: 10 * time.Millisecond}) != 20 {
		t.Fatal("custom weights ignored")
	}
}

func TestConfigErrors(t *testing.T) {
	for y, want := range map[string]string{
		"loss_weight: -1": "must not be negative",
		"loss_weight: 0\nrtt_weight: 0\njitter_weight: 0": "at least one weight",
		"bogus: 1": "field bogus not found",
	} {
		if _, err := build(t, y); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", y, err)
		}
	}
}
