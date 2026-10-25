package commit

import (
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Reordering (#224) is free by default and costs reorder_weight per
// percent when set, on the same performance score the planner uses.
func TestReorderWeight(t *testing.T) {
	base := plugin.PathStats{LossPct: 1, RTTAvg: 30 * time.Millisecond, Jitter: 2 * time.Millisecond}
	reordered := base
	reordered.ReorderPct = 20
	def := build(t, "")
	if def.Score(reordered) != def.Score(base) {
		t.Fatal("default scorer charged for reordering")
	}
	s := build(t, "reorder_weight: 2")
	if got := s.Score(reordered) - s.Score(base); got != 40 {
		t.Fatalf("20%% reordering costs %v, want 40", got)
	}
	c, _ := plugin.ConfigFromYAML("reorder_weight: -1")
	if _, err := New(c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), "reorder_weight -1 must not be negative") {
		t.Fatalf("negative reorder_weight: %v", err)
	}
	c, _ = plugin.ConfigFromYAML("loss_weight: 0\nrtt_weight: 0\njitter_weight: 0\nreorder_weight: 1")
	if _, err := New(c, plugin.Env{}); err != nil {
		t.Fatalf("reorder-only weights refused: %v", err)
	}
}
