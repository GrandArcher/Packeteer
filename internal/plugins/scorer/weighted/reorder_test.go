package weighted

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Reordering (#224) is free by default and costs reorder_weight per
// percent when set; it alone can keep the scorer valid.
func TestReorderWeight(t *testing.T) {
	def, err := build(t, "")
	if err != nil {
		t.Fatal(err)
	}
	base := plugin.PathStats{LossPct: 1, RTTAvg: 30 * time.Millisecond, Jitter: 2 * time.Millisecond}
	reordered := base
	reordered.ReorderPct = 20
	if def.Score(reordered) != def.Score(base) {
		t.Fatal("default scorer charged for reordering")
	}
	s, err := build(t, "reorder_weight: 2")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Score(reordered) - s.Score(base); got != 40 {
		t.Fatalf("20%% reordering costs %v, want 40", got)
	}
	only, err := build(t, "loss_weight: 0\nrtt_weight: 0\njitter_weight: 0\nreorder_weight: 1")
	if err != nil {
		t.Fatal(err)
	}
	if only.Score(reordered) != 20 || only.Score(base) != 0 {
		t.Fatalf("reorder-only scores %v and %v", only.Score(reordered), only.Score(base))
	}
	if _, err := build(t, "reorder_weight: -1"); err == nil {
		t.Fatal("negative reorder_weight accepted")
	}
}
