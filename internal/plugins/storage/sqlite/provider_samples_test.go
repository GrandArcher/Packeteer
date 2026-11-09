package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestProviderSamplesRoundTripReplacePrune(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db")+"\nretention: 48h")
	now := time.Date(2026, 3, 17, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)

	slot := now.Add(-10 * time.Minute)
	first := plugin.ProviderSample{Provider: "lab-a", Slot: slot, Probes: 4, Failed: 1, Measured: 3, LossSum: 30, RTTSumMs: 90, JitterSum: 6}
	old := plugin.ProviderSample{Provider: "lab-a", Slot: now.Add(-72 * time.Hour), Probes: 1, Measured: 1, RTTSumMs: 5}
	other := plugin.ProviderSample{Provider: "lab-b", Slot: slot, Probes: 2, Measured: 2, RTTSumMs: 20}
	if err := s.PutProviderSamples(ctx, []plugin.ProviderSample{first, old, other}); err != nil {
		t.Fatal(err)
	}
	// The same provider and slot replaces: values are absolute, not added.
	replaced := first
	replaced.Probes, replaced.Measured, replaced.RTTSumMs = 8, 7, 140
	if err := s.PutProviderSamples(ctx, []plugin.ProviderSample{replaced}); err != nil {
		t.Fatal(err)
	}

	got, err := s.ProviderSamples(ctx, now.Add(-100*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("rows before prune = %+v", got)
	}
	if err := s.prune(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = s.ProviderSamples(ctx, now.Add(-100*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Provider != "lab-a" || got[1].Provider != "lab-b" {
		t.Fatalf("rows after prune = %+v", got)
	}
	if got[0].Probes != 8 || got[0].Measured != 7 || got[0].RTTSumMs != 140 || got[0].LossSum != 30 || got[0].Failed != 1 || got[0].JitterSum != 6 || !got[0].Slot.Equal(slot) {
		t.Fatalf("replaced row = %+v", got[0])
	}
	// [from, to) excludes a slot at to.
	got, err = s.ProviderSamples(ctx, now.Add(-time.Hour), slot)
	if err != nil || len(got) != 0 {
		t.Fatalf("slot at the end bound: %+v %v", got, err)
	}
	if err := s.PutProviderSamples(ctx, []plugin.ProviderSample{{Slot: slot}}); err == nil {
		t.Fatal("a sample without a provider was accepted")
	}
}
