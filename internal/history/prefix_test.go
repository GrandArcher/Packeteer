package history

import (
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func bucketFailed(p netip.Prefix, day time.Time) plugin.ProbeBucket {
	return plugin.ProbeBucket{Day: day, Prefix: p, Provider: "transit-a", Probes: 5, Failed: 5}
}

func TestBuildPrefix(t *testing.T) {
	got := BuildPrefix(seed(), pfxA, Query{From: from, To: to, Now: now})
	if got.Prefix != "192.0.2.0/24" {
		t.Fatalf("prefix = %s", got.Prefix)
	}
	// Only pfxA's two day-1 rollups. The pfxB and pfxC rollups, and pfxA's
	// day before the range, are not in it.
	if len(got.Days) != 2 {
		t.Fatalf("days = %+v", got.Days)
	}
	a, b := got.Days[0], got.Days[1]
	if a.Day != "2026-09-01" || a.Provider != "transit-a" || a.Probes != 10 || a.Failed != 2 {
		t.Errorf("transit-a day = %+v", a)
	}
	// Averages are over the measured probes: 80/8, 400/8, 16/8.
	if *a.LossPct != 10 || *a.RTTMs != 50 || *a.JitterMs != 2 {
		t.Errorf("transit-a averages = %v %v %v", *a.LossPct, *a.RTTMs, *a.JitterMs)
	}
	if b.Provider != "transit-b" || *b.LossPct != 0 || *b.RTTMs != 30 {
		t.Errorf("transit-b day = %+v", b)
	}
	// Improvements 1 and 2 are pfxA's; newest first. 2 is open and, with
	// no cause stored, reads as performance.
	if len(got.Improvements) != 2 || got.Improvements[0].Start.Before(got.Improvements[1].Start) {
		t.Fatalf("improvements = %+v", got.Improvements)
	}
	open, ended := got.Improvements[0], got.Improvements[1]
	if !open.End.IsZero() || open.Cause != "performance" || *open.BeforeLossPct != 20 || *open.AfterRTTMs != 40 {
		t.Errorf("open = %+v", open)
	}
	if ended.EndReason != "ttl expired" || ended.Hours != 2 {
		t.Errorf("ended = %+v", ended)
	}
	for _, im := range got.Improvements {
		if im.Prefix != "192.0.2.0/24" {
			t.Errorf("improvement for %s in pfxA's history", im.Prefix)
		}
	}
}

func TestBuildPrefixIsExactAndEmpty(t *testing.T) {
	// A covering prefix shares no rollups or improvements with its
	// more-specific.
	got := BuildPrefix(seed(), netip.MustParsePrefix("192.0.0.0/16"), Query{From: from, To: to, Now: now})
	if len(got.Days) != 0 || len(got.Improvements) != 0 {
		t.Fatalf("covering prefix history = %+v", got)
	}
	// A day with only failed probes has no averages.
	h := seed()
	h.Buckets = append(h.Buckets, bucketFailed(pfxC, from))
	day := BuildPrefix(h, pfxC, Query{From: from, To: to, Now: now}).Days[0]
	if day.Day != "2026-09-01" || day.Failed != 5 || day.LossPct != nil || day.RTTMs != nil {
		t.Errorf("failed-only day = %+v", day)
	}
	// An improvement that ended before the range is left out.
	for _, im := range BuildPrefix(seed(), pfxC, Query{From: from, To: to, Now: now}).Improvements {
		if im.Start.Before(from.Add(-24 * time.Hour)) {
			t.Errorf("improvement outside range: %+v", im)
		}
	}
}

// The gate list the recorder stored with an improvement comes back on the
// prefix history, and a record without one (or with damaged JSON) has none
// (#201).
func TestBuildPrefixCarriesExplain(t *testing.T) {
	h := seed()
	good := `{"outcome":"moved","gates":[{"gate":"thresholds","status":"pass"}]}`
	for i := range h.Improvements {
		if h.Improvements[i].Prefix != pfxA {
			continue
		}
		h.Improvements[i].Explain = good
		break
	}
	h.Improvements = append(h.Improvements, plugin.ImprovementRecord{ID: "bad", Prefix: pfxA, Provider: "transit-b", Native: "transit-a",
		Start: from.Add(time.Hour), Explain: "{not json"})
	got := BuildPrefix(h, pfxA, Query{From: from, To: to, Now: now}).Improvements
	var withExplain, without int
	for _, im := range got {
		switch string(im.Explain) {
		case good:
			withExplain++
		case "":
			without++
		default:
			t.Fatalf("explain = %q", im.Explain)
		}
	}
	if withExplain != 1 || without != len(got)-1 {
		t.Fatalf("explain on %d of %d improvements", withExplain, len(got))
	}
	// Reports share the row type and never carry the gate list.
	rep := improvementRow(h.Improvements[0], 1)
	if rep.Explain != nil {
		t.Fatalf("report row has an explain: %s", rep.Explain)
	}
}
