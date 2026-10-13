package history

import (
	"net/netip"
	"testing"
)

func ids(rows []SearchImprovement) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Prefix+"|"+r.Provider+"|"+r.Start.Format("01-02T15")+"|"+r.Relation)
	}
	return out
}

func TestSearchByPrefix(t *testing.T) {
	// pfxA is 192.0.2.0/24: the exact search matches it and does not
	// reach pfxB or pfxC.
	got := Search(seed(), SearchQuery{Prefix: netip.MustParsePrefix("192.0.2.0/24"), From: from, To: to, Limit: 10})
	if got.ImprovementsTotal != 2 || len(got.Improvements) != 2 {
		t.Fatalf("improvements = %v", ids(got.Improvements))
	}
	// Newest first: improvement 2 (day 2) before improvement 1 (day 1).
	if !got.Improvements[0].Start.After(got.Improvements[1].Start) {
		t.Errorf("order = %v", ids(got.Improvements))
	}
	for _, r := range got.Improvements {
		if r.Relation != "exact" || r.Prefix != "192.0.2.0/24" {
			t.Errorf("row = %+v", r)
		}
	}
	if got.RollupsTotal != 1 || len(got.Rollups) != 1 {
		t.Fatalf("rollups = %+v", got.Rollups)
	}
	r := got.Rollups[0]
	// Day 1 has two providers: 10+10 probes, 2 failed, 18 measured with
	// loss 80 and RTT 700 summed. The bucket before the range is not in it.
	if r.Prefix != "192.0.2.0/24" || r.Days != 1 || r.Probes != 20 || r.Failed != 2 || r.LastDay != "2026-09-01" ||
		len(r.Providers) != 2 || r.Providers[0] != "transit-a" || r.OriginASN != 64500 {
		t.Errorf("rollup = %+v", r)
	}
	if r.LossPct == nil || *r.LossPct != 4.444 || r.RTTMs == nil || *r.RTTMs != 38.889 {
		t.Errorf("averages = %v %v", r.LossPct, r.RTTMs)
	}
}

func TestSearchCoveringAndMoreSpecific(t *testing.T) {
	covering := Search(seed(), SearchQuery{Prefix: netip.MustParsePrefix("192.0.2.128/25"), From: from, To: to, Limit: 10})
	if covering.ImprovementsTotal != 2 || covering.Improvements[0].Relation != "covering" {
		t.Errorf("covering search = %v", ids(covering.Improvements))
	}
	inside := Search(seed(), SearchQuery{Prefix: netip.MustParsePrefix("192.0.0.0/8"), From: from, To: to, Limit: 10})
	if inside.ImprovementsTotal != 2 || inside.Improvements[0].Relation != "more-specific" {
		t.Errorf("more-specific search = %v", ids(inside.Improvements))
	}
	none := Search(seed(), SearchQuery{Prefix: netip.MustParsePrefix("192.0.3.0/24"), From: from, To: to, Limit: 10})
	if none.ImprovementsTotal != 0 || none.RollupsTotal != 0 || none.Improvements == nil || none.Rollups == nil {
		t.Errorf("unrelated search = %+v", none)
	}
}

func TestSearchByASN(t *testing.T) {
	got := Search(seed(), SearchQuery{ASNs: []uint32{64501}, From: from, To: to, Limit: 10})
	// AS64501 originates pfxB only. Improvement 0 on pfxB has no origin
	// recorded, so only improvement 3 and pfxB's day-2 rollup match.
	if got.ImprovementsTotal != 1 {
		t.Fatalf("improvements = %v", ids(got.Improvements))
	}
	for _, r := range got.Improvements {
		if r.OriginASN != 64501 || r.Prefix != "198.51.100.0/24" {
			t.Errorf("row = %+v", r)
		}
		if r.Relation != "" {
			t.Errorf("an ASN match has no prefix relation: %+v", r)
		}
	}
	if got.RollupsTotal != 1 || got.Rollups[0].Prefix != "198.51.100.0/24" {
		t.Errorf("rollups = %+v", got.Rollups)
	}
}

func TestSearchCapsAndCountsEveryMatch(t *testing.T) {
	got := Search(seed(), SearchQuery{ASNs: []uint32{64500}, From: from, To: to, Limit: 1})
	if got.ImprovementsTotal != 3 || len(got.Improvements) != 1 {
		t.Fatalf("improvements %d of %d", len(got.Improvements), got.ImprovementsTotal)
	}
	// The kept row is the newest: improvement 4 on day 2.
	if got.Improvements[0].Prefix != "203.0.113.0/24" {
		t.Errorf("kept = %+v", got.Improvements[0])
	}
	if got.RollupsTotal != 2 || len(got.Rollups) != 1 || got.Rollups[0].LastDay != "2026-09-02" {
		t.Errorf("rollups %d of %d, first %+v", len(got.Rollups), got.RollupsTotal, got.Rollups)
	}
}
