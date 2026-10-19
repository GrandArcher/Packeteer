package sqlite

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func herdRec(member, id, prefix string, provider uint32, at time.Time, body string) plugin.HerdRecord {
	r := plugin.HerdRecord{Member: member, ID: id, Granularity: "route", ProviderASN: provider, OriginASN: 64500, Time: at, Body: []byte(body)}
	if prefix != "" {
		r.Prefix = netip.MustParsePrefix(prefix)
	} else {
		r.Granularity = "origin_asn"
	}
	return r
}

func ids(rs []plugin.HerdRecord) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHerdRecordsMatchAndPages(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db"))
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	recs := []plugin.HerdRecord{
		herdRec("", "a", "198.51.100.0/22", 64501, t0, "aaaa"),
		herdRec("", "b", "198.51.100.0/24", 64501, t0, "bbbb"),
		herdRec("", "c", "198.51.100.0/24", 64501, t0.Add(time.Minute), "cccc"),
		herdRec("", "d", "198.51.100.128/25", 64502, t0, "dddd"),
		herdRec("", "e", "203.0.113.0/24", 64501, t0, "eeee"),
		herdRec("", "f", "2001:db8::/32", 64501, t0, "ffff"),
		herdRec("", "g", "", 64501, t0, "gggg"),
		herdRec("peerkey", "h", "198.51.100.0/24", 64503, t0, "hhhh"),
	}
	n, err := s.PutHerdRecords(ctx, recs)
	if err != nil || n != len(recs) {
		t.Fatalf("put = %d, %v", n, err)
	}
	// The same member and id again changes nothing, whatever the body.
	again := recs[0]
	again.Body = []byte("changed")
	if n, err := s.PutHerdRecords(ctx, []plugin.HerdRecord{again}); err != nil || n != 0 {
		t.Fatalf("duplicate put = %d, %v", n, err)
	}

	q := func(p, match string) []string {
		got, err := s.HerdRecords(ctx, plugin.HerdQuery{Prefix: netip.MustParsePrefix(p), Match: match, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		return ids(got)
	}
	if got := q("198.51.100.0/24", "exact"); !eq(got, []string{"b", "c"}) {
		t.Errorf("exact = %v", got)
	}
	if got := q("198.51.100.0/24", "covering"); !eq(got, []string{"b", "c", "a"}) {
		t.Errorf("covering = %v", got)
	}
	if got := q("198.51.100.0/22", "covered"); !eq(got, []string{"b", "c", "a", "d"}) {
		t.Errorf("covered = %v", got)
	}
	if got := q("2001:db8::/32", "exact"); !eq(got, []string{"f"}) {
		t.Errorf("v6 exact = %v", got)
	}
	// An origin-ASN row has no prefix and never matches a prefix query.
	if got := q("0.0.0.0/0", "covered"); len(got) != 5 {
		t.Errorf("covered by the whole v4 space = %v, want the 5 own v4 rows", got)
	}

	// Pages follow the order (first address, last address, provider, time) and resume after the last row.
	var all []string
	var after *plugin.HerdRecord
	for {
		page, err := s.HerdRecords(ctx, plugin.HerdQuery{Member: "", Limit: 2, After: after})
		if err != nil {
			t.Fatal(err)
		}
		if len(page) == 0 {
			break
		}
		all = append(all, ids(page)...)
		after = &page[len(page)-1]
	}
	if want := []string{"g", "b", "c", "a", "d", "e", "f"}; !eq(all, want) {
		t.Errorf("paged order = %v, want %v", all, want)
	}
	if rs, _ := s.HerdRecords(ctx, plugin.HerdQuery{Member: "peerkey", Limit: 10}); !eq(ids(rs), []string{"h"}) || rs[0].Prefix.String() != "198.51.100.0/24" {
		t.Errorf("pulled rows = %+v", rs)
	}
	if rs, _ := s.HerdRecords(ctx, plugin.HerdQuery{AnyMember: true, ProviderASN: 64503, Limit: 10}); !eq(ids(rs), []string{"h"}) {
		t.Errorf("provider filter = %v", ids(rs))
	}
	if rs, _ := s.HerdRecords(ctx, plugin.HerdQuery{OriginASN: 64500, From: t0.Add(time.Minute), Limit: 10}); !eq(ids(rs), []string{"c"}) {
		t.Errorf("origin and from = %v", ids(rs))
	}
	rs, err := s.HerdRecords(ctx, plugin.HerdQuery{Member: "", Newest: true, Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 || rs[0].Time.Before(rs[1].Time) || rs[1].Time.Before(rs[2].Time) {
		t.Errorf("newest first = %+v", rs)
	}
	oldest, _ := s.HerdRecords(ctx, plugin.HerdQuery{Member: "", Limit: 100})
	maxT := oldest[0].Time
	for _, r := range oldest {
		if r.Time.After(maxT) {
			maxT = r.Time
		}
	}
	if !rs[0].Time.Equal(maxT) {
		t.Errorf("newest row is at %v, the latest stored is %v", rs[0].Time, maxT)
	}
}

func TestHerdRetentionAndTrim(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db"))
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var recs []plugin.HerdRecord
	for i := range 5 {
		recs = append(recs, herdRec("", "own"+string(rune('0'+i)), "198.51.100.0/24", 64501, t0.Add(time.Duration(i)*time.Hour), "0123456789"))
		recs = append(recs, herdRec("peer", "pull"+string(rune('0'+i)), "198.51.100.0/24", 64501, t0.Add(time.Duration(i)*time.Hour), "0123456789"))
	}
	if _, err := s.PutHerdRecords(ctx, recs); err != nil {
		t.Fatal(err)
	}
	st, err := s.HerdStats(ctx)
	if err != nil || st.LocalRecords != 5 || st.LocalBytes != 50 || st.PulledRecords != 5 || st.PulledBytes != 50 || st.PerMember["peer"] != 5 {
		t.Fatalf("stats = %+v, %v", st, err)
	}
	// Trimming the pulled class drops its oldest rows and leaves own rows.
	if n, err := s.TrimHerd(ctx, true, 25); err != nil || n != 3 {
		t.Fatalf("trim = %d, %v", n, err)
	}
	rs, _ := s.HerdRecords(ctx, plugin.HerdQuery{Member: "peer", Limit: 10})
	if !eq(ids(rs), []string{"pull3", "pull4"}) {
		t.Errorf("kept pulled rows = %v", ids(rs))
	}
	if st, _ := s.HerdStats(ctx); st.LocalRecords != 5 {
		t.Errorf("own rows after trimming pulled = %d, want 5", st.LocalRecords)
	}
	// Retention deletes rows of both classes older than the cutoff.
	if n, err := s.DeleteHerdBefore(ctx, t0.Add(3*time.Hour)); err != nil || n != 3 {
		t.Fatalf("delete before = %d, %v", n, err)
	}
	st, _ = s.HerdStats(ctx)
	if st.LocalRecords != 2 || st.PulledRecords != 2 {
		t.Errorf("stats after retention = %+v", st)
	}
}
