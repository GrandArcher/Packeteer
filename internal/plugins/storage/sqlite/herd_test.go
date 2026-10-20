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

// scanHerdStats counts herd_records the slow way, to compare with HerdStats.
func scanHerdStats(t *testing.T, s *Store) plugin.HerdStats {
	t.Helper()
	out := plugin.HerdStats{PerMember: map[string]int{}}
	rows, err := s.db.Query(`SELECT member, COUNT(*), SUM(length(body)) FROM herd_records GROUP BY member`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		var n int
		var b int64
		if err := rows.Scan(&m, &n, &b); err != nil {
			t.Fatal(err)
		}
		if m == "" {
			out.LocalRecords, out.LocalBytes = n, b
			continue
		}
		out.PulledRecords += n
		out.PulledBytes += b
		out.PerMember[m] = n
	}
	return out
}

func wantHerdStats(t *testing.T, s *Store, step string) plugin.HerdStats {
	t.Helper()
	got, err := s.HerdStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := scanHerdStats(t, s)
	if got.LocalRecords != want.LocalRecords || got.LocalBytes != want.LocalBytes ||
		got.PulledRecords != want.PulledRecords || got.PulledBytes != want.PulledBytes ||
		len(got.PerMember) != len(want.PerMember) {
		t.Fatalf("%s: stats = %+v, a scan of the rows gives %+v", step, got, want)
	}
	for m, n := range want.PerMember {
		if got.PerMember[m] != n {
			t.Fatalf("%s: member %s has %d rows in stats, %d stored", step, m, got.PerMember[m], n)
		}
	}
	return got
}

func TestHerdStatsMatchRowsAcrossStoreTrimAndPrune(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db"))
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	recs := []plugin.HerdRecord{
		herdRec("", "o1", "198.51.100.0/24", 64501, t0, "aaaa"),
		herdRec("", "o2", "203.0.113.0/24", 64501, t0.Add(time.Hour), "bbbbbb"),
		herdRec("m1", "p1", "198.51.100.0/24", 64501, t0, "cc"),
		herdRec("m1", "p2", "203.0.113.0/24", 64501, t0.Add(2*time.Hour), "dddddddd"),
		herdRec("m2", "p3", "192.0.2.0/24", 64501, t0.Add(3*time.Hour), "eeeee"),
	}
	if n, err := s.PutHerdRecords(ctx, recs); err != nil || n != 5 {
		t.Fatalf("put = %d, %v", n, err)
	}
	st := wantHerdStats(t, s, "after put")
	if st.LocalRecords != 2 || st.LocalBytes != 10 || st.PulledRecords != 3 || st.PulledBytes != 15 || st.PerMember["m1"] != 2 || st.PerMember["m2"] != 1 {
		t.Fatalf("stats after put = %+v", st)
	}

	// A row that is already stored is ignored and must not be counted.
	dup := herdRec("m1", "p1", "198.51.100.0/24", 64501, t0, "ignored-body")
	if n, err := s.PutHerdRecords(ctx, []plugin.HerdRecord{dup}); err != nil || n != 0 {
		t.Fatalf("duplicate put = %d, %v", n, err)
	}
	wantHerdStats(t, s, "after duplicate")

	// A failed batch rolls back its inserts and their counts.
	bad := []plugin.HerdRecord{herdRec("m3", "p9", "192.0.2.0/24", 64501, t0, "zzz"), {ID: "", Body: []byte("x")}}
	if _, err := s.PutHerdRecords(ctx, bad); err == nil {
		t.Fatal("batch with an empty id was stored")
	}
	st = wantHerdStats(t, s, "after rolled-back batch")
	if _, ok := st.PerMember["m3"]; ok {
		t.Errorf("rolled-back member m3 is in stats: %+v", st)
	}

	// Trim the pulled class to 8 bytes: p1 (2) and p2 (8) go, oldest first
	// by time, then p3 (5) stays only if it fits.
	if n, err := s.TrimHerd(ctx, true, 8); err != nil || n != 2 {
		t.Fatalf("trim = %d, %v", n, err)
	}
	st = wantHerdStats(t, s, "after trim")
	if st.PulledRecords != 1 || st.PulledBytes != 5 || st.LocalRecords != 2 {
		t.Errorf("stats after trim = %+v", st)
	}
	if _, ok := st.PerMember["m1"]; ok {
		t.Errorf("member m1 has no rows left but is in stats: %+v", st)
	}
	// Trimming the own class leaves the pulled class alone.
	if n, err := s.TrimHerd(ctx, false, 6); err != nil || n != 1 {
		t.Fatalf("trim own = %d, %v", n, err)
	}
	st = wantHerdStats(t, s, "after own trim")
	if st.LocalRecords != 1 || st.LocalBytes != 6 || st.PulledRecords != 1 {
		t.Errorf("stats after own trim = %+v", st)
	}
	// A class that fits drops nothing.
	if n, err := s.TrimHerd(ctx, true, 1<<20); err != nil || n != 0 {
		t.Fatalf("trim under budget = %d, %v", n, err)
	}

	// Retention empties both classes.
	if n, err := s.DeleteHerdBefore(ctx, t0.Add(24*time.Hour)); err != nil || n != 2 {
		t.Fatalf("delete before = %d, %v", n, err)
	}
	st = wantHerdStats(t, s, "after prune")
	if st.LocalRecords != 0 || st.LocalBytes != 0 || st.PulledRecords != 0 || st.PulledBytes != 0 || len(st.PerMember) != 0 {
		t.Errorf("stats after prune = %+v", st)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM herd_stats`).Scan(&n); err != nil || n != 0 {
		t.Errorf("herd_stats rows after everything is deleted = %d, %v", n, err)
	}
}

// Stats and trimming read herd_stats, not the rows: a changed stats row is
// what they report.
func TestHerdStatsAndTrimReadTheStatsTable(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, "path: "+filepath.Join(t.TempDir(), "p.db"))
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.PutHerdRecords(ctx, []plugin.HerdRecord{
		herdRec("m1", "p1", "198.51.100.0/24", 64501, t0, "abcd"),
		herdRec("m1", "p2", "198.51.100.0/24", 64501, t0.Add(time.Hour), "abcd"),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE herd_stats SET records = 77, bytes = 5000 WHERE member = 'm1'`); err != nil {
		t.Fatal(err)
	}
	st, err := s.HerdStats(ctx)
	if err != nil || st.PulledRecords != 77 || st.PulledBytes != 5000 {
		t.Fatalf("stats = %+v, %v; want the stats table values", st, err)
	}
	if n, err := s.TrimHerd(ctx, true, 5000); err != nil || n != 0 {
		t.Fatalf("trim under the stats total dropped %d rows, %v", n, err)
	}
}

// A database written before herd_stats existed is counted once on open and
// kept right afterwards.
func TestHerdStatsBackfillOnUpgrade(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "p.db")
	s := newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := s.PutHerdRecords(ctx, []plugin.HerdRecord{
		herdRec("", "o1", "198.51.100.0/24", 64501, t0, "aaaa"),
		herdRec("m1", "p1", "198.51.100.0/24", 64501, t0, "bbbbbb"),
		herdRec("m1", "p2", "203.0.113.0/24", 64501, t0, "cc"),
	}); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP TRIGGER herd_stats_insert`, `DROP TRIGGER herd_stats_delete`, `DROP TABLE herd_stats`} {
		if _, err := s.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	s = newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	st := wantHerdStats(t, s, "after upgrade")
	if st.LocalRecords != 1 || st.LocalBytes != 4 || st.PulledRecords != 2 || st.PulledBytes != 8 || st.PerMember["m1"] != 2 {
		t.Fatalf("stats after upgrade = %+v", st)
	}
	if _, err := s.PutHerdRecords(ctx, []plugin.HerdRecord{herdRec("m1", "p3", "192.0.2.0/24", 64501, t0, "ddd")}); err != nil {
		t.Fatal(err)
	}
	wantHerdStats(t, s, "insert after upgrade")

	// A second open must not count the rows again.
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	s = newStore(t, "path: "+path)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(ctx)
	wantHerdStats(t, s, "after reopen")
}
