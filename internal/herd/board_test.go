package herd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fleet is a store holding this node's records and those of three peers, all
// on documentation ASNs and prefixes.
type fleet struct {
	t     *testing.T
	store plugin.HerdStore
	peers map[string]uint32
	n     int
}

const (
	selfASN = 64501
	peerA   = "key-a" // AS64502, DE
	peerB   = "key-b" // AS64503, JP
	peerC   = "key-c" // AS64504, BR
)

func newFleet(t *testing.T) *fleet {
	return &fleet{t: t, store: testStore(t), peers: map[string]uint32{peerA: 64502, peerB: 64503, peerC: 64504}}
}

func (f *fleet) board() Board {
	return Board{Store: f.store, Self: selfASN, Peers: f.peers, Retention: 90 * 24 * time.Hour, Now: t0}
}

// put stores one record as member ("" is this node) with the given loss. A
// positive rtt gives one reply of that RTT; loss is set directly because the
// views read the stored summary.
func (f *fleet) put(member, country string, provider, origin uint32, prefix string, age time.Duration, loss, rtt float64, paths ...[]uint32) {
	f.t.Helper()
	f.n++
	at := t0.Add(-age)
	r := Record{Schema: Schema, ID: fmt.Sprintf("r%04d", f.n), Granularity: "origin_asn", OriginASN: origin, ProviderASN: provider,
		Vantage: country, Method: "icmp", Time: at, Sent: 10, Routes: 1, LossPct: &loss, RTTAvgMs: &rtt}
	if prefix != "" {
		r.Granularity, r.Prefix, r.Routes = "route", prefix, 0
	}
	if len(paths) == 1 && prefix != "" {
		r.ASPath = paths[0]
	} else {
		r.ASPaths = paths
	}
	var body []byte
	if member == "" {
		body, _ = json.Marshal(r)
	} else {
		body, _ = json.Marshal(pulledBody{Record: r, FetchedAt: t0, GeneratedAt: t0})
	}
	hr := plugin.HerdRecord{Member: member, ID: r.ID, Granularity: r.Granularity, OriginASN: origin, ProviderASN: provider, Time: at, Body: body}
	if prefix != "" {
		hr.Prefix = netip.MustParsePrefix(prefix)
	}
	if _, err := f.store.PutHerdRecords(context.Background(), []plugin.HerdRecord{hr}); err != nil {
		f.t.Fatal(err)
	}
}

// seed fills the fleet: AS64510 is degraded for three of four members, two of
// them through provider AS64520; AS64511 is fine everywhere; one route is
// measured by two members at route level.
func (f *fleet) seed() {
	min := time.Minute
	p1, p2 := []uint32{64520, 64530, 64510}, []uint32{64521, 64510}
	f.put("", "US", 64520, 64510, "", 2*min, 40, 90, p1)
	f.put("", "US", 64520, 64510, "", 20*min, 0, 20, p1) // older, superseded
	f.put(peerA, "DE", 64520, 64510, "", 3*min, 25, 120, p1)
	f.put(peerB, "JP", 64521, 64510, "", 4*min, 30, 200, p2)
	f.put(peerB, "JP", 64520, 64510, "", 4*min, 0, 15, p1)
	f.put(peerC, "BR", 64521, 64510, "", 5*min, 1, 80, p2)
	f.put("", "US", 64520, 64511, "", min, 0, 10)
	f.put(peerA, "DE", 64520, 64511, "", min, 0, 11)
	f.put(peerA, "DE", 64520, 64512, "198.51.100.0/24", 2*min, 50, 70, []uint32{64520, 64512})
	f.put(peerC, "BR", 64521, 64512, "198.51.100.0/24", 3*min, 0, 60, []uint32{64521, 64512})
	// Old record from a removed member: never shown.
	f.put("key-gone", "FR", 64520, 64510, "", min, 90, 10)
}

func TestEventsCountMembersNotRecords(t *testing.T) {
	f := newFleet(t)
	f.seed()
	ev, err := f.board().Events(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if ev.Basis != Basis || ev.LossPct != 5 || ev.WindowSeconds != 900 {
		t.Fatalf("header = %+v", ev)
	}
	if len(ev.Events) != 2 {
		t.Fatalf("events = %+v, want AS64510 and the 198.51.100.0/24 route", ev.Events)
	}
	e := ev.Events[0]
	if e.Kind != "origin_asn" || e.Value != "64510" {
		t.Fatalf("first event = %+v", e.Target)
	}
	// Local, A, B, and C measure AS64510. B and C went through two providers;
	// each member counts once. The removed member is not counted.
	if e.Reporting != 4 || e.Degraded != 3 {
		t.Errorf("AS64510 = %d of %d, want 3 of 4", e.Degraded, e.Reporting)
	}
	want := []ProviderCount{{64520, 3, 2}, {64521, 2, 1}}
	if fmt.Sprint(e.ByProvider) != fmt.Sprint(want) {
		t.Errorf("by provider = %+v, want %+v", e.ByProvider, want)
	}
	// The local 20-minute-old round is outside the window; the newest wins.
	if len(e.Vantages) != 5 || !e.Vantages[0].Local || e.Vantages[0].LossPct != 40 || !e.Vantages[0].Degraded {
		t.Errorf("vantages = %+v", e.Vantages)
	}
	r := ev.Events[1]
	if len(r.Origins) != 1 || r.Origins[0] != 64512 {
		t.Errorf("origins = %v, want the one origin members report", r.Origins)
	}
	if r.Kind != "prefix" || r.Value != "198.51.100.0/24" || r.Reporting != 2 || r.Degraded != 1 {
		t.Errorf("route event = %+v", r)
	}
	if ev.Targets != 3 {
		t.Errorf("targets measured = %d, want 3", ev.Targets)
	}

	strict, err := f.board().Events(context.Background(), "loss=35")
	if err != nil || len(strict.Events) != 2 || strict.Events[0].Degraded != 1 || strict.Events[1].Degraded != 1 {
		t.Errorf("loss=35: %+v, %v", strict.Events, err)
	}
	wide, _ := f.board().Events(context.Background(), "window=1h")
	if wide.Events[0].Reporting != 4 {
		t.Errorf("window=1h reporting = %d", wide.Events[0].Reporting)
	}
}

func TestEventsSameASNCountsOnce(t *testing.T) {
	f := newFleet(t)
	f.peers["key-a2"] = 64502 // a second node of the same operator
	f.put(peerA, "DE", 64520, 64510, "", time.Minute, 30, 100)
	f.put("key-a2", "DE", 64520, 64510, "", time.Minute, 30, 100)
	ev, err := f.board().Events(context.Background(), "")
	if err != nil || len(ev.Events) != 1 || ev.Events[0].Reporting != 1 || ev.Events[0].Degraded != 1 {
		t.Fatalf("two nodes of one ASN: %+v, %v", ev.Events, err)
	}
	if len(ev.Events[0].Vantages) != 2 {
		t.Errorf("both nodes stay visible as rows: %+v", ev.Events[0].Vantages)
	}
}

func TestBoardQueryIsStrict(t *testing.T) {
	f := newFleet(t)
	b := f.board()
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func() error
		raw  string
		want string
	}{
		{"events unknown", func() error { _, err := b.Events(ctx, "bogus=1"); return err }, "", `unknown parameter "bogus"`},
		{"events repeated", func() error { _, err := b.Events(ctx, "loss=5&loss=6"); return err }, "", "repeated"},
		{"events window", func() error { _, err := b.Events(ctx, "window=1s"); return err }, "", "window"},
		{"events window long", func() error { _, err := b.Events(ctx, "window=48h"); return err }, "", "window"},
		{"events loss", func() error { _, err := b.Events(ctx, "loss=0"); return err }, "", "loss"},
		{"mesh loss", func() error { _, err := b.Mesh(ctx, "loss=101"); return err }, "", "loss"},
		{"monitor needs target", func() error { _, err := b.Monitor(ctx, "window=1h"); return err }, "", "name an origin_asn or a prefix"},
		{"monitor prefix", func() error { _, err := b.Monitor(ctx, "prefix=198.51.100.7/24"); return err }, "", "prefix"},
		{"search needs filter", func() error { _, err := b.Search(ctx, ""); return err }, "", "name an origin_asn"},
		{"search window", func() error { _, err := b.Search(ctx, "origin_asn=64510&window=1h"); return err }, "", "unknown parameter"},
		{"map asn", func() error { _, err := b.Map(ctx, "origin_asn=64510"); return err }, "", "unknown parameter"},
	} {
		err := tc.call()
		var qe QueryError
		if err == nil || !strings.Contains(err.Error(), tc.want) || !errors.As(err, &qe) {
			t.Errorf("%s: err = %v, want a QueryError containing %q", tc.name, err, tc.want)
		}
	}
}

func TestMeshKeepsEveryVantageNumber(t *testing.T) {
	f := newFleet(t)
	f.seed()
	m, err := f.board().Mesh(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Targets) != 3 || m.Targets[0].Value != "64510" {
		t.Fatalf("targets = %+v, want AS64510 (4 members) first", m.Targets)
	}
	// Local, A, B through two providers, and C: five vantages.
	refs := map[string]int{}
	for _, r := range m.Rows {
		refs[fmt.Sprintf("%s/%s/%d", r.Member, r.Country, r.ProviderASN)]++
	}
	if len(m.Rows) != 5 || !m.Rows[0].Local {
		t.Fatalf("rows = %v", refs)
	}
	var local MeshRow
	for _, r := range m.Rows {
		if r.Local && r.ProviderASN == 64520 {
			local = r
		}
	}
	c := local.Cells[0]
	if c == nil || c.LossPct != 40 || !c.Degraded || c.RTTAvgMs == nil || *c.RTTAvgMs != 90 {
		t.Errorf("local cell for AS64510 = %+v", c)
	}
	idx := map[string]int{}
	for i, tg := range m.Targets {
		idx[tg.Value] = i
	}
	if c := local.Cells[idx["198.51.100.0/24"]]; c != nil {
		t.Errorf("local never measured the route, cell = %+v", c)
	}
	for _, r := range m.Rows {
		if len(r.Cells) != len(m.Targets) {
			t.Fatalf("row %+v has %d cells", r.VantageRef, len(r.Cells))
		}
	}
}

func TestMeshIsBounded(t *testing.T) {
	f := newFleet(t)
	for i := range maxMeshCols + 5 {
		f.put("", "US", 64520, uint32(64600+i), "", time.Minute, 0, 10)
	}
	for i := range maxMeshRows + 5 {
		f.put(peerA, "DE", uint32(65000+i), 64510, "", time.Minute, 0, 10)
	}
	m, err := f.board().Mesh(context.Background(), "")
	if err != nil || len(m.Targets) != maxMeshCols || len(m.Rows) != maxMeshRows || !m.Truncated {
		t.Fatalf("targets %d rows %d truncated %v, err %v", len(m.Targets), len(m.Rows), m.Truncated, err)
	}
}

func TestMonitorSeriesAndPathChanges(t *testing.T) {
	f := newFleet(t)
	p1, p2 := []uint32{64520, 64510}, []uint32{64521, 64510}
	for i, loss := range []float64{0, 2, 30} {
		age := time.Duration(30-10*i) * time.Minute
		path := p1
		if i == 2 {
			path = p2
		}
		f.put(peerA, "DE", 64520, 64510, "", age, loss, 100+float64(i)*50, path)
		f.put("", "US", 64520, 64510, "", age, 0, 20, p1)
	}
	f.put(peerA, "DE", 64520, 64599, "", time.Minute, 99, 1) // another target
	m, err := f.board().Monitor(context.Background(), "origin_asn=64510&window=1h")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Series) != 2 || !m.Series[0].Local {
		t.Fatalf("series = %+v", m.Series)
	}
	a := m.Series[1]
	if a.Member != peerA || len(a.Points) != 3 || a.Points[0].Time.After(a.Points[2].Time) {
		t.Fatalf("A's series = %+v", a)
	}
	if *a.Points[2].LossPct != 30 || *a.Points[2].RTTAvgMs != 200 || *a.Points[0].RTTAvgMs != 100 {
		t.Errorf("A's points = %+v", a.Points)
	}
	if len(m.Paths) != 2 {
		t.Fatalf("paths = %+v", m.Paths)
	}
	var track PathTrack
	for _, p := range m.Paths {
		if p.Member == peerA {
			track = p
		}
		if p.Local && len(p.Changes) != 1 {
			t.Errorf("the local path never changed, changes = %+v", p.Changes)
		}
	}
	if len(track.Changes) != 2 || track.Changes[0].Paths[0][0] != 64520 || track.Changes[1].Paths[0][0] != 64521 {
		t.Errorf("A's path changes = %+v", track.Changes)
	}
}

func TestMonitorByPrefixKeepsRoutesApart(t *testing.T) {
	f := newFleet(t)
	f.put(peerA, "DE", 64520, 64512, "198.51.100.0/22", time.Minute, 0, 10, []uint32{64520, 64512})
	f.put(peerA, "DE", 64520, 64512, "198.51.100.0/24", time.Minute, 0, 10, []uint32{64520, 64512})
	f.put(peerA, "DE", 64520, 64512, "", time.Minute, 0, 10, []uint32{64520, 64512})
	m, err := f.board().Monitor(context.Background(), "prefix=198.51.100.0/22&match=covered&window=1h")
	if err != nil || len(m.Series) != 2 {
		t.Fatalf("covered series = %+v, %v", m.Series, err)
	}
	if m.Series[0].Target.Value != "198.51.100.0/22" || m.Series[1].Target.Value != "198.51.100.0/24" {
		t.Errorf("targets = %+v", m.Series)
	}
}

func TestMonitorSeriesIsBounded(t *testing.T) {
	f := newFleet(t)
	for i := range maxSeriesPts + 20 {
		f.put("", "US", 64520, 64510, "", time.Duration(i)*time.Second, 0, 10)
	}
	m, err := f.board().Monitor(context.Background(), "origin_asn=64510&window=1h")
	if err != nil || len(m.Series) != 1 || len(m.Series[0].Points) != maxSeriesPts || !m.Truncated {
		t.Fatalf("points %d, truncated %v, err %v", len(m.Series[0].Points), m.Truncated, err)
	}
	if !m.Series[0].Points[maxSeriesPts-1].Time.Equal(t0.Add(0)) {
		t.Errorf("the newest round was dropped: %v", m.Series[0].Points[maxSeriesPts-1].Time)
	}
}

func TestMapByDeclaredCountry(t *testing.T) {
	f := newFleet(t)
	f.seed()
	f.put(peerC, "BR", 64521, 64513, "", 3*time.Hour, 0, 10) // BR also has an old record only for this target
	f.put("key-d", "NZ", 64520, 64510, "", 3*time.Hour, 0, 10)
	f.peers["key-d"] = 64505
	m, err := f.board().Map(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Country{}
	for _, c := range m.Countries {
		got[c.Country] = c
	}
	if len(got) != 5 {
		t.Fatalf("countries = %+v", m.Countries)
	}
	if c := got["US"]; c.Condition != "degraded" || c.Degraded != 1 || c.Measured != 2 || c.WorstLossPct == nil || *c.WorstLossPct != 40 || c.Members != 1 {
		t.Errorf("US = %+v", c)
	}
	if c := got["DE"]; c.Condition != "degraded" || c.Degraded != 2 || c.Measured != 3 {
		t.Errorf("DE = %+v", c)
	}
	if c := got["BR"]; c.Condition != "ok" || c.Degraded != 0 || c.Measured != 2 {
		t.Errorf("BR = %+v, want only the in-window targets measured", c)
	}
	if c := got["NZ"]; c.Condition != "no_data" || c.Vantages != 1 || c.Measured != 0 || c.WorstLossPct != nil {
		t.Errorf("NZ = %+v, want known but silent", c)
	}
	if _, ok := got["FR"]; ok {
		t.Error("a removed member's country is shown")
	}
	for i := 1; i < len(m.Countries); i++ {
		if m.Countries[i-1].Country >= m.Countries[i].Country {
			t.Errorf("countries not sorted: %+v", m.Countries)
		}
	}
}

func TestSearchWithinRetention(t *testing.T) {
	f := newFleet(t)
	f.seed()
	f.put(peerC, "BR", 64521, 64510, "", 60*24*time.Hour, 0, 10) // 60 days old, inside 90
	f.put(peerC, "BR", 64521, 64510, "", 100*24*time.Hour, 0, 10)
	ctx := context.Background()

	s, err := f.board().Search(ctx, "origin_asn=64510")
	if err != nil || len(s.Hits) != 1 {
		t.Fatalf("origin search = %+v, %v", s.Hits, err)
	}
	h := s.Hits[0]
	if h.Members != 4 || h.Vantages != 5 || h.Records != 7 || len(h.Providers) != 2 || h.FirstSeen.After(t0.Add(-59*24*time.Hour)) {
		t.Errorf("hit = %+v", h)
	}
	if s.Days != 90 {
		t.Errorf("days = %d", s.Days)
	}

	for raw, want := range map[string][]string{
		"provider_asn=64521":                   {"64510", "198.51.100.0/24"},
		"prefix=198.51.100.0/22&match=covered": {"198.51.100.0/24"},
		"prefix=198.51.100.0/24&match=exact":   {"198.51.100.0/24"},
		"member=" + peerA:                      {"64510", "64511", "198.51.100.0/24"},
		"member=64504":                         {"64510", "198.51.100.0/24"},
		"member=64504&origin_asn=64510":        {"64510"},
		"member=nobody":                        nil,
		"origin_asn=64999":                     nil,
		"prefix=203.0.113.0/24&match=exact":    nil,
	} {
		s, err := f.board().Search(ctx, raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		var got []string
		for _, h := range s.Hits {
			got = append(got, h.Value)
		}
		if len(got) != len(want) {
			t.Errorf("%s: hits = %v, want %v", raw, got, want)
			continue
		}
		for _, w := range want {
			found := false
			for _, g := range got {
				found = found || g == w
			}
			if !found {
				t.Errorf("%s: hits = %v, want %v", raw, got, want)
			}
		}
	}
}

func TestOverviewListsMembersAndFreshness(t *testing.T) {
	f := newFleet(t)
	f.seed()
	st := NodeStatus{Enabled: true, KeyID: "self-key", Country: "US", Granularity: "origin_asn", Classes: []string{"measurements"},
		Sources: []string{"static"}, Discovery: "query_only", RetentionDays: 90, Serving: true,
		Peers: []PeerStatus{
			{KeyID: peerC, ASN: 64504, Source: "static", LastOK: t0.Add(-2 * time.Minute)},
			{KeyID: peerA, ASN: 64502, Source: "hub", LastOK: t0.Add(-3 * time.Hour), LastError: "timeout"},
			{KeyID: "key-new", ASN: 64509, Source: "static"},
		}}
	o, err := f.board().Overview(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if o.Sharing.KeyID != "self-key" || !o.Sharing.Serving || o.Sharing.Granularity != "origin_asn" || o.Sharing.RetentionDays != 90 {
		t.Errorf("sharing = %+v", o.Sharing)
	}
	if len(o.Members) != 4 || !o.Members[0].Local || o.Members[0].Identity != "local" || o.Members[0].ASN != selfASN {
		t.Fatalf("members = %+v", o.Members)
	}
	by := map[string]MemberRow{}
	for _, m := range o.Members {
		by[m.Member] = m
		if m.Verified {
			t.Errorf("%s is shown verified: RPKI identity is not implemented", m.Member)
		}
	}
	if l := by["local"]; l.Stale || l.Records != 3 || l.Vantages != 1 || l.Countries[0] != "US" {
		t.Errorf("local = %+v", l)
	}
	if c := by[peerC]; c.Stale || c.Source != "static" || c.Records != 2 || c.Identity != "pinned_key" || c.LastOK == nil {
		t.Errorf("C = %+v", c)
	}
	if a := by[peerA]; !a.Stale || a.LastError != "timeout" || a.Source != "hub" || a.Vantages != 1 {
		t.Errorf("A = %+v", a)
	}
	if n := by["key-new"]; !n.Stale || n.NewestAgeSeconds != nil || n.Records != 0 || n.LastOK != nil {
		t.Errorf("never pulled = %+v", n)
	}
	if o.Vantages != 5 || len(o.Countries) != 4 {
		t.Errorf("vantages %d countries %v", o.Vantages, o.Countries)
	}
	if by["key-gone"].Member != "" {
		t.Error("a removed member is listed")
	}
}

// queryStore records the last query so a test can see what the board asked
// the store for.
type queryStore struct {
	plugin.HerdStore
	last plugin.HerdQuery
}

func (q *queryStore) HerdRecords(ctx context.Context, hq plugin.HerdQuery) ([]plugin.HerdRecord, error) {
	q.last = hq
	return q.HerdStore.HerdRecords(ctx, hq)
}

func TestSearchSelectsAKeyIDInTheStore(t *testing.T) {
	f := newFleet(t)
	f.seed()
	qs := &queryStore{HerdStore: f.store}
	b := f.board()
	b.Store = qs

	for raw, want := range map[string]plugin.HerdQuery{
		"member=" + peerA: {Member: peerA},
		"member=local":    {},
		"member=64504":    {AnyMember: true},
	} {
		if _, err := b.Search(context.Background(), raw); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if qs.last.Member != want.Member || qs.last.AnyMember != want.AnyMember {
			t.Errorf("%s: store query member=%q any=%v, want member=%q any=%v", raw, qs.last.Member, qs.last.AnyMember, want.Member, want.AnyMember)
		}
	}
}
