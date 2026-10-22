package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/leakwatch"
	"github.com/GrandArcher/Packeteer/internal/linkout"
	"github.com/GrandArcher/Packeteer/internal/outside"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func f64(v float64) *float64 { return &v }

var pageNow = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func pageRef(member string, asn uint32, country string, provider uint32) herd.VantageRef {
	return herd.VantageRef{Member: member, Local: member == "local", ASN: asn, Identity: "pinned_key", Country: country, ProviderASN: provider, Method: "icmp"}
}

// fixtureHerd is a herd of this node and three peers on documentation ASNs.
type fixtureHerd struct{ HerdSource }

func (fixtureHerd) Overview(context.Context) (herd.Overview, error) {
	recent, old := 60.0, 7200.0
	lastOK := pageNow.Add(-2 * time.Minute)
	oldOK := pageNow.Add(-3 * time.Hour)
	return herd.Overview{Enabled: true, AsOf: pageNow, Vantages: 5, Countries: []string{"BR", "DE", "JP", "US"},
		Sharing: herd.Sharing{KeyID: "selfkey", Country: "US", Granularity: "origin_asn", Classes: []string{"measurements", "paths"},
			Sources: []string{"static", "vip"}, Discovery: "query_only", RetentionDays: 90, Serving: true},
		Members: []herd.MemberRow{
			{Member: "local", Local: true, ASN: 64501, Identity: "local", Source: "local", Countries: []string{"US"}, Vantages: 1, Records: 3, NewestAgeSeconds: &recent},
			{Member: "key-a-0123456789", ASN: 64502, Identity: "pinned_key", Source: "static", Countries: []string{"DE"}, Vantages: 1, Records: 3, NewestAgeSeconds: &recent, LastOK: &lastOK},
			{Member: "key-b-0123456789", ASN: 64503, Identity: "pinned_key", Source: "hub", Countries: []string{"JP"}, Vantages: 2, Records: 2, NewestAgeSeconds: &old, LastOK: &oldOK, LastError: "timeout", Stale: true},
			{Member: "key-c-0123456789", ASN: 64504, Identity: "pinned_key", Source: "static", Countries: []string{}, Stale: true},
		}}, nil
}

func (fixtureHerd) Events(context.Context, string) (herd.Events, error) {
	local := herd.EventVantage{VantageRef: pageRef("local", 64501, "US", 64520), LossPct: 40, RTTAvgMs: f64(90), AgeSeconds: 120, Degraded: true}
	a := herd.EventVantage{VantageRef: pageRef("key-a", 64502, "DE", 64520), LossPct: 25, RTTAvgMs: f64(120), AgeSeconds: 180, Degraded: true}
	b := herd.EventVantage{VantageRef: pageRef("key-b", 64503, "JP", 64521), LossPct: 30, RTTAvgMs: f64(200), AgeSeconds: 240, Degraded: true}
	c := herd.EventVantage{VantageRef: pageRef("key-c", 64504, "BR", 64521), LossPct: 1, RTTAvgMs: f64(80), AgeSeconds: 300}
	route := herd.EventVantage{VantageRef: pageRef("key-a", 64502, "DE", 64520), LossPct: 50, RTTAvgMs: f64(70), AgeSeconds: 120, Degraded: true}
	return herd.Events{Enabled: true, AsOf: pageNow, WindowSeconds: 900, LossPct: 5, Basis: herd.Basis, Targets: 3, Events: []herd.EventRow{
		{Target: herd.Target{Kind: "origin_asn", Value: "64510", Query: "origin_asn=64510"}, Reporting: 4, Degraded: 3,
			ByProvider: []herd.ProviderCount{{ProviderASN: 64520, Reporting: 3, Degraded: 2}, {ProviderASN: 64521, Reporting: 2, Degraded: 1}},
			Vantages:   []herd.EventVantage{local, a, b, c}},
		{Target: herd.Target{Kind: "prefix", Value: "198.51.100.0/24", Query: "prefix=198.51.100.0%2F24"}, Reporting: 2, Degraded: 1, Origins: []uint32{64512},
			ByProvider: []herd.ProviderCount{{ProviderASN: 64520, Reporting: 1, Degraded: 1}}, Vantages: []herd.EventVantage{route}},
	}}, nil
}

func (fixtureHerd) Mesh(context.Context, string) (herd.Mesh, error) {
	cell := func(loss, rtt float64, bad bool) *herd.MeshCell {
		return &herd.MeshCell{LossPct: loss, RTTAvgMs: f64(rtt), AgeSeconds: 60, Degraded: bad}
	}
	return herd.Mesh{Enabled: true, AsOf: pageNow, WindowSeconds: 3600, LossPct: 5,
		Targets: []herd.Target{{Kind: "origin_asn", Value: "64510"}, {Kind: "origin_asn", Value: "64511"}, {Kind: "prefix", Value: "198.51.100.0/24"}},
		Rows: []herd.MeshRow{
			{VantageRef: pageRef("local", 64501, "US", 64520), Cells: []*herd.MeshCell{cell(40, 90, true), cell(0, 10, false), nil}},
			{VantageRef: pageRef("key-a", 64502, "DE", 64520), Cells: []*herd.MeshCell{cell(25, 120, true), cell(0, 11, false), cell(50, 70, true)}},
			{VantageRef: pageRef("key-c", 64504, "BR", 64521), Cells: []*herd.MeshCell{cell(1, 80, false), nil, cell(0, 60, false)}},
		}}, nil
}

func (fixtureHerd) Map(context.Context, string) (herd.Map, error) {
	return herd.Map{Enabled: true, AsOf: pageNow, WindowSeconds: 900, LossPct: 5, Countries: []herd.Country{
		{Country: "DE", Members: 1, Vantages: 1, Measured: 3, Degraded: 2, WorstLossPct: f64(50), Condition: "degraded"},
		{Country: "JP", Members: 1, Vantages: 2, Measured: 2, Condition: "ok", WorstLossPct: f64(0)},
		{Country: "NZ", Members: 1, Vantages: 1, Condition: "no_data"},
	}}, nil
}

func (fixtureHerd) Monitor(context.Context, string) (herd.Monitor, error) {
	target := herd.Target{Kind: "origin_asn", Value: "64510", Query: "origin_asn=64510"}
	pt := func(min int, loss, rtt float64) herd.Point {
		return herd.Point{Time: pageNow.Add(time.Duration(min) * time.Minute), LossPct: f64(loss), RTTAvgMs: f64(rtt)}
	}
	return herd.Monitor{Enabled: true, AsOf: pageNow, WindowSeconds: 3600,
		Series: []herd.Series{
			{VantageRef: pageRef("local", 64501, "US", 64520), Target: target, Points: []herd.Point{pt(-30, 0, 20), pt(-20, 0, 20), pt(-10, 0, 20)}},
			{VantageRef: pageRef("key-a", 64502, "DE", 64520), Target: target, Points: []herd.Point{pt(-30, 0, 100), pt(-20, 2, 150), pt(-10, 30, 200)}},
		},
		Paths: []herd.PathTrack{
			{VantageRef: pageRef("local", 64501, "US", 64520), Target: target, Changes: []herd.PathChange{{Time: pageNow.Add(-30 * time.Minute), Paths: [][]uint32{{64520, 64510}}}}},
			{VantageRef: pageRef("key-a", 64502, "DE", 64520), Target: target, Changes: []herd.PathChange{
				{Time: pageNow.Add(-30 * time.Minute), Paths: [][]uint32{{64520, 64510}}},
				{Time: pageNow.Add(-10 * time.Minute), Paths: [][]uint32{{64521, 64510}}},
			}},
		}}, nil
}

func (fixtureHerd) Vantages(context.Context, string) (herd.VantageView, error) {
	fetched := pageNow.Add(-time.Minute)
	return herd.VantageView{Enabled: true, AsOf: pageNow, Vantages: []herd.Vantage{
		{VantageRef: pageRef("local", 64501, "US", 64520), Records: 3, Latest: herd.VantageRow{AgeSeconds: 120, LossPct: f64(0), RTTAvgMs: f64(20)}},
		{VantageRef: pageRef("key-a", 64502, "DE", 64520), Records: 3, Latest: herd.VantageRow{AgeSeconds: 180, LossPct: f64(30), RTTAvgMs: f64(200), FetchedAt: &fetched}},
	}}, nil
}

func (fixtureHerd) Search(context.Context, string) (herd.Search, error) {
	return herd.Search{Enabled: true, AsOf: pageNow, Days: 90, Hits: []herd.Hit{
		{Target: herd.Target{Kind: "origin_asn", Value: "64510"}, Members: 4, Vantages: 5, Records: 7, Providers: []uint32{64520, 64521}, FirstSeen: pageNow.Add(-48 * time.Hour), LastSeen: pageNow},
		{Target: herd.Target{Kind: "prefix", Value: "198.51.100.0/24"}, Members: 2, Vantages: 2, Records: 2, Providers: []uint32{64520}, Origins: []uint32{64512}, FirstSeen: pageNow.Add(-time.Hour), LastSeen: pageNow},
	}}, nil
}

// atlasStub stands in for the Atlas source, whose read needs a server.
type atlasStub struct{}

func (atlasStub) ID() string { return "atlas" }

func (atlasStub) Section(_ outside.Target, now time.Time) outside.Section {
	at, age := now.Add(-2*time.Minute), 120.0
	return outside.Section{ID: "atlas", Source: "RIPE Atlas (public data, not filtered by the selected target)", AsOf: &at, AgeSeconds: &age,
		Error: "/measurements/1001/latest/: 503 Service Unavailable", Columns: []string{"What", "Type or status", "Loss", "RTT avg (ms)", "Result time"},
		Rows: [][]string{{"mesh measurement 1001, probe 8", "ping", "100.0 %", "", "2026-10-18T11:58:00Z"}}}
}

func TestHerdPageRendering(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node is required in CI to run the herd page test")
		}
		t.Skip("node not installed")
	}
	s := newIXPServer(t)
	s.SetHerd(fixtureHerd{})
	st := leakwatch.Status{Sources: []leakwatch.SourceStatus{{Name: "ris", Type: "rislive"}}, Leaks: []leakwatch.Leak{}}
	s.SetHerdOutside(outside.NewSet(atlasStub{},
		outside.RIS{Status: func() leakwatch.Status { return st }},
		outside.RPKI{Validate: func(netip.Prefix, uint32) plugin.RPKIValidity { return plugin.RPKIValid }, Updated: func() time.Time { return time.Time{} }},
		outside.Links{Set: linkout.New(linkout.Config{Enabled: []string{"ripestat", "cloudflare_radar"}})}))

	dir := t.TempDir()
	for name, path := range map[string]string{
		"overview": "/api/herd/overview", "events": "/api/herd/events", "mesh": "/api/herd/mesh", "map": "/api/herd/map",
		"monitor": "/api/herd/monitor?origin_asn=64510", "vantages": "/api/herd/vantages?origin_asn=64510", "search": "/api/herd/search?origin_asn=64510",
		"outside": "/api/herd/outside?prefix=198.51.100.0/24&origin_asn=64510",
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s = %d %s", path, rec.Code, rec.Body)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".json"), rec.Body.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := exec.Command(node, "herd_page_test.js", dir).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ok") {
		t.Fatalf("herd page: %v\n%s", err, out)
	}
}
