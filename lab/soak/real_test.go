package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/mrt"
)

func mrtRecord(t *testing.T, sub mrt.MRTSubTypeTableDumpv2, body mrt.Body) []byte {
	t.Helper()
	m, err := mrt.NewMRTMessage(1, mrt.TABLE_DUMPv2, sub, body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func seqPath(asns ...uint32) bgp.PathAttributeInterface {
	return bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, asns)})
}

// testDump is a TABLE_DUMP_V2 file of documentation prefixes and ASNs.
// Peer 0 is the full feed with five routes; peer 1 has one. Routes 198.51.100.0/24
// and 203.0.113.0/24 differ only in next hop, and the IPv6 route has the
// same attributes with an MP_REACH_NLRI, so all three are one set. 192.0.2.128/25
// carries a two-octet AS path and aggregator, as an old dump does.
func testDump(t *testing.T) []byte {
	t.Helper()
	var d bytes.Buffer
	d.Write(mrtRecord(t, mrt.PEER_INDEX_TABLE, mrt.NewPeerIndexTable("192.0.2.250", "", []*mrt.Peer{
		mrt.NewPeer("192.0.2.1", "192.0.2.1", 64496, true),
		mrt.NewPeer("192.0.2.2", "192.0.2.2", 64497, true),
	})))
	common := func(next bgp.PathAttributeInterface) []bgp.PathAttributeInterface {
		return []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0), seqPath(64496, 64500), next,
			bgp.NewPathAttributeCommunities([]uint32{64496<<16 | 100}),
		}
	}
	rib := func(sub mrt.MRTSubTypeTableDumpv2, seq uint32, p bgp.AddrPrefixInterface, e ...*mrt.RibEntry) {
		d.Write(mrtRecord(t, sub, mrt.NewRib(seq, p, e)))
	}
	rib(mrt.RIB_IPV4_UNICAST, 0, bgp.NewIPAddrPrefix(24, "198.51.100.0"),
		mrt.NewRibEntry(0, 1, 0, common(bgp.NewPathAttributeNextHop("192.0.2.1")), false),
		mrt.NewRibEntry(1, 1, 0, []bgp.PathAttributeInterface{bgp.NewPathAttributeOrigin(2), seqPath(64497)}, false))
	rib(mrt.RIB_IPV4_UNICAST, 1, bgp.NewIPAddrPrefix(24, "203.0.113.0"),
		mrt.NewRibEntry(0, 1, 0, common(bgp.NewPathAttributeNextHop("192.0.2.9")), false))
	rib(mrt.RIB_IPV4_UNICAST, 2, bgp.NewIPAddrPrefix(24, "192.0.2.0"),
		mrt.NewRibEntry(0, 1, 0, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(1), seqPath(64496, 64501),
			bgp.NewPathAttributeNextHop("192.0.2.1"), bgp.NewPathAttributeMultiExitDisc(50),
			bgp.NewPathAttributeLargeCommunities([]*bgp.LargeCommunity{bgp.NewLargeCommunity(64496, 1, 2)}),
		}, false))
	rib(mrt.RIB_IPV4_UNICAST, 3, bgp.NewIPAddrPrefix(25, "192.0.2.128"),
		mrt.NewRibEntry(0, 1, 0, []bgp.PathAttributeInterface{
			bgp.NewPathAttributeOrigin(0),
			bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAsPathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, []uint16{64496, 64502})}),
			bgp.NewPathAttributeNextHop("192.0.2.1"), bgp.NewPathAttributeAtomicAggregate(),
			bgp.NewPathAttributeAggregator(uint16(64503), "192.0.2.77"),
		}, false))
	rib(mrt.RIB_IPV6_UNICAST, 4, bgp.NewIPv6AddrPrefix(48, "2001:db8:1::"),
		mrt.NewRibEntry(0, 1, 0, common(bgp.NewPathAttributeMpReachNLRI("2001:db8::1", nil)), false))
	return d.Bytes()
}

func writeDump(t *testing.T, name string, b []byte, gz bool) string {
	t.Helper()
	if gz {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(b)
		_ = w.Close()
		b = buf.Bytes()
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func wantTestDump(t *testing.T, rt *realTable) {
	t.Helper()
	// IPv4 first, ordered by set, then prefix; the IPv6 route follows.
	want := []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.0/24", "192.0.2.128/25", "2001:db8:1::/48"}
	var got []string
	for _, e := range rt.entries {
		got = append(got, e.prefix.String())
	}
	if !slices.Equal(got, want) || rt.v4 != 4 {
		t.Fatalf("entries %v (v4 %d), want %v (v4 4)", got, rt.v4, want)
	}
	// Same attributes with a different next hop, or as IPv6, are one set.
	if s := []uint32{rt.entries[0].set, rt.entries[1].set, rt.entries[4].set}; s[0] != s[1] || s[1] != s[2] {
		t.Fatalf("sets %v, want one set for the three routes that differ only in next hop and family", s)
	}
	if rt.entries[2].set == rt.entries[0].set || rt.entries[3].set == rt.entries[2].set || len(rt.sets) != 3 {
		t.Fatalf("%d sets, entries %+v", len(rt.sets), rt.entries)
	}
	if rt.peers != 2 || rt.skipped != 0 {
		t.Fatalf("peers %d skipped %d", rt.peers, rt.skipped)
	}
}

// The loader picks the peer with the most routes, reads plain and gzip
// files, drops the next hop and MP_REACH_NLRI, and adds LOCAL_PREF.
func TestLoadRealPicksLargestPeerAndGroupsBySet(t *testing.T) {
	d := testDump(t)
	for _, gz := range []bool{false, true} {
		rt, err := loadReal(writeDump(t, "dump", d, gz))
		if err != nil {
			t.Fatal(err)
		}
		wantTestDump(t, rt)
	}
	rt, _ := loadReal(writeDump(t, "dump", d, false))
	for i, set := range rt.sets {
		var types []bgp.BGPAttrType
		for _, a := range set {
			types = append(types, a.GetType())
		}
		if slices.Contains(types, bgp.BGP_ATTR_TYPE_NEXT_HOP) || slices.Contains(types, bgp.BGP_ATTR_TYPE_MP_REACH_NLRI) ||
			!slices.Contains(types, bgp.BGP_ATTR_TYPE_LOCAL_PREF) || !slices.IsSorted(types) {
			t.Errorf("set %d has attribute types %v", i, types)
		}
	}
	info := rt.info()
	if *info != (TableInfo{Peers: 2, IPv4: 4, IPv6: 1, Sets: 3}) {
		t.Fatalf("info %+v", info)
	}
}

// A RouteViews dump is bzip2. The fixture is the test dump compressed with
// a bzip2 tool.
func TestLoadRealReadsBzip2(t *testing.T) {
	rt, err := loadReal("testdata/tiny-dump.mrt.bz2")
	if err != nil {
		t.Fatal(err)
	}
	wantTestDump(t, rt)
}

func TestLoadRealRejectsEmptyAndTruncated(t *testing.T) {
	if _, err := loadReal(writeDump(t, "empty", nil, false)); err == nil {
		t.Fatal("empty dump accepted")
	}
	d := testDump(t)
	if _, err := loadReal(writeDump(t, "cut", d[:len(d)-9], false)); err == nil {
		t.Fatal("truncated dump accepted")
	}
	gz := writeDump(t, "whole.gz", d, true)
	b, _ := os.ReadFile(gz)
	if _, err := loadReal(writeDump(t, "cut.gz", b[:len(b)-12], false)); err == nil {
		t.Fatal("truncated gzip download accepted")
	}
	if _, err := loadReal(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("missing file accepted")
	}
}

// A router plays the real table: one UPDATE per set and family, the next
// hop rewritten to a lab provider, the dump's attributes kept in the
// four-octet form the session negotiated, and no prefix named anywhere
// but on the wire.
func TestRouterPlaysRealTable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src, err := loadReal(writeDump(t, "dump", testDump(t), false))
	if err != nil {
		t.Fatal(err)
	}
	tbl := newRealTable(src)
	rt := newTestRouter(t, ctx, 1, tbl, newAdvertised())
	s := acceptFake(t, rt)
	go rt.serve(ctx, make(chan struct{}))
	eventually(t, "table and End-of-RIB", func() bool { return s.eors() == 2 })

	ann, _ := s.routes()
	if len(ann) != tbl.n {
		t.Fatalf("%d prefixes sent, want %d", len(ann), tbl.n)
	}
	for i, p := range ann {
		if p != tbl.prefix(i) {
			t.Fatalf("entry %d sent as %s, want %s", i, p, tbl.prefix(i))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.in) != 4 { // set 0 IPv4 (2 prefixes), set 1, set 2, set 0 IPv6
		t.Fatalf("%d UPDATEs, want 4", len(s.in))
	}
	seen := map[string]*bgp.BGPUpdate{}
	for _, m := range s.in {
		u := m.Body.(*bgp.BGPUpdate)
		if len(u.NLRI) > 0 {
			seen[nlriPrefix(u.NLRI[0]).String()] = u
		} else {
			seen["v6"] = u
		}
	}
	first := seen["198.51.100.0/24"]
	if first == nil || len(first.NLRI) != 2 {
		t.Fatalf("the two routes of one set are not one UPDATE: %+v", first)
	}
	attrs := func(u *bgp.BGPUpdate) (path []bgp.AsPathParamInterface, comms []uint32, med, lp uint32, nh string) {
		for _, a := range u.PathAttributes {
			switch v := a.(type) {
			case *bgp.PathAttributeAsPath:
				path = v.Value
			case *bgp.PathAttributeCommunities:
				comms = v.Value
			case *bgp.PathAttributeMultiExitDisc:
				med = v.Value
			case *bgp.PathAttributeLocalPref:
				lp = v.Value
			case *bgp.PathAttributeNextHop:
				nh = v.Value.String()
			case *bgp.PathAttributeMpReachNLRI:
				nh = v.Nexthop.String()
			}
		}
		return
	}
	path, comms, _, lp, nh := attrs(first)
	if len(path) != 1 || !slices.Equal(path[0].GetAS(), []uint32{64496, 64500}) || !slices.Equal(comms, []uint32{64496<<16 | 100}) || lp != 100 || nh != nextHopsV4[0] {
		t.Fatalf("set 0: path %v comms %v local_pref %d next hop %s", path, comms, lp, nh)
	}
	_, _, med, _, nh := attrs(seen["192.0.2.0/24"])
	if med != 50 || nh != nextHopsV4[1] {
		t.Fatalf("set 1: med %d next hop %s", med, nh)
	}
	path, _, _, _, _ = attrs(seen["192.0.2.128/25"])
	if _, ok := path[0].(*bgp.As4PathParam); !ok || !slices.Equal(path[0].GetAS(), []uint32{64496, 64502}) {
		t.Fatalf("a two-octet AS path was not rebuilt in four-octet form: %v", path)
	}
	var agg *bgp.PathAttributeAggregator
	for _, a := range seen["192.0.2.128/25"].PathAttributes {
		if v, ok := a.(*bgp.PathAttributeAggregator); ok {
			agg = v
		}
	}
	if agg == nil || agg.Value.AS != 64503 || agg.Value.Askind != reflect.Uint32 {
		t.Fatalf("aggregator %+v", agg)
	}
	if _, _, _, _, nh = attrs(seen["v6"]); nh != nextHopsV6[0] {
		t.Fatalf("IPv6 next hop %s, want %s", nh, nextHopsV6[0])
	}
}

// The router appends the next hop to the set's attributes; that must not
// write into the set the other sessions share.
func TestRealAttrsAreNotShared(t *testing.T) {
	src, err := loadReal(writeDump(t, "dump", testDump(t), false))
	if err != nil {
		t.Fatal(err)
	}
	a := append(src.attrs(0), bgp.NewPathAttributeNextHop("192.0.2.1"))
	b := append(src.attrs(0), bgp.NewPathAttributeNextHop("192.0.2.2"))
	if a[len(a)-1].(*bgp.PathAttributeNextHop).Value.String() != "192.0.2.1" || len(a) != len(src.sets[0])+1 {
		t.Fatalf("a second append changed the first: %v %v", a[len(a)-1], b[len(b)-1])
	}
}

// A route from Packeteer on a real-table run is a fault, and the fault
// names no prefix.
func TestRealRouteFaultNamesNoPrefix(t *testing.T) {
	src, err := loadReal(writeDump(t, "dump", testDump(t), false))
	if err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	why := routeFault(p, goodComms, newRealTable(src))
	if why == "" || strings.Contains(why, "198.51") {
		t.Fatalf("fault %q", why)
	}
}

func TestRealProfile(t *testing.T) {
	p, err := loadProfile("budgets.yaml", "realtable")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Real || p.Inject != 0 || p.Prefixes != 0 || p.FlowRate != 0 || p.Churn != 0 || p.StaticTargets != 0 {
		t.Fatalf("profile %+v", p)
	}
	// The table size comes from the dump, and the budgets follow the
	// paths: prefixes times sessions.
	if err := p.multiply(3); err != nil {
		t.Fatal(err)
	}
	p.useReal(&realTable{entries: make([]realEntry, 1_000_000)})
	if p.Prefixes != 1_000_000 || p.sessions() != 3 {
		t.Fatalf("prefixes %d sessions %d", p.Prefixes, p.sessions())
	}
	one, _ := loadProfile("budgets.yaml", "realtable")
	if one.Budgets.RSSPeakMBPerM == 0 || one.Budgets.LearnSecondsPerM == 0 {
		t.Fatal("the real profile checks neither learn time nor peak RSS")
	}
	wantBudget(t, "realtable x3", "peak", p.Budgets.RSSPeakMB, 3*one.Budgets.RSSPeakMBPerM)
	wantBudget(t, "realtable x3", "learn", p.Budgets.LearnSeconds, 3*one.Budgets.LearnSecondsPerM)

	for name, mut := range map[string]func(*Profile){
		"inject":  func(p *Profile) { p.Inject = 50 },
		"static":  func(p *Profile) { p.StaticTargets = 10 },
		"vip":     func(p *Profile) { p.VIPTargets = 10 },
		"outage":  func(p *Profile) { p.OutageTargets = 3 },
		"churn":   func(p *Profile) { p.Churn = 600 },
		"flow":    func(p *Profile) { p.FlowRate = 1000 },
		"prefixs": func(p *Profile) { p.Prefixes = 5000 },
	} {
		bad := one
		mut(&bad)
		if err := bad.validate(); err == nil || !strings.Contains(err.Error(), "observe only") {
			t.Errorf("%s: real profile accepted (%v)", name, err)
		}
	}
	bad := one
	if err := bad.multiply(5); err == nil {
		t.Error("5 sessions accepted")
	}
}

// config and run take a dump only with a real profile, and a real
// profile needs one.
func TestRunRequiresDumpExactlyForRealProfiles(t *testing.T) {
	for _, args := range [][]string{
		{"-budgets", "budgets.yaml", "-profile", "realtable", "-pid", "1"},
		{"-budgets", "budgets.yaml", "-profile", "smoke", "-mrt", "x", "-pid", "1"},
	} {
		if _, err := cmdRun(args); err == nil || !strings.Contains(err.Error(), "-mrt") {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// A real run is observe only: the generated config has the default mode,
// no announcer, no probe targets, and one neighbor per session.
func TestRealProfileGeneratesObserveConfig(t *testing.T) {
	p, err := loadProfile("budgets.yaml", "realtable")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.multiply(3); err != nil {
		t.Fatal(err)
	}
	cfg := packeteerConfig(p, ports{BGP: 11179, Flow: 12055, HTTP: 18081}, "/var/lib/packeteer")
	for _, bad := range []string{"mode: inject", "announcer:", "type: static", "type: vip", "type: outage"} {
		if strings.Contains(cfg, bad) {
			t.Errorf("config has %q", bad)
		}
	}
	if !strings.Contains(cfg, "mode: observe\n") || strings.Count(cfg, "    - address: 127.0.0.") != 3 {
		t.Fatalf("config:\n%s", cfg)
	}
}

// The workflow is manual only, and nothing else runs the profile.
func TestRealTableIsOptIn(t *testing.T) {
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	wf := read("../../.github/workflows/realtable.yml")
	for _, trigger := range []string{"pull_request", "schedule:", "push:", "workflow_run"} {
		if strings.Contains(wf, trigger) {
			t.Errorf("realtable.yml runs on %s", trigger)
		}
	}
	if !strings.Contains(wf, "workflow_dispatch:") || !strings.Contains(wf, "bash lab/realtable.sh") {
		t.Error("realtable.yml must be a workflow_dispatch job that runs lab/realtable.sh")
	}
	entries, _ := os.ReadDir("../../.github/workflows")
	for _, e := range entries {
		if e.Name() != "realtable.yml" && strings.Contains(read("../../.github/workflows/"+e.Name()), "realtable") {
			t.Errorf("%s runs the real-table profile", e.Name())
		}
	}
}

// The script refuses a dump host outside the public archives and a session
// count outside 1 to 4 before it downloads or starts anything.
func TestRealtableScriptRefusesBadInput(t *testing.T) {
	for _, tc := range []struct {
		env  string
		args []string
		want string
	}{
		{"REALTABLE_URL=https://example.com/bview.gz", []string{"img"}, "REALTABLE_URL must be on"},
		{"REALTABLE_URL=http://data.ris.ripe.net/rrc00/latest-bview.gz", []string{"img"}, "REALTABLE_URL must be on"},
		{"REALTABLE_URL=https://data.ris.ripe.net/rrc00/latest-bview.gz", []string{"img", "5"}, "MULTIPLY must be 1 to 4"},
	} {
		cmd := exec.Command("bash", append([]string{"../realtable.sh"}, tc.args...)...)
		cmd.Env = append(os.Environ(), tc.env)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 || !strings.Contains(string(out), tc.want) {
			t.Errorf("%s %v: %v %s", tc.env, tc.args, err, out)
		}
	}
}
