package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/mrt"

	"github.com/GrandArcher/Packeteer/lab/soak/shape"
)

func attrs(path ...uint32) []bgp.PathAttributeInterface {
	return []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{bgp.NewAs4PathParam(bgp.BGP_ASPATH_ATTR_TYPE_SEQ, path)}),
		bgp.NewPathAttributeMpReachNLRI("192.0.2.1", nil),
	}
}

func record(t *testing.T, sub mrt.MRTSubTypeTableDumpv2, body mrt.Body) []byte {
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

// Peer 0 is a full feed of three routes, peer 1 a stub with one: only the
// full feed is counted, and the output holds counts and no prefix.
func TestRunPoolsFullFeedsAndWritesCountsOnly(t *testing.T) {
	var dump bytes.Buffer
	dump.Write(record(t, mrt.PEER_INDEX_TABLE, mrt.NewPeerIndexTable("192.0.2.250", "", []*mrt.Peer{
		mrt.NewPeer("192.0.2.1", "192.0.2.1", 64496, true),
		mrt.NewPeer("192.0.2.2", "192.0.2.2", 64497, true),
	})))
	rib := func(sub mrt.MRTSubTypeTableDumpv2, seq uint32, p bgp.AddrPrefixInterface, e ...*mrt.RibEntry) {
		dump.Write(record(t, sub, mrt.NewRib(seq, p, e)))
	}
	rib(mrt.RIB_IPV4_UNICAST, 0, bgp.NewIPAddrPrefix(24, "198.51.100.0"),
		mrt.NewRibEntry(0, 1, 0, attrs(64496, 64500), false), mrt.NewRibEntry(1, 1, 0, attrs(64497), false))
	rib(mrt.RIB_IPV4_UNICAST, 1, bgp.NewIPAddrPrefix(23, "203.0.112.0"),
		mrt.NewRibEntry(0, 1, 0, attrs(64496, 64500), false))
	rib(mrt.RIB_IPV6_UNICAST, 2, bgp.NewIPv6AddrPrefix(48, "2001:db8:1::"),
		mrt.NewRibEntry(0, 1, 0, attrs(64496, 64501), false))
	dir := t.TempDir()
	path := filepath.Join(dir, "dump.gz")
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(dump.Bytes())
	_ = w.Close()
	if err := os.WriteFile(path, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run(path, "test dump", "2026-01-02", &out); err != nil {
		t.Fatal(err)
	}
	s, err := shape.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if s.Peers != 1 || s.Routes != 3 || s.IPv4.Length[24] != 1 || s.IPv4.Length[23] != 1 ||
		s.IPv6.Length[48] != 1 || s.ASPathLength[2] != 3 || s.AttributeSets != 2 {
		t.Fatalf("shape %+v", s)
	}
	for _, leak := range []string{"198.51", "203.0.", "2001:db8", "6449", "6450"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("output contains %q", leak)
		}
	}
}

func TestRunRejectsEmptyDump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(path, "x", "2026-01-02", &bytes.Buffer{}); err == nil {
		t.Fatal("empty dump accepted")
	}
}
