package flow

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// v5proto is a NetFlow v5 export with one record per (dst, proto, octets).
func v5proto(recs ...struct {
	dst    string
	proto  uint8
	octets uint32
}) []byte {
	b := make([]byte, 24+48*len(recs))
	binary.BigEndian.PutUint16(b[0:], 5)
	binary.BigEndian.PutUint16(b[2:], uint16(len(recs)))
	for i, r := range recs {
		o := 24 + 48*i
		copy(b[o+4:o+8], netip.MustParseAddr(r.dst).AsSlice())
		binary.BigEndian.PutUint32(b[o+20:], r.octets)
		b[o+38] = r.proto
	}
	return b
}

func countersOf(t *testing.T, s *Source) map[string]uint64 {
	t.Helper()
	cs, err := s.FlowCounters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]uint64{}
	for _, c := range cs {
		out[plugin.TrafficKey{Prefix: c.Prefix, Protocol: c.Protocol}.String()] = c.Bytes
	}
	return out
}

// Counters are per destination prefix and IP protocol, cumulative across
// the window, and mapped through the RIB like targets.
func TestFlowCountersByProtocol(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:2055\nwindow: 10s\n")
	t0 := time.Unix(1_700_000_000, 0)
	pin(s, t0)
	s.SetPrefixLookup(func(a netip.Addr) (netip.Prefix, bool) {
		p := netip.MustParsePrefix("198.51.100.0/24")
		return p, p.Contains(a)
	})
	type rec = struct {
		dst    string
		proto  uint8
		octets uint32
	}
	exp := netip.MustParseAddr("192.0.2.8")
	s.ingest(t0, exp, v5proto(rec{"198.51.100.10", 17, 1000}, rec{"198.51.100.20", 17, 500}, rec{"198.51.100.10", 6, 300},
		rec{"203.0.113.9", 17, 200}, rec{"10.0.0.1", 17, 9999}))
	s.ingest(t0.Add(time.Minute), exp, v5proto(rec{"198.51.100.30", 17, 100}))
	// sFlow sampled IPv6 carries protocol 6 in the test builder.
	s.ingest(t0, exp, buildSFlowV6(10, netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1"), 100))
	pin(s, t0.Add(time.Minute))
	got := countersOf(t, s)
	want := map[string]uint64{
		"198.51.100.0/24 udp": 1600, // still counting after the 10s window
		"198.51.100.0/24 tcp": 300,
		"203.0.113.0/24 udp":  200,
		"2001:db8:2::/48 tcp": 1000,
	}
	if len(got) != len(want) {
		t.Fatalf("counters = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("counters = %v, want %v", got, want)
		}
	}
	// Idle keys are forgotten after an hour.
	pin(s, t0.Add(2*time.Hour))
	if got := countersOf(t, s); len(got) != 0 {
		t.Fatalf("idle counters kept: %v", got)
	}
}

func TestFlowCountersCap(t *testing.T) {
	c := newCounters(2)
	t0 := time.Unix(1_700_000_000, 0)
	c.add(t0, netip.MustParsePrefix("198.51.100.0/24"), 17, 10)
	c.add(t0, netip.MustParsePrefix("198.51.100.0/24"), 6, 10)
	c.add(t0, netip.MustParsePrefix("203.0.113.0/24"), 17, 10)
	if n := len(c.snapshot(t0)); n != 2 {
		t.Fatalf("cap 2 holds %d keys", n)
	}
	// Once the old keys are idle, a new one is counted.
	c.add(t0.Add(2*time.Hour), netip.MustParsePrefix("203.0.113.0/24"), 17, 10)
	if s := c.snapshot(t0.Add(2 * time.Hour)); len(s) != 1 || s[0].Prefix.String() != "203.0.113.0/24" {
		t.Fatalf("after idle = %+v", s)
	}
}
