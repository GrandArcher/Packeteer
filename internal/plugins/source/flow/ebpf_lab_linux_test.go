//go:build linux

package flow

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath/labtest"
)

// sampler is a router that exports one sFlow sample per rate packets.
type sampler struct{ seen, rate int }

// observe counts a packet and returns the datagram the router exports for
// it, or nil when the packet is not sampled.
func (m *sampler) observe(src, dst netip.Addr, ipLen uint32) []byte {
	m.seen++
	if m.seen%m.rate != 0 {
		return nil
	}
	return sflowDatagram(flowSampleBody(uint32(m.rate), sampledV4Record(src, dst, ipLen)))
}

// A router that samples 1 packet in 1000 exports a sample only when its
// packet counter reaches 1000, so a short burst never reaches the sFlow
// listener. The eBPF collector on the same source counts every packet (#229).
func TestEBPFSeesBurstThatSampledFlowMisses(t *testing.T) {
	labtest.RequireRoot(t)
	const (
		burst   = 40
		payload = 200
		rate    = 1000
		ipBytes = 20 + 8 + payload
	)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	labtest.StaticNeighbor(t, "192.0.2.77", "02:00:00:00:00:77", dev)

	s := mustSource(t, "listen: 127.0.0.1:0\nebpf: {interface: "+dev+"}\nwindow: 1m\nmin_bytes: 1\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stop, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		if err := s.Stop(stop); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	if s.ebpfRun == nil {
		t.Fatal("eBPF collector did not load; the lab kernel must support TCX (Linux 6.6)")
	}
	exporter, err := net.Dial("udp", s.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer exporter.Close()
	conn, err := net.Dial("udp", "192.0.2.77:9")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	router := &sampler{rate: rate}
	exported := 0
	for range burst {
		if _, err := conn.Write(make([]byte, payload)); err != nil {
			t.Fatal(err)
		}
		if dg := router.observe(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.77"), ipBytes); dg != nil {
			exported++
			if _, err := exporter.Write(dg); err != nil {
				t.Fatal(err)
			}
		}
	}
	if exported != 0 {
		t.Fatalf("a 1:%d sampler exported %d samples of a %d-packet burst", rate, exported, burst)
	}

	waitFor(t, "burst counted", func() bool { return volumeOf(t, s, "192.0.2.0/24") >= burst*ipBytes })
	if got := volumeOf(t, s, "192.0.2.0/24"); got != burst*ipBytes {
		t.Fatalf("counted %d bytes, want %d (%d packets of %d IP bytes)", got, burst*ipBytes, burst, ipBytes)
	}
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "192.0.2.0/24" || ts[0].Weight != burst*ipBytes || ts[0].Host.String() != "192.0.2.77" {
		t.Fatalf("targets = %+v", ts)
	}

	// The sampler is not blind: a long enough flow does reach it.
	for range rate - burst {
		if dg := router.observe(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.77"), ipBytes); dg != nil {
			exported++
		}
	}
	if exported != 1 {
		t.Fatalf("a 1:%d sampler exported %d samples of %d packets, want 1", rate, exported, rate)
	}
}
