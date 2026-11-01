//go:build linux

package flow

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath/labtest"
)

// A router that samples 1 packet in 1000 exports a sample only when its
// packet counter reaches 1000. A short burst below that never reaches an
// exporter; the eBPF collector counts every packet (#229).
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

	s := mustSource(t, "ebpf: {interface: "+dev+"}\nwindow: 1m\nmin_bytes: 1\n")
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

	conn, err := net.Dial("udp", "192.0.2.77:9")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sampled := 0
	for n := 1; n <= burst; n++ {
		if _, err := conn.Write(make([]byte, payload)); err != nil {
			t.Fatal(err)
		}
		if n%rate == 0 {
			sampled++
		}
	}
	if sampled != 0 {
		t.Fatalf("a 1:%d sampler exported %d samples of a %d-packet burst", rate, sampled, burst)
	}

	waitFor(t, "burst counted", func() bool { return volumeOf(t, s, "192.0.2.0/24") >= burst*ipBytes })
	if got := volumeOf(t, s, "192.0.2.0/24"); got != burst*ipBytes {
		t.Fatalf("counted %d bytes, want %d (%d packets of %d IP bytes)", got, burst*ipBytes, burst, ipBytes)
	}
	ts := targetsOf(t, s)
	if len(ts) != 1 || ts[0].Prefix.String() != "192.0.2.0/24" || ts[0].Weight != burst*ipBytes || ts[0].Host.String() != "192.0.2.77" {
		t.Fatalf("targets = %+v", ts)
	}
}
