package flow

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func startSource(t *testing.T, y string) (*Source, *net.UDPConn) {
	t.Helper()
	s := mustSource(t, y)
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		stop, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		if err := s.Stop(stop); err != nil {
			t.Error(err)
		}
	})
	dst, err := net.ResolveUDPAddr("udp", s.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return s, conn
}

func windowBytes(t *testing.T, s *Source) uint64 {
	t.Helper()
	vs, err := s.Volumes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var n uint64
	for _, v := range vs {
		n += v.Bytes
	}
	return n
}

func TestWorkersConfig(t *testing.T) {
	if s := mustSource(t, "listen: ':2055'\n"); s.workers != defaultWorkers {
		t.Fatalf("default workers = %d", s.workers)
	}
	if s := mustSource(t, "listen: ':2055'\nworkers: 16\n"); s.workers != 16 {
		t.Fatalf("workers = %d", s.workers)
	}
	for _, y := range []string{"workers: 17", "workers: -1"} {
		_, err := build("listen: ':2055'\n" + y)
		if err == nil || !strings.Contains(err.Error(), "workers") {
			t.Errorf("%q: err = %v", y, err)
		}
	}
}

// Template first, then data from the same exporter: the reader decodes in
// arrival order, so no worker can see a data set before its template.
func TestWorkersKeepTemplateOrder(t *testing.T) {
	s, conn := startSource(t, "listen: 127.0.0.1:0\nworkers: 16\n")
	tmpl := tmplSetIPFIX(256, [][2]uint16{{ieDstV4, 4}, {ieInBytes, 4}})
	if _, err := conn.Write(buildIPFIX(7, tmpl)); err != nil {
		t.Fatal(err)
	}
	// Bursts stay under the loopback socket buffer, which holds a few
	// hundred small datagrams.
	const packets, burst = 1000, 50
	for i := range packets {
		dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		if _, err := conn.Write(buildIPFIX(7, dataSet(256, v4rec(dst, 1000)))); err != nil {
			t.Fatal(err)
		}
		if (i+1)%burst == 0 {
			want := uint64(i+1) * 1000
			waitFor(t, "burst counted", func() bool { return windowBytes(t, s) == want })
		}
	}
	if n := s.Truncated()["workers"]; n != 0 {
		t.Fatalf("queue drops = %d", n)
	}
}

// A stalled window must not stop the reader: datagrams past the queue are
// dropped and counted under limit workers, and the ones in the queue are
// counted once the window frees up.
func TestWorkersQueueFullIsCounted(t *testing.T) {
	s, conn := startSource(t, "listen: 127.0.0.1:0\nworkers: 1\n")
	const packets, burst = 700, 50
	pkt := buildV5(1, []v5rec{{dst: netip.MustParseAddr("203.0.113.10"), octets: 1000}})
	s.win.mu.Lock()
	for i := range packets {
		if _, err := conn.Write(pkt); err != nil {
			s.win.mu.Unlock()
			t.Fatal(err)
		}
		if (i+1)%burst == 0 {
			time.Sleep(10 * time.Millisecond) // let the reader drain the socket
		}
	}
	// The stalled worker holds one datagram and the queue holds
	// queuePerWorker; the reader has to take and drop all the rest.
	const queued = queuePerWorker + 1
	// The kernel may drop a few loopback datagrams before the reader
	// takes them, so the drop count is bounded rather than exact.
	const kernelSlack = 50
	waitFor(t, "queue drops", func() bool { return s.queueFull.Load() >= packets-queued-kernelSlack })
	s.win.mu.Unlock()
	waitFor(t, "queued datagrams counted", func() bool { return windowBytes(t, s) >= queued*1000 })
	got := s.Truncated()["workers"]
	if got < packets-queued-kernelSlack || got > packets-queued {
		t.Fatalf("Truncated workers = %d, want %d to %d", got, packets-queued-kernelSlack, packets-queued)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A reload stops the source and starts a new one on the same port; the
// same Source must also start again with a fresh queue and workers.
func TestRestartAfterStop(t *testing.T) {
	s, conn := startSource(t, "listen: 127.0.0.1:0\nworkers: 2\n")
	pkt := buildV5(1, []v5rec{{dst: netip.MustParseAddr("203.0.113.10"), octets: 1000}})
	if _, err := conn.Write(pkt); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "first datagram counted", func() bool { return windowBytes(t, s) == 1000 })
	stop, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := s.Stop(stop); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("restart after Stop: %v", err)
	}
	dst, err := net.ResolveUDPAddr("udp", s.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn2, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	if _, err := conn2.Write(pkt); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second datagram counted", func() bool { return windowBytes(t, s) == 2000 })
}
