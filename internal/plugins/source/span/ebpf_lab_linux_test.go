//go:build linux

package span

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath/labtest"
	"golang.org/x/sys/unix"
)

// injector writes frames out of a veth end with an AF_PACKET socket, so
// the traffic is synthetic, stays on the veth pair, and leaves no host.
type injector struct {
	fd int
	to *unix.SockaddrLinklayer
}

func newInjector(t *testing.T, dev string) *injector {
	t.Helper()
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	to := &unix.SockaddrLinklayer{Ifindex: ifi.Index, Halen: 6}
	copy(to.Addr[:], macB)
	return &injector{fd: fd, to: to}
}

func (j *injector) send(b []byte) error { return unix.Sendto(j.fd, b, 0, j.to) }

func startLab(t *testing.T, y string) *Source {
	t.Helper()
	s := mustSource(t, y)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		if err := s.Stop(stop); err != nil {
			t.Errorf("stop: %v", err)
		}
	})
	return s
}

// The eBPF path and the AF_PACKET path read the same traffic on a veth
// pair and must give the same counts (#229).
func TestEBPFVethSameMetricsAsAFPacket(t *testing.T) {
	labtest.RequireRoot(t)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	y := "interface: " + dev + "\npromiscuous: false\nlocal: [192.0.2.0/24, \"2001:db8:1::/48\"]\n"
	raw := startLab(t, y)
	kern := startLab(t, y+"ebpf: true\n")
	if _, ok := kern.cap.(ebpfCapture); !ok {
		t.Fatalf("ebpf: true used %T; the lab kernel must support TCX (Linux 6.6)", kern.cap)
	}
	if _, ok := raw.cap.(ebpfCapture); ok {
		t.Fatal("ebpf off used the eBPF path")
	}
	j := newInjector(t, dev)
	for _, p := range fixturePackets() {
		if p.dst.Addr() != retransV4 && p.src.Addr() != retransV4 {
			continue
		}
		p.vlan = 0
		if err := j.send(frame(p)); err != nil {
			t.Fatal(err)
		}
	}
	waitRetrans(t, raw)
	waitRetrans(t, kern)
	if n := kern.Truncated()["ebpf_ring_full"]; n != 0 {
		t.Fatalf("ring buffer full %d times on 276 frames", n)
	}
}

// A kernel or device that cannot take the program falls back without an
// error: a tun device has no Ethernet header.
func TestEBPFUnsupportedDeviceFallsBack(t *testing.T) {
	labtest.RequireRoot(t)
	dev := labtest.Tun(t)
	s := startLab(t, "interface: "+dev+"\npromiscuous: false\nebpf: true\nlocal: [192.0.2.0/24]\n")
	if _, ok := s.cap.(ebpfCapture); ok {
		t.Fatal("eBPF attached to a device without an Ethernet header")
	}
	if s.cap == nil {
		t.Fatal("no capture after fallback")
	}
}

// TestEBPFCPUPerGbit prints the capture CPU cost of both paths for the
// same traffic: seconds of process CPU above a run with no capture, per
// gigabit of frames sent.
func TestEBPFCPUPerGbit(t *testing.T) {
	labtest.RequireRoot(t)
	const (
		frames  = 200000
		payload = 1448
	)
	dev, _ := labtest.Veth(t, "192.0.2.1/24")
	j := newInjector(t, dev)
	one := frame(pkt{src: ap(localV4, 40000), dst: ap(netip.MustParseAddr("198.51.100.10"), 443), flags: flagACK, data: payload})
	gbit := float64(frames*len(one)*8) / 1e9

	run := func(c capture) (cpu time.Duration, got, sent int) {
		done := make(chan struct{})
		counted := make(chan int, 1)
		if c != nil {
			go func() {
				buf := make([]byte, snapLen)
				n := 0
				idle := 0
				for idle < 2 {
					select {
					case <-done:
						idle++
					default:
					}
					if _, err := c.read(buf); err == nil {
						n++
						idle = 0
					} else if err != errReadTimeout {
						break
					}
				}
				counted <- n
			}()
		}
		before := cpuTime(t)
		for range frames {
			if j.send(one) == nil {
				sent++
			}
		}
		close(done)
		if c != nil {
			got = <-counted
		}
		return cpuTime(t) - before, got, sent
	}

	base, _, sent := run(nil)
	if sent < frames*9/10 {
		t.Fatalf("sent only %d of %d frames", sent, frames)
	}
	rawCap, err := openCapture(dev, false, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	rawCPU, rawGot, rawSent := run(rawCap)
	_ = rawCap.close()
	kernCap, err := openEBPF(dev, false, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	kernCPU, kernGot, kernSent := run(kernCap)
	drops := kernCap.(ebpfCapture).drops()
	_ = kernCap.close()

	t.Logf("sent %d frames of %d bytes (%.2f Gbit) per run; no-capture baseline %.2fs CPU", sent, len(one), gbit, base.Seconds())
	t.Logf("af_packet: %d frames read, %.2fs CPU above baseline, %.2f CPU-seconds per Gbit", rawGot, (rawCPU - base).Seconds(), (rawCPU-base).Seconds()/gbit)
	t.Logf("ebpf:      %d frames read, %d ring drops, %.2fs CPU above baseline, %.2f CPU-seconds per Gbit", kernGot, drops, (kernCPU - base).Seconds(), (kernCPU-base).Seconds()/gbit)
	if uint64(kernGot)+drops < uint64(kernSent)*99/100 {
		t.Fatalf("eBPF path saw %d frames and counted %d drops of %d sent", kernGot, drops, kernSent)
	}
	if rawGot == 0 || rawSent == 0 {
		t.Fatalf("AF_PACKET path read %d frames", rawGot)
	}
}

func cpuTime(t *testing.T) time.Duration {
	t.Helper()
	var ru unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &ru); err != nil {
		t.Fatal(err)
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}
