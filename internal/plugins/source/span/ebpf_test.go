package span

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCapture hands out queued frames, then times out like a quiet link.
type fakeCapture struct {
	mu     sync.Mutex
	frames [][]byte
	closed bool
}

func (f *fakeCapture) link() int { return linkEthernet }

func (f *fakeCapture) read(buf []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.frames) == 0 {
		f.mu.Unlock()
		time.Sleep(2 * time.Millisecond)
		f.mu.Lock()
		return 0, errReadTimeout
	}
	n := copy(buf, f.frames[0])
	f.frames = f.frames[1:]
	return n, nil
}

func (f *fakeCapture) close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func retransFrames() [][]byte {
	var out [][]byte
	for _, p := range fixturePackets() {
		if p.dst.Addr() != retransV4 && p.src.Addr() != retransV4 {
			continue
		}
		p.vlan = 0
		out = append(out, frame(p))
	}
	return out
}

func startEBPFSource(t *testing.T, y string, ebpf, raw func(string, bool, time.Duration) (capture, error)) *Source {
	t.Helper()
	s := mustSource(t, y)
	s.openEBPF, s.openRaw = ebpf, raw
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

func waitRetrans(t *testing.T, s *Source) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		ps := s.Problems()
		if len(ps) == 1 && ps[0].Prefix.String() == "198.51.100.0/24" {
			c := ps[0].Counts
			if c.Segments == 276 && c.Retrans == 36 && c.Flows == 12 {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("problems = %+v", s.Problems())
}

// With ebpf on, frames from the eBPF capture give the same verdict as the
// AF_PACKET loopback test and the pcap fixture, and the raw path is not opened.
func TestEBPFCaptureScoresLikeRawPath(t *testing.T) {
	fc := &fakeCapture{frames: retransFrames()}
	raw := func(string, bool, time.Duration) (capture, error) {
		t.Error("AF_PACKET opened although the eBPF path loaded")
		return nil, errors.New("unexpected")
	}
	s := startEBPFSource(t, baseYAML+"ebpf: true\n", func(iface string, promisc bool, _ time.Duration) (capture, error) {
		if iface != "eth1" || !promisc {
			t.Errorf("opened %s promisc=%v", iface, promisc)
		}
		return fc, nil
	}, raw)
	waitRetrans(t, s)
}

func TestEBPFFallsBackToAFPacket(t *testing.T) {
	fc := &fakeCapture{frames: retransFrames()}
	ebpfCalls := 0
	s := startEBPFSource(t, baseYAML+"ebpf: true\n", func(string, bool, time.Duration) (capture, error) {
		ebpfCalls++
		return nil, errors.New("attach TCX: operation not supported")
	}, func(string, bool, time.Duration) (capture, error) { return fc, nil })
	waitRetrans(t, s)
	if ebpfCalls != 1 {
		t.Fatalf("eBPF tried %d times", ebpfCalls)
	}
}

func TestEBPFOffNeverTriesEBPF(t *testing.T) {
	fc := &fakeCapture{frames: retransFrames()}
	s := startEBPFSource(t, baseYAML, func(string, bool, time.Duration) (capture, error) {
		t.Error("eBPF path tried although ebpf is off")
		return nil, errors.New("unexpected")
	}, func(string, bool, time.Duration) (capture, error) { return fc, nil })
	waitRetrans(t, s)
}

func TestEBPFFallbackStillReportsRawFailure(t *testing.T) {
	s := mustSource(t, baseYAML+"ebpf: true\n")
	s.openEBPF = func(string, bool, time.Duration) (capture, error) { return nil, errors.New("no bpf") }
	s.openRaw = func(string, bool, time.Duration) (capture, error) { return nil, errors.New("no NET_RAW") }
	err := s.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no NET_RAW") {
		t.Fatalf("Start = %v, want the AF_PACKET error", err)
	}
}

func TestEBPFRejectedWithPcap(t *testing.T) {
	_, err := build("pcap_file: /var/lib/packeteer/x.pcap\nebpf: true\nlocal: [192.0.2.0/24]\n")
	if err == nil || !strings.Contains(err.Error(), "ebpf applies only to interface capture") {
		t.Fatalf("err = %v", err)
	}
}
