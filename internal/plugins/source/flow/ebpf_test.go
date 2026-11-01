package flow

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakeFlows struct {
	mu     sync.Mutex
	snap   map[ebpfpath.FlowKey]ebpfpath.Totals
	closed bool
}

func (f *fakeFlows) Snapshot() (map[ebpfpath.FlowKey]ebpfpath.Totals, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[ebpfpath.FlowKey]ebpfpath.Totals, len(f.snap))
	for k, v := range f.snap {
		out[k] = v
	}
	return out, nil
}

func (f *fakeFlows) set(k ebpfpath.FlowKey, t ebpfpath.Totals) {
	f.mu.Lock()
	f.snap[k] = t
	f.mu.Unlock()
}

func (f *fakeFlows) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeFlows) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

func ebpfSource(t *testing.T, y string, f *fakeFlows) *Source {
	t.Helper()
	s := mustSource(t, y)
	s.ebpfEvery = 5 * time.Millisecond
	s.openFlows = func(iface string, max int) (flowReader, error) {
		if iface != "eth9" || max != 2048 {
			t.Errorf("opened %s with %d entries", iface, max)
		}
		return f, nil
	}
	return s
}

func volumeOf(t *testing.T, s *Source, p string) uint64 {
	t.Helper()
	vols, err := s.Volumes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vols {
		if v.Prefix.String() == p {
			return v.Bytes
		}
	}
	return 0
}

func TestEBPFCollectorFeedsWindow(t *testing.T) {
	key := ebpfpath.FlowKey{Src: netip.MustParseAddr("192.0.2.10"), Dst: netip.MustParseAddr("198.51.100.7"), Proto: 17}
	private := ebpfpath.FlowKey{Src: key.Src, Dst: netip.MustParseAddr("10.1.2.3"), Proto: 6}
	f := &fakeFlows{snap: map[ebpfpath.FlowKey]ebpfpath.Totals{key: {Bytes: 300, Packets: 5}, private: {Bytes: 9999, Packets: 9}}}
	s := ebpfSource(t, "ebpf: {interface: eth9, max_entries: 2048}\nwindow: 1m\n", f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err == nil {
		t.Fatal("second Start accepted")
	}
	waitFor(t, "first poll", func() bool { return volumeOf(t, s, "198.51.100.0/24") == 300 })
	f.set(key, ebpfpath.Totals{Bytes: 450, Packets: 8})
	waitFor(t, "delta", func() bool { return volumeOf(t, s, "198.51.100.0/24") == 450 })
	time.Sleep(30 * time.Millisecond)
	if got := volumeOf(t, s, "198.51.100.0/24"); got != 450 {
		t.Fatalf("an unchanged counter was added again: %d", got)
	}
	if got := volumeOf(t, s, "10.1.2.0/24"); got != 0 {
		t.Fatalf("private destination counted: %d", got)
	}
	cs, err := s.FlowCounters(context.Background())
	if err != nil || len(cs) != 1 || cs[0].Protocol != plugin.IPProtocol(17) || cs[0].Bytes != 450 {
		t.Fatalf("flow counters = %+v, %v", cs, err)
	}
	stop, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := s.Stop(stop); err != nil {
		t.Fatal(err)
	}
	if !f.isClosed() {
		t.Fatal("Stop did not release the kernel program")
	}
	// A restart on the same source loads it again.
	if err := s.Start(ctx); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := s.Stop(stop); err != nil {
		t.Fatal(err)
	}
}

func TestEBPFUnavailableKeepsListeners(t *testing.T) {
	s := mustSource(t, "listen: 127.0.0.1:0\nebpf: {interface: eth9}\n")
	s.openFlows = func(string, int) (flowReader, error) { return nil, errors.New("operation not permitted") }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("an unavailable eBPF path must not fail Start: %v", err)
	}
	s.connMu.Lock()
	conns, run := len(s.conns), s.ebpfRun
	s.connMu.Unlock()
	if conns != 1 || run != nil {
		t.Fatalf("listeners = %d, ebpf run = %v", conns, run)
	}
	stop, c := context.WithTimeout(context.Background(), 5*time.Second)
	defer c()
	if err := s.Stop(stop); err != nil {
		t.Fatal(err)
	}
}

func TestEBPFConfig(t *testing.T) {
	for y, want := range map[string]string{
		"window: 1m\n":                                     "listen or ebpf is required",
		"ebpf: {interface: \"\"}\n":                        "not a valid interface name",
		"ebpf: {interface: \"a b\"}\n":                     "not a valid interface name",
		"ebpf: {interface: eth9, max_entries: 10}\n":       "max_entries 10 must be between",
		"ebpf: {interface: eth9, max_entries: 99999999}\n": "max_entries 99999999 must be between",
		"ebpf: {interface: eth9, bogus: 1}\n":              "bogus",
	} {
		if _, err := build(y); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", y, err, want)
		}
	}
	s := mustSource(t, "ebpf: {interface: eth9}\n")
	if s.ebpf.MaxEntries != ebpfpath.DefaultFlowEntries {
		t.Fatalf("default max_entries = %d", s.ebpf.MaxEntries)
	}
}
