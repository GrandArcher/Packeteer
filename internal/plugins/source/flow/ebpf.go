package flow

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/ebpfpath"
)

// ebpfPoll is how often the kernel counters are read. A burst shorter than
// that is still counted whole: the kernel adds up every packet, and the
// window buckets are 10 seconds wide.
const ebpfPoll = time.Second

// EBPFConfig is the flow source's eBPF collector block (#229). It counts
// every packet leaving the interface in the kernel, unsampled, and feeds the
// same window as the NetFlow, IPFIX, and sFlow listeners.
type EBPFConfig struct {
	// Interface is the Ethernet interface whose egress is counted.
	Interface string `yaml:"interface"`
	// MaxEntries bounds the kernel flow table (source, destination, and
	// protocol). The kernel evicts the least recently used flow past it.
	// Default 65536.
	MaxEntries int `yaml:"max_entries"`
}

func newEBPF(c *EBPFConfig) (*EBPFConfig, error) {
	if c == nil {
		return nil, nil
	}
	out := *c
	if out.Interface == "" || len(out.Interface) > 15 || strings.ContainsAny(out.Interface, "/ \t\n") {
		return nil, fmt.Errorf("ebpf.interface %q is not a valid interface name", out.Interface)
	}
	if out.MaxEntries == 0 {
		out.MaxEntries = ebpfpath.DefaultFlowEntries
	}
	if out.MaxEntries < ebpfpath.MinFlowEntries || out.MaxEntries > ebpfpath.MaxFlowEntries {
		return nil, fmt.Errorf("ebpf.max_entries %d must be between %d and %d", out.MaxEntries, ebpfpath.MinFlowEntries, ebpfpath.MaxFlowEntries)
	}
	return &out, nil
}

// ebpfRun is one running poller.
type ebpfRun struct{ cancel context.CancelFunc }

// flowReader is the kernel flow table.
type flowReader interface {
	Snapshot() (map[ebpfpath.FlowKey]ebpfpath.Totals, error)
	Close() error
}

func openFlows(iface string, maxEntries int) (flowReader, error) {
	return ebpfpath.OpenFlows(iface, maxEntries)
}

// startEBPF loads the collector. A kernel or container that cannot load it
// is not an error: the source keeps its listeners and says so in the log.
func (s *Source) startEBPF(ctx context.Context) {
	f, err := s.openFlows(s.ebpf.Interface, s.ebpf.MaxEntries)
	if err != nil {
		s.log.Warn("flow eBPF collector unavailable", "interface", s.ebpf.Interface, "err", err)
		return
	}
	pctx, cancel := context.WithCancel(ctx)
	run := &ebpfRun{cancel: cancel}
	s.connMu.Lock()
	if s.ebpfRun != nil {
		s.connMu.Unlock()
		cancel()
		_ = f.Close()
		return
	}
	s.ebpfRun = run
	s.connMu.Unlock()
	s.log.Info("flow eBPF collector", "interface", s.ebpf.Interface, "max_entries", s.ebpf.MaxEntries)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer f.Close()
		s.pollEBPF(pctx, f)
		cancel()
		s.connMu.Lock()
		if s.ebpfRun == run {
			s.ebpfRun = nil
		}
		s.connMu.Unlock()
	}()
}

// stopEBPF ends the poller; Stop then waits for it through wg.
func (s *Source) stopEBPF() {
	s.connMu.Lock()
	run := s.ebpfRun
	s.connMu.Unlock()
	if run != nil {
		run.cancel()
	}
}

func (s *Source) pollEBPF(ctx context.Context, f flowReader) {
	var diff ebpfpath.Differ
	t := time.NewTicker(s.ebpfEvery)
	defer t.Stop()
	failed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		snap, err := f.Snapshot()
		if err != nil {
			if !failed {
				s.log.Warn("flow eBPF read", "err", err)
			}
			failed = true
			continue
		}
		failed = false
		ds := diff.Next(snap)
		if len(ds) == 0 {
			continue
		}
		obs := make([]observation, 0, len(ds))
		var packets uint64
		for _, d := range ds {
			obs = append(obs, observation{dst: d.Key.Dst, src: d.Key.Src, proto: d.Key.Proto, bytes: d.Bytes})
			packets += d.Packets
		}
		s.log.Debug("flow eBPF poll", "flows", len(ds), "packets", packets)
		s.apply(s.now(), obs)
	}
}
