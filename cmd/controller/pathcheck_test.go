package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type fakePathStatus struct {
	calls map[string]bool
}

func (f *fakePathStatus) SetPathMismatch(name string, mismatch bool) {
	if f.calls == nil {
		f.calls = map[string]bool{}
	}
	f.calls[name] = mismatch
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func boolPtr(v bool) *bool { return &v }

func TestPathTargetsSkipsRemoteAndOptOut(t *testing.T) {
	cfg := &config.Config{Providers: []config.Provider{
		{Name: "local", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"},
		{Name: "opted-out", SourceIP: "192.0.2.12", NextHop: "192.0.2.2", PathCheck: boolPtr(false)},
		{Name: "remote", SourceIP: "", NextHop: "192.0.2.3", Domain: "pop-b"},
		{Name: "bad-address", SourceIP: "not-an-ip", NextHop: "192.0.2.4"},
	}}
	cfg.Domain = "pop-a"
	got := pathTargets(cfg)
	if len(got) != 1 || got[0].Name != "local" {
		t.Fatalf("targets = %+v", got)
	}
	if got[0].Source != netip.MustParseAddr("192.0.2.11") || got[0].NextHop != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("target addresses = %+v", got[0])
	}
}

func TestPathTargetsSkipsLoopbackSource(t *testing.T) {
	cfg := &config.Config{Providers: []config.Provider{
		{Name: "loopback-v4", SourceIP: "127.0.0.1", NextHop: "192.0.2.1"},
		{Name: "loopback-v6", SourceIP: "::1", NextHop: "2001:db8::1"},
		{Name: "local", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"},
	}}
	got := pathTargets(cfg)
	if len(got) != 1 || got[0].Name != "local" {
		t.Fatalf("targets = %+v", got)
	}
}

func TestPathCheckRoundRecordsEveryVerdict(t *testing.T) {
	status := &fakePathStatus{}
	next := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("198.51.100.9")
	sawSink := false
	c := &pathChecker{
		status: status,
		targets: []pathTarget{
			{Name: "matches", Source: netip.MustParseAddr("192.0.2.11"), NextHop: next},
			{Name: "wrong-hop", Source: netip.MustParseAddr("192.0.2.12"), NextHop: next},
			{Name: "no-reply", Source: netip.MustParseAddr("192.0.2.13"), NextHop: next},
			{Name: "send-error", Source: netip.MustParseAddr("192.0.2.14"), NextHop: next},
		},
		hop: func(_ context.Context, src, dst netip.Addr, _, _ int, _ time.Duration) (netip.Addr, bool, error) {
			sawSink = sawSink || dst == pathSink4
			switch {
			case src == netip.MustParseAddr("192.0.2.11"):
				return next, true, nil
			case src == netip.MustParseAddr("192.0.2.12"):
				return other, false, nil
			case src == netip.MustParseAddr("192.0.2.13"):
				return netip.Addr{}, false, nil
			default:
				return netip.Addr{}, false, errors.New("network unreachable")
			}
		},
		timeout: time.Second,
		log:     discardLog(),
	}
	if n := c.round(context.Background()); n != 4 {
		t.Fatalf("checked = %d, want 4", n)
	}
	if !sawSink {
		t.Error("probe destination was not the documentation sink")
	}
	if status.calls["matches"] {
		t.Error("matching hop recorded a mismatch")
	}
	for _, name := range []string{"wrong-hop", "no-reply", "send-error"} {
		if !status.calls[name] {
			t.Errorf("%s was not a mismatch", name)
		}
	}
}

func TestPathCheckRoundSkipsUnavailableSource(t *testing.T) {
	status := &fakePathStatus{}
	c := &pathChecker{
		status:  status,
		targets: []pathTarget{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), NextHop: netip.MustParseAddr("192.0.2.1")}},
		hop: func(context.Context, netip.Addr, netip.Addr, int, int, time.Duration) (netip.Addr, bool, error) {
			return netip.Addr{}, false, plugin.ErrSourceUnavailable
		},
		timeout: time.Second,
		log:     discardLog(),
	}
	if n := c.round(context.Background()); n != 0 {
		t.Fatalf("checked = %d, want 0", n)
	}
	if len(status.calls) != 0 {
		t.Fatalf("unavailable source changed status: %+v", status.calls)
	}
}

func TestPathCheckerForHonorsEnabled(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("path check is Linux-only")
	}
	base := &config.Config{Providers: []config.Provider{
		{Name: "transit-a", SourceIP: "192.0.2.11", NextHop: "192.0.2.1"},
	}}
	if pc := pathCheckerFor(base, nil, nil, discardLog()); pc == nil {
		t.Fatal("checker should run by default")
	}
	off := *base
	off.Probe.PathCheck.Enabled = boolPtr(false)
	if pc := pathCheckerFor(&off, nil, nil, discardLog()); pc != nil {
		t.Fatal("checker should be off")
	}
}

func TestPathCheckerRunChecksAndStops(t *testing.T) {
	ran := make(chan struct{}, 1)
	c := &pathChecker{
		status:  &fakePathStatus{},
		targets: []pathTarget{{Name: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), NextHop: netip.MustParseAddr("192.0.2.1")}},
		hop: func(context.Context, netip.Addr, netip.Addr, int, int, time.Duration) (netip.Addr, bool, error) {
			select {
			case ran <- struct{}{}:
			default:
			}
			return netip.MustParseAddr("192.0.2.1"), true, nil
		},
		timeout: time.Second,
		log:     discardLog(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.run(ctx, time.Hour)
		close(done)
	}()
	select {
	case <-ran:
	case <-time.After(2 * time.Second):
		t.Fatal("checker did not check immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("checker did not stop on cancel")
	}
}
