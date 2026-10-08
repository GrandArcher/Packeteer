package fixed

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func cfg(s string) plugin.Config {
	c, err := plugin.ConfigFromYAML(s)
	if err != nil {
		panic(err)
	}
	return c
}

func req(provider string) plugin.ProbeRequest {
	return plugin.ProbeRequest{
		Provider: provider,
		Source:   netip.MustParseAddr("192.0.2.11"),
		Target:   netip.MustParseAddr("198.51.100.1"),
		Count:    4,
		Timeout:  time.Second,
	}
}

func TestFixedResults(t *testing.T) {
	p, err := New(cfg(`
sent: 4
paths:
  - provider: transit-a
    rtt_ms: 80
  - provider: transit-b
    rtt_ms: 10
    loss_pct: 50
  - provider: transit-c
    source_down: true
`), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Probe(context.Background(), req("transit-a"))
	if err != nil || a.Sent != 4 || len(a.RTTs) != 4 || a.RTTs[0] != 80*time.Millisecond {
		t.Fatalf("a = %+v err=%v", a, err)
	}
	b, err := p.Probe(context.Background(), req("transit-b"))
	if err != nil || b.Sent != 4 || len(b.RTTs) != 2 {
		t.Fatalf("b = %+v err=%v", b, err)
	}
	if _, err := p.Probe(context.Background(), req("transit-c")); err == nil || !strings.Contains(err.Error(), plugin.ErrSourceUnavailable.Error()) {
		t.Fatalf("source down err = %v", err)
	}
	if _, err := p.Probe(context.Background(), req("transit-z")); err == nil || !strings.Contains(err.Error(), "no result") {
		t.Fatalf("missing provider err = %v", err)
	}
}

func TestFixedFileReread(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.yaml")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("paths:\n  - {provider: transit-a, rtt_ms: 80}\n  - {provider: transit-b, rtt_ms: 10}\n")
	p, err := New(cfg("file: "+path+"\n"), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Probe(context.Background(), req("transit-a"))
	if err != nil || a.RTTs[0] != 80*time.Millisecond {
		t.Fatalf("before = %+v err=%v", a, err)
	}
	write("paths:\n  - {provider: transit-a, rtt_ms: 10}\n  - {provider: transit-b, rtt_ms: 80}\n")
	a, err = p.Probe(context.Background(), req("transit-a"))
	if err != nil || a.RTTs[0] != 10*time.Millisecond {
		t.Fatalf("after = %+v err=%v", a, err)
	}
}

func TestFixedConfigErrors(t *testing.T) {
	if _, err := New(cfg("bogus: true\n"), plugin.Env{}); err == nil {
		t.Fatal("want unknown field error")
	}
	if _, err := New(cfg("paths:\n  - {provider: a, loss_pct: 101}\n"), plugin.Env{}); err == nil {
		t.Fatal("want loss error")
	}
	if _, err := New(cfg("{}\n"), plugin.Env{}); err == nil {
		t.Fatal("want empty config error")
	}
	if _, err := New(cfg("paths:\n  - {provider: a, rtts_ms: [1], loss_pct: 10}\n"), plugin.Env{}); err == nil {
		t.Fatal("want rtts_ms and loss_pct error")
	}
	if _, err := New(cfg("paths:\n  - {provider: a, target: not-an-ip, rtt_ms: 1}\n"), plugin.Env{}); err == nil {
		t.Fatal("want target error")
	}
	if _, err := New(cfg("paths:\n  - {provider: a, rtt_ms: 1}\n  - {provider: a, rtt_ms: 2}\n"), plugin.Env{}); err == nil || !strings.Contains(err.Error(), "duplicate provider") {
		t.Fatalf("duplicate = %v", err)
	}
}

func TestFixedRTTSpreadAndMatch(t *testing.T) {
	p, err := New(cfg(`
paths:
  - provider: transit-a
    loss_pct: 100
  - provider: transit-a
    target: 198.51.100.50
    rtts_ms: [5, 80, 5]
    sent: 3
  - provider: transit-a
    target: 198.51.100.1
    count: 2
    rtts_ms: [5, 50]
    sent: 2
  - provider: transit-a
    target: 198.51.100.1
    count: 6
    rtts_ms: [10, 11, 10, 11, 10, 11]
    sent: 6
`), plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	noisy := req("transit-a")
	noisy.Target = netip.MustParseAddr("198.51.100.50")
	noisy.Count = 4
	got, err := p.Probe(context.Background(), noisy)
	if err != nil || got.Sent != 3 || len(got.RTTs) != 3 || got.RTTs[0] != 5*time.Millisecond || got.RTTs[1] != 80*time.Millisecond {
		t.Fatalf("noisy = %+v err=%v", got, err)
	}
	fast := req("transit-a")
	fast.Count = 2
	got, err = p.Probe(context.Background(), fast)
	if err != nil || got.Sent != 2 || len(got.RTTs) != 2 || got.RTTs[1] != 50*time.Millisecond {
		t.Fatalf("fast = %+v err=%v", got, err)
	}
	full := req("transit-a")
	full.Count = 6
	got, err = p.Probe(context.Background(), full)
	if err != nil || got.Sent != 6 || len(got.RTTs) != 6 || got.RTTs[0] != 10*time.Millisecond || got.RTTs[1] != 11*time.Millisecond {
		t.Fatalf("full = %+v err=%v", got, err)
	}
	other := req("transit-a")
	other.Target = netip.MustParseAddr("198.51.100.64")
	got, err = p.Probe(context.Background(), other)
	if err != nil || got.Sent != 4 || len(got.RTTs) != 0 {
		t.Fatalf("default loss = %+v err=%v", got, err)
	}
}
