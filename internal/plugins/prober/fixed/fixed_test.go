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
}
