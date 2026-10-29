package goprober

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func build(t *testing.T, yaml string) (plugin.Prober, error) {
	t.Helper()
	c, err := plugin.ConfigFromYAML(yaml)
	if err != nil {
		t.Fatal(err)
	}
	return plugin.Probers.New(TypeName, c, plugin.Env{})
}

func request() plugin.ProbeRequest {
	return plugin.ProbeRequest{
		Provider: "transit-a",
		Source:   netip.MustParseAddr("192.0.2.11"),
		Target:   netip.MustParseAddr("198.51.100.1"),
		Count:    3,
		Timeout:  time.Second,
	}
}

func TestProbe(t *testing.T) {
	p, err := build(t, "rtt_ms: 12.5")
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Probe(context.Background(), request())
	if err != nil {
		t.Fatal(err)
	}
	want := 12500 * time.Microsecond
	if res.Sent != 3 || len(res.RTTs) != 3 || res.RTTs[0] != want || res.RTTs[2] != want {
		t.Fatalf("result = %+v, want 3 sent and 3 replies of %v", res, want)
	}
}

func TestDefaultRTT(t *testing.T) {
	p, err := plugin.Probers.New(TypeName, plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Probe(context.Background(), request())
	if err != nil || res.RTTs[0] != 10*time.Millisecond {
		t.Fatalf("res=%+v err=%v, want a 10ms default", res, err)
	}
}

func TestConfigErrors(t *testing.T) {
	for yaml, want := range map[string]string{
		"rtt_ms: -1":  "must be positive",
		"rtt_msec: 5": "rtt_msec",
	} {
		_, err := build(t, yaml)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to contain %q", yaml, err, want)
		}
	}
}

func TestProbeFailsClosed(t *testing.T) {
	p, err := build(t, "rtt_ms: 5")
	if err != nil {
		t.Fatal(err)
	}
	noSource := request()
	noSource.Source = netip.Addr{}
	tagged := request()
	tagged.DSCP = 46
	for name, req := range map[string]plugin.ProbeRequest{"no source": noSource, "dscp": tagged} {
		if _, err := p.Probe(context.Background(), req); !errors.Is(err, plugin.ErrSourceUnavailable) {
			t.Errorf("%s: err = %v, want ErrSourceUnavailable", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Probe(ctx, request()); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: err = %v, want context.Canceled", err)
	}
}
