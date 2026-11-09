package oop

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestProbeWireRoundTrip(t *testing.T) {
	req := plugin.ProbeRequest{Provider: "transit-a", Source: netip.MustParseAddr("192.0.2.11"), Target: netip.MustParseAddr("2001:db8::1"),
		Count: 3, Timeout: 1500 * time.Millisecond, Mark: 7, DSCP: 46}
	got, err := NewProbeParams(req).Request()
	if err != nil || got != req {
		t.Fatalf("request = %+v, %v; want %+v", got, err, req)
	}
	for _, bad := range []ProbeParams{{Source: "nope", Target: "192.0.2.1"}, {Source: "192.0.2.1", Target: "nope"}} {
		if _, err := bad.Request(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}

	res := plugin.ProbeResult{Sent: 3, RTTs: []time.Duration{10500 * time.Microsecond, 12 * time.Millisecond}}
	back, err := NewProbeResult(res).Result()
	if err != nil || back.Sent != 3 || len(back.RTTs) != 2 || back.RTTs[0] != res.RTTs[0] || back.RTTs[1] != res.RTTs[1] {
		t.Fatalf("result = %+v, %v", back, err)
	}
	for name, bad := range map[string]ProbeResult{
		"more replies than sent": {Sent: 1, RTTsMs: []float64{1, 2}},
		"negative sent":          {Sent: -1},
		"negative rtt":           {Sent: 1, RTTsMs: []float64{-1}},
	} {
		if _, err := bad.Result(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestTargetsWire(t *testing.T) {
	in := []plugin.Target{
		{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Host: netip.MustParseAddr("198.51.100.1")},
		{Prefix: netip.MustParsePrefix("2001:db8::/32"), Weight: 2},
	}
	out, err := NewTargetsResult(in).Parse()
	if err != nil || len(out) != 2 || out[0].Prefix != in[0].Prefix || out[0].Host != in[0].Host || out[1].Prefix != in[1].Prefix || out[1].Weight != 2 || out[1].Host.IsValid() {
		t.Fatalf("targets = %+v, %v", out, err)
	}
	for want, bad := range map[string]TargetEntry{
		"bad prefix":            {Prefix: "nope"},
		"not an address inside": {Prefix: "198.51.100.0/24", Host: "203.0.113.1"},
	} {
		if _, err := (TargetsResult{Targets: []TargetEntry{bad}}).Parse(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", want, err)
		}
	}
}

func TestNewSpecEnvironment(t *testing.T) {
	dir := t.TempDir()
	e := plugin.Env{PluginDir: dir, Getenv: func(k string) string {
		if k == "SECRET" {
			return "s3cret"
		}
		return ""
	}}
	spec, err := NewSpec(plugin.KindProber, e, Launch{Command: "/bin/sh", Env: map[string]string{"TOKEN": "x-${SECRET}"}}, plugin.EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "PACKETEER_PLUGIN_KIND=prober", "TOKEN=x-s3cret"}
	if strings.Join(spec.Env, " ") != strings.Join(want, " ") {
		t.Fatalf("env = %v, want %v", spec.Env, want)
	}
	if spec.Timeout != DefaultTimeout || spec.Gate != nil {
		t.Fatalf("spec = %+v", spec)
	}
	n, err := NewSpec(plugin.KindNotifier, e, Launch{Command: "/bin/sh"}, plugin.EventFilter{MinSeverity: plugin.SeverityWarning})
	if err != nil || n.Gate == nil {
		t.Fatalf("notifier spec = %+v, %v", n, err)
	}
}
