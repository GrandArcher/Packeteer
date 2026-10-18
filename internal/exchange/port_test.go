package exchange

import (
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

func TestApplyPorts(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	cost := 1500.0
	exs := []Exchange{
		{Name: "ix-a", Port: &PortConfig{CapacityMbps: 1000, CommitMbps: 400, PortCost: &cost}},
		{Name: "ix-b", Port: &PortConfig{CapacityMbps: 1000}},
		{Name: "ix-c", Port: &PortConfig{CapacityMbps: 1000}},
		{Name: "ix-d"},
	}
	row := func(name string, p95, out float64, at time.Time) plugin.Usage {
		return plugin.Usage{Provider: name, CommitMbps: 1, Samples: 5, Single: true, UsageMbps: p95, OutMbps: out, Updated: at}
	}
	stats := []Stats{{Name: "ix-a"}, {Name: "ix-b"}, {Name: "ix-c"}, {Name: "ix-d"}}
	ApplyPorts(stats, exs, []plugin.Usage{
		row("ix-a", 300, 350, now),
		row("ix-b", 10, 10, now.Add(-time.Hour)),
		row("ix-d", 10, 10, now),
	}, now, 15*time.Minute)

	a := stats[0].Port
	if a == nil || a.State != PortOK || a.LoadMbps != 350 || a.P95Mbps != 300 || a.HeadroomMbps != 100 ||
		a.CapacityMbps != 1000 || a.CommitMbps != 400 || a.PortCost == nil || *a.PortCost != 1500 {
		t.Fatalf("ix-a port = %+v", a)
	}
	if b := stats[1].Port; b == nil || b.State != PortStale || b.HeadroomMbps != 0 {
		t.Fatalf("ix-b port = %+v", b)
	}
	if c := stats[2].Port; c == nil || c.State != PortNoTelemetry {
		t.Fatalf("ix-c port = %+v", c)
	}
	if stats[3].Port != nil {
		t.Fatalf("an exchange without a port block got %+v", stats[3].Port)
	}
}
