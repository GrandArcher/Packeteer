package exchange

import (
	"time"

	"github.com/GrandArcher/Packeteer/internal/plugins/scorer/ports"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Port states. Commit and cost planning move nothing onto the exchange's
// peers unless the state is PortOK.
const (
	PortOK          = "ok"
	PortNoTelemetry = "no_telemetry"
	PortStale       = "stale"
)

// PortConfig is an exchange's configured shared port (#151).
type PortConfig struct {
	CapacityMbps float64
	CommitMbps   float64
	PortCost     *float64
}

// PortStats is the port as configured and as last read from the telemetry
// binding named like the exchange. Display only.
type PortStats struct {
	State        string   `json:"state"`
	CapacityMbps float64  `json:"capacity_mbps"`
	CommitMbps   float64  `json:"commit_mbps,omitempty"`
	PortCost     *float64 `json:"port_cost,omitempty"`
	// LoadMbps is the larger of the latest outbound rate and the billable
	// 95th. P95Mbps is the billable 95th. Both are set only when State is ok.
	LoadMbps float64 `json:"load_mbps"`
	P95Mbps  float64 `json:"p95_mbps"`
	// HeadroomMbps is the room under capacity and, when set, commit.
	HeadroomMbps float64 `json:"headroom_mbps"`
}

// ApplyPorts fills Port on each exchange that has one, from the telemetry
// rows (the row whose provider is the exchange name). maxAge is the commit
// and cost planners' freshness limit.
func ApplyPorts(stats []Stats, exs []Exchange, rows []plugin.Usage, now time.Time, maxAge time.Duration) {
	byName := map[string]plugin.Usage{}
	for _, u := range rows {
		if _, dup := byName[u.Provider]; !dup {
			byName[u.Provider] = u
		}
	}
	cfg := map[string]*PortConfig{}
	for _, ex := range exs {
		cfg[ex.Name] = ex.Port
	}
	for i := range stats {
		pc := cfg[stats[i].Name]
		if pc == nil {
			continue
		}
		ps := &PortStats{State: PortNoTelemetry, CapacityMbps: pc.CapacityMbps, CommitMbps: pc.CommitMbps, PortCost: pc.PortCost}
		if u, ok := byName[stats[i].Name]; ok {
			if load, p95, fresh := ports.Read(u, now, maxAge); fresh {
				ps.State, ps.LoadMbps, ps.P95Mbps = PortOK, load, p95
				ps.HeadroomMbps = ports.Room(pc.CapacityMbps, pc.CommitMbps, load, p95)
			} else {
				ps.State = PortStale
			}
		}
		stats[i].Port = ps
	}
}
