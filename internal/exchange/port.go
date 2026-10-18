package exchange

import (
	"time"

	"github.com/GrandArcher/Packeteer/internal/portload"
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

// PortCommits is port.commit_mbps by exchange name, for the exchanges that
// have a port.
func PortCommits(exs []Exchange) map[string]float64 {
	out := map[string]float64{}
	for _, ex := range exs {
		if ex.Port != nil {
			out[ex.Name] = ex.Port.CommitMbps
		}
	}
	return out
}

// WithPortCommit returns rows with the commit of each port row set to the
// port's. A port's telemetry binding needs a commit_mbps to be readable, but
// it is a placeholder; alerts, metrics and the commit page must judge the
// port by port.commit_mbps. The scorers read the rows unchanged.
func WithPortCommit(rows []plugin.Usage, commits map[string]float64) []plugin.Usage {
	out := append([]plugin.Usage(nil), rows...)
	for i := range out {
		if c, ok := commits[out[i].Provider]; ok {
			out[i].CommitMbps = c
		}
	}
	return out
}

// ApplyPorts fills Port on each exchange that has one, from the telemetry
// rows (the row whose provider is the exchange name). maxAge is the
// freshness limit of the scorer that plans against the port.
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
			if load, p95, fresh := portload.Read(u, now, maxAge); fresh {
				ps.State, ps.LoadMbps, ps.P95Mbps = PortOK, load, p95
				ps.HeadroomMbps = portload.Room(pc.CapacityMbps, pc.CommitMbps, load, p95)
			} else {
				ps.State = PortStale
			}
		}
		stats[i].Port = ps
	}
}
