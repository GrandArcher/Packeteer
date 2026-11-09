package httpapi

import (
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/herd"
)

func TestHerdMetricsCountTripsByLimitAndPeer(t *testing.T) {
	st := herd.NodeStatus{
		Limits: []herd.TripCount{
			{Trip: herd.Trip{Limit: "rate_global"}, Count: 7},
			{Trip: herd.Trip{Limit: "pull_bytes", Peer: "abc"}, Count: 2},
		},
		Peers: []herd.PeerStatus{
			{KeyID: "abc", LastOK: time.Now()},
			{KeyID: "def", LastOK: time.Now(), Failures: 3},
			{KeyID: "ghi"},
		},
		Queue: herd.QueueStatus{Dropped: 5, Stored: 9, Restarts: 1},
		Store: herd.StoreStatus{LocalRecords: 4, LocalBytes: 400, LocalBudget: 1000, PulledRecords: 2, PulledBytes: 200, PulledBudget: 500},
	}
	got := string(HerdMetrics(st))
	for _, want := range []string{
		`packeteer_herd_limit_trips_total{limit="rate_global"} 7`,
		`packeteer_herd_limit_trips_total{limit="pull_bytes",peer="abc"} 2`,
		"packeteer_herd_records_dropped_total 5",
		"packeteer_herd_records_stored_total 9",
		"packeteer_herd_restarts_total 1",
		`packeteer_herd_store_bytes{class="pulled"} 200`,
		`packeteer_herd_store_budget_bytes{class="local"} 1000`,
		`packeteer_herd_peer_up{peer="abc"} 1`,
		`packeteer_herd_peer_up{peer="def"} 0`,
		`packeteer_herd_peer_up{peer="ghi"} 0`,
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("metrics miss %q:\n%s", want, got)
		}
	}
}
