package httpapi

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

// A measurement taken by a probe agent names its site and agent (#230),
// and a local one carries neither.
func TestProbeRowsNameTheirSiteAndAgent(t *testing.T) {
	r := probe.Result{Provider: "far", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Site: "dc-b", Agent: "agent-b",
		Stats: probe.Stats{Sent: 3, Received: 3}}
	raw, _ := json.Marshal(probeFrom(r))
	if !strings.Contains(string(raw), `"site":"dc-b"`) || !strings.Contains(string(raw), `"agent":"agent-b"`) {
		t.Fatalf("probe json = %s", raw)
	}
	r.Site, r.Agent = "", ""
	raw, _ = json.Marshal(probeFrom(r))
	if strings.Contains(string(raw), "site") || strings.Contains(string(raw), "agent") {
		t.Fatalf("local probe json = %s", raw)
	}
}

func TestProviderRowNamesItsSite(t *testing.T) {
	rows := assembleProviders(Input{Started: true, Providers: []config.Provider{{Name: "far", Site: "dc-b", NextHop: "203.0.113.12"}},
		Status: []probe.ProviderStatus{{Name: "far", Site: "dc-b", Up: false, Reason: "no usable probe agent"}}})
	if len(rows) != 1 || rows[0].Site != "dc-b" || rows[0].Up || rows[0].Reason != "no usable probe agent" {
		t.Fatalf("rows = %+v", rows)
	}
}
