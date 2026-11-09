package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var fs4 = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}

// flowSpecOnEdge lists the FlowSpec rules the simulated edge learned from
// Packeteer as "NLRI | extended communities", sorted. Each must carry the
// packeteer community, the marker, and NO_EXPORT, or it is reported as
// "untagged".
func flowSpecOnEdge(t *testing.T, srv *server.BgpServer) []string {
	t.Helper()
	var out []string
	err := srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_ADJ_IN, Name: "127.0.0.2", Family: fs4}, func(d *api.Destination) {
		for _, p := range d.Paths {
			if p.IsWithdraw {
				continue
			}
			n, err := apiutil.GetNativeNlri(p)
			if err != nil {
				t.Error(err)
				continue
			}
			attrs, _ := apiutil.UnmarshalPathAttributes(p.Pattrs)
			var ext []string
			comms := map[uint32]bool{}
			for _, a := range attrs {
				switch v := a.(type) {
				case *bgp.PathAttributeExtendedCommunities:
					for _, e := range v.Value {
						ext = append(ext, e.String())
					}
				case *bgp.PathAttributeCommunities:
					for _, c := range v.Value {
						comms[c] = true
					}
				}
			}
			s := n.String() + " | " + strings.Join(ext, ",")
			if !comms[64512<<16|666] || !comms[64512<<16|668] || !comms[0xFFFFFF01] {
				s = "untagged " + s
			}
			out = append(out, s)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// TestDaemonFlowSpecCountryRateLimitWithdraw runs the controller in
// inject against a simulated edge that advertises 203.0.113.0/24 and
// negotiates FlowSpec. A FlowSpec drop from a source country becomes one
// rule per country network, tagged and NO_EXPORT; a rule for a prefix
// that is not learned is never announced; a rate limit replaces the drop
// in place; the feed lists the changes; shutdown withdraws everything.
func TestDaemonFlowSpecCountryRateLimitWithdraw(t *testing.T) {
	srv, port := edgeRouter(t)
	if _, err := srv.UpdatePeer(context.Background(), &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: 64512},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis:  []*api.AfiSafi{{Config: &api.AfiSafiConfig{Family: v4, Enabled: true}}, {Config: &api.AfiSafiConfig{Family: fs4, Enabled: true}}},
	}}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	geo := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(geo, geoiptest.Build(map[string]string{
		"198.51.100.0/26": "XA", "198.51.100.64/26": "XA", "192.0.2.128/25": "XA", "198.51.100.128/25": "XB",
	}), 0o644); err != nil {
		t.Fatal(err)
	}
	httpPort := freePort(t)
	cfg := fmt.Sprintf(`mode: inject
asn: 64512
router_id: 192.0.2.10
packeteer_community: "64512:666"
local_pref: 250
hold_time: 1s
thresholds: {min_loss_delta_pct: 90, min_rtt_delta_ms: 5000}
http: {listen: "127.0.0.1:%d"}
providers:
  - {name: transit-a, source_ip: 192.0.2.11, next_hop: 192.0.2.1}
  - {name: transit-b, source_ip: 192.0.2.12, next_hop: 192.0.2.2}
allowlist: {prefixes: ["198.51.100.0/24"]}
probe: {interval: 1s, timeout: 200ms, packets: 1}
probers:
  - type: fixed
    config: {paths: [{provider: transit-a, rtt_ms: 1}, {provider: transit-b, rtt_ms: 1}]}
bgp:
  neighbors:
    - {address: 127.0.0.1, port: %d, local_address: 127.0.0.2}
announcer: {type: gobgp}
mitigation:
  mode: inject
  allowlist: [203.0.113.0/24]
  max_rules: 4
  geoip_db: %s
  announcer:
    type: gobgp
    config:
      marker: "64512:668"
      flowspec:
        redirect:
          - {name: scrub-vrf, route_target: "64512:777"}
`, httpPort, port, geo)
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		switch k {
		case HTTPUserEnv:
			return "lab"
		case HTTPPassEnv:
			return "lab-only"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var out, logs syncBuf
	done := make(chan int, 1)
	go func() { done <- run(ctx, []string{"-config", path}, env, &out, &logs) }()

	base := fmt.Sprintf("http://127.0.0.1:%d/api/mitigations", httpPort)
	call := func(method, url, body string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, url, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.SetBasicAuth("lab", "lab-only")
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return resp.StatusCode, m
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s\nedge: %v\n%s", what, flowSpecOnEdge(t, srv), logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitFor("the ops API", func() bool { code, _ := call(http.MethodGet, base, ""); return code == http.StatusOK })
	waitFor("the session", func() bool { return strings.Contains(logs.String(), "state=ESTABLISHED") })

	// XA is three networks; two merge, so two routes. XA+XB would be 3.
	code, rule := call(http.MethodPost, base, `{"prefix":"203.0.113.0/24","action":"flowspec_drop","source_countries":["XA"],"match":{"protocols":["udp"],"destination_ports":[53]},"ttl":"10m"}`)
	if code != http.StatusCreated || rule["routes"] != float64(2) {
		t.Fatalf("country drop: %d %v", code, rule)
	}
	// Not learned: held, never announced (1 route; 3 of 4 held).
	if code, _ := call(http.MethodPost, base, `{"prefix":"203.0.113.128/25","action":"flowspec_drop","ttl":"10m"}`); code != http.StatusCreated {
		t.Fatalf("pending flowspec: %d", code)
	}
	// Past the cap: 2 more routes would be 5 of 4.
	if code, _ := call(http.MethodPost, base, `{"prefix":"203.0.113.0/24","action":"flowspec_drop","source_countries":["XA"],"ttl":"10m"}`); code != http.StatusConflict {
		t.Fatalf("flowspec past the cap: %d", code)
	}
	want := []string{
		"[destination: 203.0.113.0/24][source: 192.0.2.128/25][protocol: ==udp][destination-port: ==53] | discard",
		"[destination: 203.0.113.0/24][source: 198.51.100.0/25][protocol: ==udp][destination-port: ==53] | discard",
	}
	waitFor("country drop on the edge", func() bool { return strings.Join(flowSpecOnEdge(t, srv), "\n") == strings.Join(want, "\n") })

	// Rate limit replaces the drop in place (same key); 8 Mbit/s is
	// 1,000,000 bytes/s.
	if code, _ := call(http.MethodPost, base, `{"prefix":"203.0.113.0/24","action":"flowspec_rate_limit","rate_mbps":8,"source_countries":["XA"],"match":{"protocols":[17],"destination_ports":["53"]},"ttl":"10m"}`); code != http.StatusCreated {
		t.Fatalf("rate limit: %d", code)
	}
	waitFor("rate limit on the edge", func() bool {
		got := flowSpecOnEdge(t, srv)
		return len(got) == 2 && strings.HasSuffix(got[0], "| rate: 1000000.000000") && strings.HasSuffix(got[1], "| rate: 1000000.000000")
	})
	_, st := call(http.MethodGet, base, "")
	kinds := map[string]int{}
	for _, f := range st["feed"].([]any) {
		kinds[f.(map[string]any)["kind"].(string)]++
	}
	if kinds["added"] != 3 || kinds["replaced"] != 1 || kinds["announced"] < 2 || st["routes_announced"] != float64(2) {
		t.Fatalf("feed = %v, status = %v", kinds, st)
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit %d\n%s", code, logs.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if !strings.Contains(logs.String(), "mitigation routes withdrawn") {
		t.Fatalf("shutdown did not withdraw:\n%s", logs.String())
	}
	waitFor("flowspec gone after shutdown", func() bool { return len(flowSpecOnEdge(t, srv)) == 0 })
}

func TestEventWatchMitigation(t *testing.T) {
	s := &sink{}
	w := newEventWatch(s, "inject")
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	m := plugin.FlowSpecMatch{Protocols: []plugin.IPProtocol{17}}
	r := mitigation.Rule{ID: "r1", Prefix: netip.MustParsePrefix("203.0.113.0/24"), Action: plugin.MitigationFlowSpecRateLimit,
		Match: &m, Countries: []string{"XA"}, RateMbps: 8, Routes: 2, Expires: now.Add(time.Hour), Reason: "flood"}
	w.mitigation([]mitigation.Change{
		{Time: now, Kind: mitigation.ChangeAdded, Mode: "observe", Rule: r},
		{Time: now, Kind: mitigation.ChangeAnnounced, Mode: "inject", Rule: r},
		{Time: now, Kind: mitigation.ChangeWithdrawn, Mode: "inject", Rule: r, Detail: "not in the learned RIB"},
		{Time: now, Kind: mitigation.ChangeExpired, Mode: "inject", Rule: r},
	})
	got := s.take()
	if len(got) != 4 {
		t.Fatalf("events = %+v", got)
	}
	kinds := []string{plugin.EventMitigationAdded, plugin.EventMitigationOn, plugin.EventMitigationOff, plugin.EventMitigationEnded}
	for i, e := range got {
		if e.Kind != kinds[i] || e.Fields["rule"] != "r1" || e.Fields["match"] != "proto=17" || e.Fields["source_countries"] != "XA" ||
			e.Fields["rate_mbps"] != "8" || e.Fields["routes"] != "2" {
			t.Errorf("event %d = %+v", i, e)
		}
	}
	if !strings.Contains(got[0].Message, "dry run") || got[2].Fields["detail"] != "not in the learned RIB" || got[3].Fields["end"] != "expired" {
		t.Fatalf("events = %+v", got)
	}
	var nilW *eventWatch
	nilW.mitigation([]mitigation.Change{{Kind: mitigation.ChangeAdded}}) // no panic
}
