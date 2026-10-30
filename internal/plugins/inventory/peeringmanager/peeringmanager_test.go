package peeringmanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const asJSON = `{"count": 5, "next": null, "previous": null, "results": [
 {"asn": 64496, "name": "Transit A", "tags": [{"slug": "packeteer", "name": "Packeteer"}],
  "local_context_data": {"packeteer": {"type": "transit", "source_ip": "192.0.2.10", "next_hop": "192.0.2.1", "communities": ["64496:100", "64496:1:2"]}}},
 {"asn": 64497, "name": "Peer B", "tags": ["packeteer", "other"], "local_context_data": {"packeteer": {"next_hop": "198.51.100.1"}}},
 {"asn": 64498, "name": "Untagged", "tags": [{"slug": "other"}], "local_context_data": {"packeteer": {"next_hop": "198.51.100.2"}}},
 {"asn": 64499, "name": "No Context", "tags": [{"name": "packeteer"}], "local_context_data": null},
 {"asn": 64500, "name": "Bad Hop", "tags": [{"slug": "packeteer"}], "local_context_data": {"packeteer": {"next_hop": "nope"}}}
]}`

func TestFetchKeepsTaggedAutonomousSystems(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		_, _ = w.Write([]byte(asJSON))
	}))
	defer srv.Close()
	c, err := plugin.ConfigFromYAML("base_url: " + srv.URL + "\ntag: packeteer\n")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := New(c, plugin.Env{Getenv: func(k string) string {
		if k == TokenEnv {
			return "lab-token"
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := inv.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Token lab-token" || gotPath != "/api/peering/autonomous-systems/" || gotMethod != http.MethodGet {
		t.Fatalf("request %s %s auth %q", gotMethod, gotPath, gotAuth)
	}
	var names []string
	for _, p := range res.Providers {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"no-context", "peer-b", "transit-a"}) {
		t.Fatalf("providers %v", names)
	}
	a := res.Providers[2]
	if a.ASN != 64496 || a.Type != "transit" || a.SourceIP != "192.0.2.10" || a.NextHop != "192.0.2.1" || !slices.Equal(a.Communities, []string{"64496:100", "64496:1:2"}) {
		t.Fatalf("transit-a %+v", a)
	}
	if nc := res.Providers[0]; nc.ASN != 64499 || nc.NextHop != "" {
		t.Fatalf("no-context %+v", nc)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Name != "bad-hop" || !strings.Contains(res.Skipped[0].Reason, "next_hop") {
		t.Fatalf("skipped %+v", res.Skipped)
	}
}

func TestNewNeedsTokenAndTag(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, token, want string }{
		"no token": {"base_url: http://127.0.0.1:1\ntag: t\n", "", TokenEnv},
		"no tag":   {"base_url: http://127.0.0.1:1\n", "lab-token", "tag is required"},
	} {
		c, err := plugin.ConfigFromYAML(tc.yaml)
		if err != nil {
			t.Fatal(err)
		}
		_, err = New(c, plugin.Env{Getenv: func(string) string { return tc.token }})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
	if !plugin.Inventories.Has(TypeName) {
		t.Fatal("peeringmanager is not registered")
	}
}
