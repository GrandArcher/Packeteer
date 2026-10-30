package netbox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

const providersJSON = `{"count": 5, "next": null, "previous": null, "results": [
 {"name": "Transit A", "slug": "transit-a", "asns": [{"asn": 64497}, {"asn": 64496}],
  "custom_fields": {"packeteer_type": "transit", "packeteer_source_ip": "192.0.2.10", "packeteer_next_hop": "192.0.2.1",
                    "packeteer_communities": "64496:100,64496:200", "other_field": "ignored"}},
 {"name": "Peer B", "slug": "peer-b", "asns": [], "custom_fields": {"packeteer_next_hop": "198.51.100.1", "packeteer_communities": ["64496:7"]}},
 {"name": "Broken", "slug": "broken", "asns": [{"asn": 64498}], "custom_fields": {"packeteer_next_hop": "not-an-ip"}},
 {"name": "Odd Name!", "slug": "bad slug", "asns": [], "custom_fields": null},
 {"name": "!!!", "slug": "", "asns": [], "custom_fields": {}}
]}`

func newPlugin(t *testing.T, base, token string) plugin.Inventory {
	t.Helper()
	c, err := plugin.ConfigFromYAML("base_url: " + base + "\ntag: packeteer\n")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := New(c, plugin.Env{Getenv: func(k string) string {
		if k == TokenEnv {
			return token
		}
		return ""
	}})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestFetchReadsTaggedProvidersFromCustomFields(t *testing.T) {
	var gotAuth, gotTag, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotTag, gotPath, gotMethod = r.Header.Get("Authorization"), r.URL.Query().Get("tag"), r.URL.Path, r.Method
		_, _ = w.Write([]byte(providersJSON))
	}))
	defer srv.Close()
	res, err := newPlugin(t, srv.URL, "lab-token").Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Token lab-token" || gotTag != "packeteer" || gotPath != "/api/circuits/providers/" || gotMethod != http.MethodGet {
		t.Fatalf("request: %s %q tag %q auth %q", gotMethod, gotPath, gotTag, gotAuth)
	}
	if len(res.Providers) != 3 {
		t.Fatalf("providers %+v", res.Providers)
	}
	a := find(t, res, "transit-a")
	if a.ASN != 64496 || a.Type != "transit" || a.SourceIP != "192.0.2.10" || a.NextHop != "192.0.2.1" || !slices.Equal(a.Communities, []string{"64496:100", "64496:200"}) {
		t.Fatalf("transit-a %+v", a)
	}
	b := find(t, res, "peer-b")
	if b.ASN != 0 || b.NextHop != "198.51.100.1" || !slices.Equal(b.Communities, []string{"64496:7"}) {
		t.Fatalf("peer-b %+v", b)
	}
	// "bad slug" is not a valid name, so the name slug is used.
	find(t, res, "odd-name")
	var skipped []string
	for _, s := range res.Skipped {
		skipped = append(skipped, s.Name+": "+s.Reason)
	}
	if len(skipped) != 2 || !strings.Contains(strings.Join(skipped, "|"), "broken: next_hop") || !strings.Contains(strings.Join(skipped, "|"), "!!!: no usable name") {
		t.Fatalf("skipped %v", skipped)
	}
}

func TestV2TokenUsesBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{"count": 0, "next": nil, "results": []any{}})
	}))
	defer srv.Close()
	if _, err := newPlugin(t, srv.URL, "nbt_lab.token").Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer nbt_lab.token" {
		t.Fatalf("auth %q", gotAuth)
	}
}

func TestFetchErrorDoesNotLeakTheToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := newPlugin(t, srv.URL, "lab-token").Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "lab-token") {
		t.Fatalf("err %v", err)
	}
}

func TestNewChecksTheConfigAndFetchNeedsTheToken(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"unknown key": {"base_url: http://127.0.0.1:1\ntag: t\nwrite: true\n", "write"},
		"no tag":      {"base_url: http://127.0.0.1:1\n", "tag is required"},
	} {
		c, err := plugin.ConfigFromYAML(tc.yaml)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = New(c, plugin.Env{}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
	// The controller loads the config without the token; only Fetch reads it.
	inv := newPlugin(t, "http://127.0.0.1:1", "")
	if _, err := inv.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), TokenEnv) {
		t.Fatalf("fetch without a token: %v", err)
	}
	if !plugin.Inventories.Has(TypeName) {
		t.Fatal("netbox is not registered")
	}
}

func find(t *testing.T, res plugin.InventoryResult, name string) plugin.InventoryProvider {
	t.Helper()
	for _, p := range res.Providers {
		if p.Name == name {
			return p
		}
	}
	t.Fatalf("no %s in %+v", name, res.Providers)
	return plugin.InventoryProvider{}
}
