package herd

import (
	"context"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// At route level a route that only flow listed is held back until crowd_k
// other verified members serve it; a static route is served at once.
func TestCrowdThresholdHoldsOnlyUserDerivedRoutes(t *testing.T) {
	m := newMember(t, 64501, func(c *config.Herd) {
		c.Share.Granularity = config.HerdRoute
		c.Share.Sources = []string{"static", "flow"}
	})
	m.rules.Sources["flow"] = true
	crowd := 0
	m.crowd = func(p netip.Prefix) int {
		if p != netip.MustParsePrefix("198.51.100.0/24") {
			t.Errorf("crowd asked about %s", p)
		}
		return crowd
	}
	m.serve()
	flowRoute := Route{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Provider: "transit-a", Path: []uint32{64501, 64510}, Sources: []string{"flow"}}
	both := Route{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Provider: "transit-a", Path: []uint32{64501, 64511}, Sources: []string{"static", "flow"}}
	m.seed(m.mkRecord("f1", 64510, 64501, "198.51.100.0/24", t0.Add(-time.Minute), 10, 11), flowRoute)
	m.seed(m.mkRecord("s1", 64511, 64501, "203.0.113.0/24", t0.Add(-time.Minute), 10, 11), both)

	served := func(q string) int {
		code, body := m.srv.Preview(q)
		var env Envelope
		if code != 200 || json.Unmarshal(body, &env) != nil {
			t.Fatalf("preview %s: %d %s", q, code, body)
		}
		return len(env.Records)
	}
	for _, c := range []struct {
		crowd, flow int
	}{{0, 0}, {1, 0}, {2, 1}} {
		crowd = c.crowd
		if got := served("prefix=198.51.100.0/24"); got != c.flow {
			t.Errorf("crowd %d of k=2: flow route served %d records, want %d", c.crowd, got, c.flow)
		}
		if got := served("prefix=203.0.113.0/24"); got != 1 {
			t.Errorf("crowd %d: a route static also listed must not wait for the crowd (served %d)", c.crowd, got)
		}
	}
}

// Only verified peers count, once per ASN, never this node's own ASN, and
// only for a record of exactly that route.
func TestCrowdCountIsVerifiedDistinctOtherASNsForTheExactRoute(t *testing.T) {
	st := testStore(t)
	p := netip.MustParsePrefix("198.51.100.0/24")
	put := func(member, prefix string) {
		rec := plugin.HerdRecord{Member: member, ID: member + prefix, Granularity: config.HerdRoute, Prefix: netip.MustParsePrefix(prefix), OriginASN: 64510, ProviderASN: 64501, Time: t0, Body: []byte(`{}`)}
		if _, err := st.PutHerdRecords(context.Background(), []plugin.HerdRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	peers := []PeerStatus{
		{KeyID: "k1", ASN: 65537, Verified: true},
		{KeyID: "k2", ASN: 65537, Verified: true},
		{KeyID: "k3", ASN: 65538},
		{KeyID: "k4", ASN: 64500, Verified: true},
		{KeyID: "k5", ASN: 65539, Verified: true},
		{KeyID: "k6", ASN: 65540, Verified: true},
	}
	for _, k := range []string{"k1", "k2", "k3", "k4", "k5"} {
		put(k, "198.51.100.0/24")
	}
	put("k6", "198.51.100.0/23")
	if n := crowdCount(context.Background(), st, peers, 64500, p, t0.Add(-time.Hour)); n != 2 {
		t.Errorf("crowd = %d, want 2 (AS65537 once and AS65539)", n)
	}
	if n := crowdCount(context.Background(), st, peers, 64500, p, t0.Add(time.Hour)); n != 0 {
		t.Errorf("crowd before floor = %d, want 0", n)
	}
}

// The crowd count reads verification live and is kept for one pull
// interval.
func TestHerdCrowdReadsVerificationLiveAndCachesAPullInterval(t *testing.T) {
	now := t0
	cfg := testCfg(t, func(c *config.Herd) {
		c.KeyFile = filepath.Join(t.TempDir(), "node.key")
		c.Identity = &config.HerdIdentity{URL: "https://127.0.0.1:1/rsc.json", Refresh: time.Hour}
	})
	st := testStore(t)
	h, err := New(Options{Cfg: cfg, ASN: 64496, Store: st, RIB: &fakeRIB{ready: true}, Rules: defaultRules(), Now: func() time.Time { return now }, Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	pe := h.pull.list()[0]
	pe.st.ASN = 64502
	p := netip.MustParsePrefix("198.51.100.0/24")
	rec := plugin.HerdRecord{Member: pe.id, ID: "x", Granularity: config.HerdRoute, Prefix: p, OriginASN: 64510, ProviderASN: 64501, Time: t0, Body: []byte(`{}`)}
	if _, err := st.PutHerdRecords(context.Background(), []plugin.HerdRecord{rec}); err != nil {
		t.Fatal(err)
	}
	if n := h.crowd(p); n != 0 {
		t.Fatalf("crowd before verification = %d", n)
	}
	h.crowdAt = map[netip.Prefix]crowdEntry{}
	h.ids.set = map[binding]time.Time{{64502, pe.id}: t0.Add(time.Hour)}
	if n := h.crowd(p); n != 1 {
		t.Fatalf("crowd of one verified peer = %d", n)
	}
	h.ids.set = nil
	if n := h.crowd(p); n != 1 {
		t.Errorf("crowd within the pull interval = %d, want the kept 1", n)
	}
	now = now.Add(cfg.Limits.PullInterval)
	if n := h.crowd(p); n != 0 {
		t.Errorf("crowd after the peer's binding went and the interval passed = %d, want 0", n)
	}
	if h.Status(context.Background()).Peers[0].Verified {
		t.Error("status still shows the peer verified")
	}
}
