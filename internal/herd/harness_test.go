package herd

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/plugins/storage/sqlite"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var t0 = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

const baseYAML = `
mode: observe
asn: 64512
router_id: 192.0.2.10
storage: {type: sqlite}
bgp:
  neighbors:
    - address: 192.0.2.254
providers:
  - name: transit-a
    source_ip: 192.0.2.11
    next_hop: 192.0.2.1
herd:
  enabled: true
  share:
    classes: [measurements, paths]
  vantage: {country: US}
  listen: 127.0.0.1:0
  key_file: /tmp/unused.key
  peers:
    - url: https://192.0.2.30:9444
      key: ed25519:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
`

func testCfg(t *testing.T, edit func(*config.Herd)) *config.Herd {
	t.Helper()
	cfg, err := config.Parse([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(cfg.Herd)
	}
	return cfg.Herd
}

func testStore(t *testing.T) plugin.HerdStore {
	t.Helper()
	c, err := plugin.ConfigFromYAML("path: " + filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlite.New(c, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Stop(context.Background()) })
	return s
}

func testNode(t *testing.T) *Node {
	t.Helper()
	n, err := LoadNode(filepath.Join(t.TempDir(), "node.key"))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// member is one herd node under test.
type member struct {
	t     *testing.T
	asn   uint32
	cfg   *config.Herd
	node  *Node
	store plugin.HerdStore
	rules *Rules
	rib   *fakeRIB
	trips *Trips
	srv   *Server

	mu     sync.Mutex
	now    time.Time
	audits []Audit
	active bool
}

func (m *member) clock() time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.now
}

func (m *member) setClock(t time.Time) {
	m.mu.Lock()
	m.now = t
	m.mu.Unlock()
}

func (m *member) auditLog() []Audit {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Audit(nil), m.audits...)
}

func defaultRules() *Rules {
	return &Rules{ASNs: map[uint32]bool{}, Sources: map[string]bool{"static": true, "vip": true, "outage": true}}
}

// newMember builds a node with its own store. It does not listen yet.
func newMember(t *testing.T, asn uint32, edit func(*config.Herd)) *member {
	t.Helper()
	m := &member{t: t, asn: asn, cfg: testCfg(t, edit), node: testNode(t), store: testStore(t),
		rules: defaultRules(), rib: &fakeRIB{ready: true, paths: map[netip.Prefix][]uint32{}}, trips: &Trips{}, now: t0, active: true}
	return m
}

// serve starts the pull API for peers, pinned by their nodes.
func (m *member) serve(peers ...*Node) {
	m.t.Helper()
	keys := map[string]ed25519.PublicKey{}
	for _, n := range peers {
		keys[n.ID()] = n.pub
	}
	m.srv = NewServer(ServerOptions{
		Cfg: m.cfg, ASN: m.asn, Node: m.node, Store: m.store, RIB: m.rib, Rules: m.rules, Peers: keys,
		Now: m.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: m.trips,
		Active: func() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.active },
		Audit:  func(a Audit) { m.mu.Lock(); m.audits = append(m.audits, a); m.mu.Unlock() },
	})
	m.cfg.Listen = "127.0.0.1:0"
	if err := m.srv.Start(); err != nil {
		m.t.Fatal(err)
	}
	m.t.Cleanup(m.srv.Stop)
}

func (m *member) url() string { return "https://" + m.srv.Addr().String() }

// peerOf configures c to pull from other, pinning its key.
func peerOf(c *config.Herd, other *member) {
	c.Peers = []config.HerdPeer{{URL: other.url(), Key: other.node.PublicKey()}}
}

// client is an mTLS client with the identity of from, pinned to to.
func client(from *Node, to *member) *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:            tls.VersionTLS13,
			Certificates:          []tls.Certificate{from.cert},
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: pinned(map[string]ed25519.PublicKey{to.node.ID(): to.node.pub}),
		}, DisableKeepAlives: true},
	}
}

func get(t *testing.T, c *http.Client, url string) (int, http.Header, []byte) {
	t.Helper()
	res, err := c.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

// mkRecord builds a valid record of the member's granularity.
func (m *member) mkRecord(id string, origin, provider uint32, prefix string, at time.Time, rtts ...float64) Record {
	r := Record{
		Schema: Schema, ID: id, Granularity: m.cfg.Share.Granularity, OriginASN: origin, ProviderASN: provider,
		Vantage: m.cfg.Vantage.Country, Method: "icmp", Time: at, Sent: len(rtts) + 1,
		ASPath: []uint32{provider, 64500, origin},
	}
	if r.Granularity == config.HerdRoute {
		r.Prefix = prefix
	} else {
		r.Routes = 1
		r.ASPath = nil
		r.ASPaths = [][]uint32{{provider, 64500, origin}}
	}
	for _, v := range rtts {
		r.Samples = append(r.Samples, Sample{Host: 0, RTTMs: v})
	}
	r.setSummary()
	return r
}

// seed stores r as one of the member's own records, behind one route, and
// puts the route in the member's RIB view.
func (m *member) seed(r Record, rt Route) {
	m.t.Helper()
	m.rib.mu.Lock()
	m.rib.paths[rt.Prefix] = rt.Path
	m.rib.mu.Unlock()
	body, _ := json.Marshal(r)
	meta, _ := json.Marshal([]Route{rt})
	hr := plugin.HerdRecord{ID: r.ID, Granularity: r.Granularity, OriginASN: r.OriginASN, ProviderASN: r.ProviderASN, Time: r.Time, Body: body, Meta: meta}
	if r.Prefix != "" {
		hr.Prefix = netip.MustParsePrefix(r.Prefix)
	}
	if _, err := m.store.PutHerdRecords(context.Background(), []plugin.HerdRecord{hr}); err != nil {
		m.t.Fatal(err)
	}
}

func route(prefix string, path ...uint32) Route {
	return Route{Prefix: netip.MustParsePrefix(prefix), Provider: "transit-a", Path: path, Sources: []string{"static"}}
}

func (m *member) seedN(n int, origin uint32) {
	for i := range n {
		m.seed(m.mkRecord(fmt.Sprintf("r%04d", i), origin, 64501, "198.51.100.0/24", t0.Add(-time.Duration(i)*time.Minute), 10, 11, 12),
			route("198.51.100.0/24", 64501, 64500, origin))
	}
}
