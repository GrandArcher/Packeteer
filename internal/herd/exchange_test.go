package herd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newExchange(self *Node, selfASN uint32, max int, agrees func(Entry) bool) (*Exchange, *Trips) {
	trips := &Trips{}
	return NewExchange(ExchangeOptions{
		Max: max, Self: self.ID(), SelfASN: selfASN, Skip: func(string, string) bool { return false },
		Agrees: agrees, Life: time.Hour, Trips: trips, Log: quietLog(),
	}), trips
}

func relayed(docs ...[]byte) []Relayed {
	out := make([]Relayed, len(docs))
	for i, d := range docs {
		out[i] = Relayed{Entry: d}
	}
	return out
}

// A relayer can withhold entries but not forge them: every relayed entry
// is checked like a hub entry, and a tampered, expired, oversized, or
// pin-breaking one is refused.
func TestExchangeRefusesTamperedExpiredOversizedAndPinBreakingEntries(t *testing.T) {
	self := testNode(t)
	own := signed(t, self, func() Entry { e := testEntry(self); e.ASN = 64500; return e }())
	_, a := entryFor(t, 64501, "https://192.0.2.31:9444")
	_, b := entryFor(t, 64502, "https://192.0.2.32:9444")
	tampered := []byte(strings.Replace(string(b), "192.0.2.32", "192.0.2.39", 1))
	_, expired := entryFor(t, 64503, "https://192.0.2.33:9444", func(e *Entry) { e.Expires = t0.Add(time.Minute) })
	oversized := []byte(strings.Replace(string(a), `"schema"`, `"pad":"`+strings.Repeat("x", MaxEntryBytes)+`","schema"`, 1))
	_, pinned := entryFor(t, 64504, "https://192.0.2.34:9444")

	x, _ := newExchange(self, 64500, 8, func(e Entry) bool { return e.ASN != 64504 })
	refused := x.Offer("relayer", relayed(own, a, b, tampered, expired, oversized, pinned), t0.Add(time.Hour))
	if refused != 4 {
		t.Errorf("refused %d entries, want 4 (tampered, expired, oversized, pinned elsewhere)", refused)
	}
	peers := x.Peers(t0.Add(time.Hour))
	got := map[uint32]HubPeer{}
	for _, p := range peers {
		got[p.ASN] = p
	}
	if len(peers) != 2 || got[64501].URL != "https://192.0.2.31:9444" || got[64502].URL != "https://192.0.2.32:9444" {
		t.Fatalf("peers = %+v, want 64501 and 64502 at their own urls", peers)
	}
	for _, p := range peers {
		if p.Source != SourceExchange {
			t.Errorf("source %q", p.Source)
		}
		if _, err := CheckEntry(p.Entry, t0.Add(time.Hour)); err != nil {
			t.Errorf("the entry kept for relaying does not verify: %v", err)
		}
	}
}

func TestExchangeKeepsOneEntryPerASNCapsAndAgesOut(t *testing.T) {
	self := testNode(t)
	n1, first := entryFor(t, 64501, "https://192.0.2.31:9444")
	_, stranger := entryFor(t, 64501, "https://192.0.2.39:9444", func(e *Entry) { e.Issued = t0.Add(time.Minute) })
	rotated := signed(t, n1, func() Entry {
		e := testEntry(n1)
		e.Issued = t0.Add(2 * time.Minute)
		e.Nodes[0].URL = "https://192.0.2.41:9444"
		return e
	}())
	_, second := entryFor(t, 64502, "https://192.0.2.32:9444")
	_, third := entryFor(t, 64503, "https://192.0.2.33:9444")

	x, trips := newExchange(self, 64500, 2, nil)
	now := t0.Add(time.Hour)
	if n := x.Offer("r1", relayed(first, stranger), now); n != 1 {
		t.Errorf("an entry for a known ASN signed by an unrelated key: refused %d, want 1", n)
	}
	x.Offer("r1", relayed(rotated, second, third), now)
	peers := x.Peers(now)
	urls := map[uint32]string{}
	for _, p := range peers {
		urls[p.ASN] = p.URL
	}
	if len(peers) != 2 || urls[64501] != "https://192.0.2.41:9444" || urls[64502] == "" {
		t.Errorf("peers = %+v, want the rotated 64501 entry and 64502 only", peers)
	}
	if !hasTrip(trips, "exchange_peers") {
		t.Errorf("the exchange_peers cap did not trip: %+v", trips.Snapshot())
	}
	// 64502 is listed again later, reached 10 minutes before; 64501 is not
	// and ages out. A relay of an old contact does not refresh an entry.
	x.Offer("r2", []Relayed{{Entry: second, AgeSeconds: 600}}, now.Add(50*time.Minute))
	x.Offer("r3", []Relayed{{Entry: rotated, AgeSeconds: 3000}}, now.Add(50*time.Minute))
	if peers = x.Peers(now.Add(70 * time.Minute)); len(peers) != 1 || peers[0].ASN != 64502 {
		t.Errorf("after an hour without a fresh relay: %+v, want only 64502", peers)
	}
	if peers = x.Peers(now.Add(101 * time.Minute)); len(peers) != 0 {
		t.Errorf("64502 was last reached 91 minutes ago: %+v, want none", peers)
	}
}

// For an ASN the hub does not pin, an unverified entry that was relayed
// first cannot keep the verified member out.
func TestExchangeVerifiedEntryReplacesAnUnverifiedOne(t *testing.T) {
	self := testNode(t)
	_, squat := entryFor(t, 64501, "https://192.0.2.39:9444")
	owner, real := entryFor(t, 64501, "https://192.0.2.31:9444")
	_, other := entryFor(t, 64501, "https://192.0.2.40:9444")
	x := NewExchange(ExchangeOptions{
		Max: 4, Self: self.ID(), SelfASN: 64500, Skip: func(string, string) bool { return false }, Life: time.Hour,
		Verified: func(asn uint32, id string) bool { return asn == 64501 && id == owner.ID() }, Trips: &Trips{}, Log: quietLog(),
	})
	now := t0.Add(time.Hour)
	if n := x.Offer("r1", relayed(squat, real), now); n != 0 {
		t.Errorf("refused %d, want the verified entry to replace the squatter", n)
	}
	if n := x.Offer("r1", relayed(other), now); n != 1 {
		t.Errorf("an unverified entry replaced a verified one (refused %d)", n)
	}
	if peers := x.Peers(now); len(peers) != 1 || peers[0].URL != "https://192.0.2.31:9444" {
		t.Errorf("peers = %+v, want the verified member", peers)
	}
}

func hasTrip(tr *Trips, limit string) bool {
	for _, c := range tr.Snapshot() {
		if c.Limit == limit {
			return true
		}
	}
	return false
}

// exchanger is one member's side of peer exchange in a test: its puller
// learns from the peer lists it reads and its server accepts what it
// learned. at maps a key id to the loopback address the member listens on,
// since a relayed entry may not name a loopback address. hub is the seed,
// which is a hub peer and so never learned again by exchange.
type exchanger struct {
	m    *member
	x    *Exchange
	pull *Puller
}

func newExchanger(t *testing.T, m *member, at map[string]string, hub *Node) *exchanger {
	t.Helper()
	e := &exchanger{m: m}
	m.exch = &KeySet{}
	e.x = NewExchange(ExchangeOptions{
		Max: 8, Self: m.node.ID(), SelfASN: m.asn, Skip: func(id, _ string) bool { return id == hub.ID() },
		Life: time.Hour, Trips: m.trips, Log: quietLog(),
	})
	m.cfg.Peers = nil
	p, err := NewPuller(PullerOptions{
		Cfg: m.cfg, Node: m.node, Store: m.store, Origins: func() []uint32 { return []uint32{64510} },
		Now: m.clock, Log: quietLog(), Trips: m.trips, Jitter: func() float64 { return 1 }, Exchange: e.x,
		Learned: func() {
			peers := e.x.Peers(m.clock())
			for i := range peers {
				peers[i].URL = at[KeyID(peers[i].Key)]
			}
			e.pull.SetExchange(peers)
			m.exch.Set(peers)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.hubDial = nil
	t.Cleanup(p.Close)
	e.pull = p
	m.relay = func() []Relayed { return p.Relay(m.clock(), time.Hour) }
	return e
}

// Members that know only a seed find each other from the seed's peer
// list, refuse the bad entries in it, pull each other, and relay each
// other's entries in turn.
func TestMembersFindEachOtherByPeerExchangeFromASeed(t *testing.T) {
	seed := newMember(t, 64499, nil)
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	at := map[string]string{}
	ea, eb := newExchanger(t, a, at, seed.node), newExchanger(t, b, at, seed.node)
	a.serve()
	b.serve()
	a.seedN(2, 64510)
	b.seedN(3, 64510)
	at[a.node.ID()], at[b.node.ID()] = a.url(), b.url()

	entryAt := func(m *member) []byte {
		e := testEntry(m.node)
		e.ASN, e.Nodes[0].URL = m.asn, "https://192.0.2."+map[uint32]string{64501: "31", 64502: "32", 64499: "20"}[m.asn]+":9444"
		return signed(t, m.node, e)
	}
	ra, rb, rs := entryAt(a), entryAt(b), entryAt(seed)
	tampered := []byte(strings.Replace(string(rb), "192.0.2.32", "192.0.2.39", 1))
	seed.relay = func() []Relayed { return relayed(ra, rb, tampered) }
	seed.serve(a.node, b.node)
	at[seed.node.ID()] = seed.url()
	now := t0.Add(time.Hour)
	for _, m := range []*member{seed, a, b} {
		m.setClock(now)
	}
	hub := []HubPeer{{URL: seed.url(), Key: seed.node.pub, ASN: 64499, Source: SourceHub, Entry: rs}}
	ea.pull.SetHub(hub)
	eb.pull.SetHub(hub)

	for range 2 {
		ea.pull.Round(context.Background())
		eb.pull.Round(context.Background())
	}

	for _, tc := range []struct {
		e     *exchanger
		other *member
	}{{ea, b}, {eb, a}} {
		st := map[string]PeerStatus{}
		for _, p := range tc.e.pull.Peers() {
			st[p.Source] = p
		}
		if s := st[SourceHub]; s.Relayed != 3 || s.RelayRefused != 1 || s.Failures != 0 {
			t.Errorf("AS%d seed peer = %+v, want 3 relayed, 1 refused", tc.e.m.asn, s)
		}
		if s := st[SourceExchange]; s.ASN != tc.other.asn || s.Failures != 0 || s.LastOK.IsZero() || s.Pulled == 0 {
			t.Errorf("AS%d exchange peer = %+v, want AS%d pulled without failures", tc.e.m.asn, s, tc.other.asn)
		}
		if rows := pulledRows(t, tc.e.m, tc.other.node); len(rows) == 0 {
			t.Errorf("AS%d pulled nothing from AS%d", tc.e.m.asn, tc.other.asn)
		}
	}

	// a relays the seed's and b's entries, as signed by them.
	if code, _, body := tryGet(client(testNode(t), a), a.url()+PathPeers); code != 0 {
		t.Fatalf("an unknown key read a's peer list: %d %s", code, body)
	}
	code, _, body := get(t, client(b.node, a), a.url()+PathPeers)
	if code != http.StatusOK || verifyDocument(a.node.pub, body) != nil {
		t.Fatalf("peer list: %d %s", code, body)
	}
	var l PeerList
	if err := json.Unmarshal(body, &l); err != nil {
		t.Fatal(err)
	}
	asns := map[uint32]bool{}
	for _, r := range l.Entries {
		e, err := CheckEntry(r.Entry, now)
		if err != nil {
			t.Errorf("relayed entry does not verify: %v", err)
		}
		asns[e.ASN] = true
	}
	if len(l.Entries) != 2 || !asns[64499] || !asns[64502] {
		t.Errorf("a relays %+v, want the seed's and b's entries", asns)
	}
	if code, _, _ := get(t, client(b.node, a), a.url()+PathPeers+"?x=1"); code != http.StatusBadRequest {
		t.Errorf("peer list with a parameter: %d, want 400", code)
	}
}

// With herd.hub a node runs peer exchange: learned peers are pulled and
// may connect, a hub or static peer is never learned again, and the peer
// list is served. herd.identity adds the identity source.
func TestHerdWiresExchangeAndIdentity(t *testing.T) {
	cfg := testCfg(t, func(c *config.Herd) {
		c.KeyFile = filepath.Join(t.TempDir(), "node.key")
		c.Hub = &config.HerdHub{URL: "https://127.0.0.1:1/herd.json", Refresh: time.Hour, MaxPeers: 16, ExchangePeers: 4}
		c.Identity = &config.HerdIdentity{URL: "https://127.0.0.1:1/rsc.json", Refresh: time.Hour}
	})
	h, err := New(Options{Cfg: cfg, ASN: 64496, Store: testStore(t), RIB: &fakeRIB{ready: true}, Rules: defaultRules(), Now: func() time.Time { return t0 }, Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	if h.exch == nil || h.srv.o.Relay == nil || h.ids == nil {
		t.Fatal("exchange or identity not wired")
	}
	hubPeer, hubRaw := entryFor(t, 64501, "https://192.0.2.31:9444")
	h.hub.o.Snapshot = listOf(t, hubRaw)
	h.hub.Refresh(context.Background())

	learned, raw := entryFor(t, 64502, "https://192.0.2.32:9444")
	_, static := entryFor(t, 64503, cfg.Peers[0].URL)
	h.exch.Offer("relayer", relayed(raw, hubRaw, static), t0)
	h.applyExchange()
	src := map[string]string{}
	for _, p := range h.pull.Peers() {
		src[p.KeyID] = p.Source
	}
	if len(src) != 3 || src[learned.ID()] != SourceExchange || src[hubPeer.ID()] != SourceSnapshot {
		t.Errorf("peers by source = %v, want the static, the hub, and one exchange peer", src)
	}
	if !h.srv.o.Exchange.Has(learned.ID()) || h.srv.o.Exchange.Has(hubPeer.ID()) {
		t.Error("the learned key must be accepted by the pull API as an exchange key, the hub key only as a hub key")
	}
	st := h.Status(context.Background())
	if st.Identity == nil || st.CrowdK != cfg.Share.CrowdK || st.Verified {
		t.Errorf("status identity %+v crowd_k %d verified %v", st.Identity, st.CrowdK, st.Verified)
	}
}
