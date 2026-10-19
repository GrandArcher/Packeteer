package herd

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// entryFor is a signed entry of asn at url, made by a fresh node.
func entryFor(t *testing.T, asn uint32, url string, edit ...func(*Entry)) (*Node, []byte) {
	t.Helper()
	n := testNode(t)
	e := testEntry(n)
	e.ASN, e.Nodes[0].URL = asn, url
	for _, f := range edit {
		f(&e)
	}
	return n, signed(t, n, e)
}

func listOf(t *testing.T, entries ...[]byte) []byte {
	t.Helper()
	b, err := BuildHubList(entries, t0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseHubListKeepsOnlyVerifiedEntries(t *testing.T) {
	_, good := entryFor(t, 64501, "https://192.0.2.31:9444")
	_, forged := entryFor(t, 64502, "https://192.0.2.32:9444")
	forged = []byte(strings.Replace(string(forged), "64502", "64509", 1))
	_, expired := entryFor(t, 64503, "https://192.0.2.33:9444", func(e *Entry) { e.Expires = t0.Add(time.Minute) })

	entries, rejected, err := ParseHubList(listOf(t, good, forged, expired, []byte(`{"junk":1}`)), t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ASN != 64501 || rejected != 3 {
		t.Errorf("entries = %+v, rejected = %d; want only 64501 and 3 rejected", entries, rejected)
	}
}

func TestParseHubListRefusals(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":     "<html>",
		"wrong schema": `{"schema":"other/1","entries":[]}`,
		"oversized":    `{"schema":"` + HubSchema + `","entries":[],"pad":"` + strings.Repeat("x", MaxHubBytes) + `"}`,
	} {
		if _, _, err := ParseHubList([]byte(raw), t0); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var l HubList
	l.Schema = HubSchema
	l.Entries = make([]json.RawMessage, MaxHubEntries+1)
	for i := range l.Entries {
		l.Entries[i] = json.RawMessage("{}")
	}
	raw, _ := json.Marshal(l)
	if _, _, err := ParseHubList(raw, t0); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("too many entries: %v", err)
	}
	if _, _, err := ParseHubList(snapshot, t0); err != nil {
		t.Errorf("built-in snapshot: %v", err)
	}
}

// TestBuiltInSnapshotIsCurrent is the release gate of make hub-snapshot: the
// file about to ship must have no entry that is rejected or expired now. It
// is skipped in normal runs because a committed snapshot ages.
func TestBuiltInSnapshotIsCurrent(t *testing.T) {
	if os.Getenv("HUB_SNAPSHOT_CHECK") == "" {
		t.Skip("run by make hub-snapshot")
	}
	entries, rejected, err := ParseHubList(snapshot, time.Now())
	if err != nil || rejected != 0 {
		t.Fatalf("snapshot: %d entries, %d rejected, err %v", len(entries), rejected, err)
	}
}

func entryOf(t *testing.T, n *Node, asn uint32, url string, issued time.Time) Entry {
	t.Helper()
	e := testEntry(n)
	e.ASN, e.Nodes[0].URL, e.Issued, e.Expires = asn, url, issued, issued.Add(24*time.Hour)
	e.Signer = n.PublicKey()
	return e
}

func TestSelectPeers(t *testing.T) {
	self, a, b, a2, c := testNode(t), testNode(t), testNode(t), testNode(t), testNode(t)
	none := func(string, string) bool { return false }
	entries := []Entry{
		entryOf(t, a, 64501, "https://192.0.2.31:9444", t0),
		entryOf(t, a2, 64501, "https://192.0.2.32:9444", t0.Add(time.Hour)), // newer entry of the same ASN
		entryOf(t, b, 64502, "https://192.0.2.33:9444", t0),
		entryOf(t, self, 64599, "https://192.0.2.34:9444", t0), // this node's own entry
		entryOf(t, c, 64512, "https://192.0.2.35:9444", t0),    // this node's own ASN
	}

	got := selectPeers(entries, self.ID(), 64512, none, 16, SourceHub)
	asns := map[uint32]string{}
	for _, p := range got {
		asns[p.ASN] = p.URL
		if p.Source != SourceHub {
			t.Errorf("source = %q", p.Source)
		}
	}
	if len(got) != 2 || asns[64501] != "https://192.0.2.32:9444" || asns[64502] == "" {
		t.Errorf("selected %+v; want the newest 64501 entry and 64502, not self, not our ASN", got)
	}

	t.Run("skip and cap", func(t *testing.T) {
		got := selectPeers(entries, self.ID(), 64512, func(id, _ string) bool { return id == b.ID() }, 16, SourceHub)
		if len(got) != 1 || got[0].ASN != 64501 {
			t.Errorf("skip: %+v", got)
		}
		if got := selectPeers(entries, self.ID(), 64512, none, 1, SourceHub); len(got) != 1 {
			t.Errorf("cap: %+v", got)
		}
	})

	t.Run("a key is used once", func(t *testing.T) {
		dup := entryOf(t, a, 64530, "https://192.0.2.36:9444", t0) // a's key under another ASN
		got := selectPeers([]Entry{entries[0], dup}, self.ID(), 64512, none, 16, SourceHub)
		if len(got) != 1 {
			t.Errorf("selected %+v, want the key once", got)
		}
	})

	t.Run("a full cap differs between members", func(t *testing.T) {
		var many []Entry
		for i := range 40 {
			many = append(many, entryOf(t, testNode(t), uint32(65000+i), "https://192.0.2.40:9444", t0))
			many[i].Nodes[0].URL = "https://192.0.2.40:" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + "00"
		}
		first := func(n *Node) uint32 { return selectPeers(many, n.ID(), 64512, none, 1, SourceHub)[0].ASN }
		seen := map[uint32]bool{}
		for range 8 {
			seen[first(testNode(t))] = true
		}
		if len(seen) < 3 {
			t.Errorf("8 members picked only %d distinct first peers out of 40", len(seen))
		}
		n := testNode(t)
		if a, b := first(n), first(n); a != b {
			t.Errorf("the choice is not stable for one member: %d then %d", a, b)
		}
	})
}

func TestKeySet(t *testing.T) {
	var nilSet *KeySet
	if nilSet.Has("x") {
		t.Error("nil set has a key")
	}
	n := testNode(t)
	k := &KeySet{}
	k.Set([]HubPeer{{Key: n.pub}})
	if !k.Has(n.ID()) || k.Has("other") {
		t.Error("set contents wrong")
	}
	k.Set(nil)
	if k.Has(n.ID()) {
		t.Error("Set does not replace")
	}
}

// hubServer serves body, or status when set.
type hubServer struct {
	*httptest.Server
	mu     sync.Mutex
	body   []byte
	status int
}

func newHubServer(t *testing.T, body []byte) *hubServer {
	h := &hubServer{body: body, status: 200}
	h.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.status != 200 {
			http.Error(w, "no", h.status)
			return
		}
		_, _ = w.Write(h.body)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hubServer) set(body []byte, status int) {
	h.mu.Lock()
	h.body, h.status = body, status
	h.mu.Unlock()
}

type applied struct {
	mu    sync.Mutex
	peers []HubPeer
}

func (a *applied) apply(p []HubPeer) { a.mu.Lock(); a.peers = p; a.mu.Unlock() }
func (a *applied) get() []HubPeer    { a.mu.Lock(); defer a.mu.Unlock(); return a.peers }

func testHub(t *testing.T, srv *hubServer, snap []byte, clock *time.Time) (*Hub, *applied) {
	t.Helper()
	ap := &applied{}
	self := testNode(t)
	h := NewHub(HubOptions{
		Cfg:  &config.HerdHub{URL: srv.URL, Refresh: time.Hour, MaxPeers: 16},
		Self: self.ID(), ASN: 64512, Skip: func(string, string) bool { return false },
		Apply: ap.apply, Client: srv.Client(), Snapshot: snap,
		Now: func() time.Time { return *clock }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return h, ap
}

func TestStatusURLDropsWhatMayHoldASecret(t *testing.T) {
	if got := statusURL("https://user:pw@hub.example.net:8443/herd.json?token=s3cret#frag"); got != "https://hub.example.net:8443/herd.json" {
		t.Errorf("statusURL = %q", got)
	}
}

func TestHubRefreshAppliesVerifiedPeers(t *testing.T) {
	_, e1 := entryFor(t, 64501, "https://192.0.2.31:9444")
	_, e2 := entryFor(t, 64502, "https://192.0.2.32:9444", func(e *Entry) { e.RetentionDays = 7 }) // invalid
	srv := newHubServer(t, listOf(t, e1, e2))
	clock := t0.Add(time.Hour)
	h, ap := testHub(t, srv, nil, &clock)

	h.Refresh(context.Background())

	got := ap.get()
	st := h.Status()
	if len(got) != 1 || got[0].ASN != 64501 || got[0].Source != SourceHub {
		t.Fatalf("applied %+v", got)
	}
	if st.Source != SourceHub || st.Listed != 1 || st.Rejected != 1 || st.Peers != 1 || st.LastError != "" || !st.FetchedAt.Equal(clock) || st.URL != srv.URL {
		t.Errorf("status = %+v", st)
	}
}

func TestHubFallsBackToTheSnapshotOnlyBeforeTheFirstSuccess(t *testing.T) {
	_, snapEntry := entryFor(t, 64540, "https://192.0.2.41:9444")
	_, live := entryFor(t, 64501, "https://192.0.2.31:9444")
	srv := newHubServer(t, nil)
	srv.set(nil, 503)
	clock := t0.Add(time.Hour)
	h, ap := testHub(t, srv, listOf(t, snapEntry), &clock)

	h.Refresh(context.Background())
	if got := ap.get(); len(got) != 1 || got[0].ASN != 64540 || got[0].Source != SourceSnapshot {
		t.Fatalf("snapshot not used: %+v", got)
	}
	if st := h.Status(); st.Source != SourceSnapshot || !strings.Contains(st.LastError, "503") {
		t.Errorf("status = %+v", st)
	}

	srv.set(listOf(t, live), 200)
	h.Refresh(context.Background())
	if got := ap.get(); len(got) != 1 || got[0].ASN != 64501 || got[0].Source != SourceHub {
		t.Fatalf("hub list not used: %+v", got)
	}

	// After a success the snapshot is never used again; a failed refresh
	// keeps the last list.
	srv.set(nil, 500)
	h.Refresh(context.Background())
	if got := ap.get(); len(got) != 1 || got[0].ASN != 64501 {
		t.Errorf("after a failure: %+v", got)
	}
	if st := h.Status(); st.Source != SourceHub || st.LastError == "" || st.Peers != 1 {
		t.Errorf("status = %+v", st)
	}
}

func TestHubDropsEntriesAsTheyExpireWhileTheHubIsDown(t *testing.T) {
	_, e := entryFor(t, 64501, "https://192.0.2.31:9444")
	srv := newHubServer(t, listOf(t, e))
	clock := t0.Add(time.Hour)
	h, ap := testHub(t, srv, nil, &clock)
	h.Refresh(context.Background())
	if len(ap.get()) != 1 {
		t.Fatal("entry not applied")
	}

	srv.set(nil, 502)
	clock = t0.Add(91 * 24 * time.Hour)
	h.Refresh(context.Background())

	if got := ap.get(); len(got) != 0 {
		t.Errorf("expired entry still applied: %+v", got)
	}
	if st := h.Status(); st.Listed != 0 || st.Peers != 0 {
		t.Errorf("status = %+v", st)
	}
}

func TestHubRefusesBadResponses(t *testing.T) {
	clock := t0.Add(time.Hour)
	for name, body := range map[string][]byte{
		"not a list": []byte("hello"),
		"too large":  []byte(strings.Repeat("x", MaxHubBytes+10)),
	} {
		srv := newHubServer(t, body)
		h, ap := testHub(t, srv, nil, &clock)
		h.Refresh(context.Background())
		if len(ap.get()) != 0 || h.Status().LastError == "" {
			t.Errorf("%s: peers %+v status %+v", name, ap.get(), h.Status())
		}
	}
}

func TestHubDoesNotFollowARedirectToHTTP(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
	}))
	defer plain.Close()
	var tlsHits atomic.Int32
	var loop atomic.Bool
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tlsHits.Add(1)
		if loop.Load() {
			http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
			return
		}
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsSrv.Close()
	clock := t0

	// The default client does not trust the test certificate, so its redirect
	// policy is moved onto the test server's client.
	policy := NewHub(HubOptions{
		Cfg: &config.HerdHub{URL: tlsSrv.URL, Refresh: time.Hour, MaxPeers: 16}, Self: "x", Skip: func(string, string) bool { return false },
		Apply: func([]HubPeer) {}, Now: func() time.Time { return clock }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).o.Client.CheckRedirect
	cli := tlsSrv.Client()
	cli.CheckRedirect = policy
	h := NewHub(HubOptions{
		Cfg: &config.HerdHub{URL: tlsSrv.URL, Refresh: time.Hour, MaxPeers: 16}, Self: "x", Skip: func(string, string) bool { return false },
		Apply: func([]HubPeer) {}, Client: cli, Now: func() time.Time { return clock }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	h.Refresh(context.Background())
	if plainHits.Load() != 0 || !strings.Contains(h.Status().LastError, "302") {
		t.Errorf("redirect to http: plain hits %d, status %+v", plainHits.Load(), h.Status())
	}

	loop.Store(true)
	tlsHits.Store(0)
	h.Refresh(context.Background())
	if n := tlsHits.Load(); n < 2 || n > 5 || h.Status().LastError == "" {
		t.Errorf("redirect loop: %d requests, status %+v", n, h.Status())
	}
}

// Hub peers are pulled like static ones, and their keys may pull from us.
func TestHubPeersPullAndMayConnect(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	b.cfg.Peers = nil
	a.hub = &KeySet{}
	a.serve()
	a.seedN(4, 64510)
	cli := client(b.node, a)

	if code, _, _ := tryGet(cli, a.url()+PathStatus); code != 0 {
		t.Fatalf("an unlisted key connected (status %d)", code)
	}

	p, err := NewPuller(PullerOptions{
		Cfg: b.cfg, Node: b.node, Store: b.store, Origins: func() []uint32 { return []uint32{64510} },
		Now: b.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: b.trips, Jitter: func() float64 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	p.Round(context.Background())
	if len(p.Peers()) != 0 || len(pulledRows(t, b, a.node)) != 0 {
		t.Fatal("pulled with no peers")
	}

	hp := []HubPeer{{URL: a.url(), Key: a.node.pub, ASN: 64501, Source: SourceHub}}
	p.SetHub(hp)
	a.hub.Set([]HubPeer{{Key: b.node.pub}})
	p.Round(context.Background())

	if rows := pulledRows(t, b, a.node); len(rows) != 4 {
		t.Fatalf("pulled %d rows, want 4; peers %+v", len(rows), p.Peers())
	}
	st := p.Peers()
	if len(st) != 1 || st[0].Source != SourceHub || st[0].ASN != 64501 || st[0].Failures != 0 {
		t.Errorf("peers = %+v", st)
	}

	// The same peer in the next list keeps its state.
	p.SetHub(hp)
	if st := p.Peers(); len(st) != 1 || st[0].Pulled != 4 {
		t.Errorf("state lost on refresh: %+v", st)
	}
	// Dropped from the list: no longer pulled, and its key is refused.
	p.SetHub(nil)
	a.hub.Set(nil)
	if len(p.Peers()) != 0 {
		t.Errorf("peer kept: %+v", p.Peers())
	}
	if code, _, _ := tryGet(client(b.node, a), a.url()+PathStatus); code != 0 {
		t.Errorf("a key removed from the hub list still connects (status %d)", code)
	}
}

// The pin is checked at the handshake and again on each request, so a key
// that leaves the hub list loses a connection it already holds.
func TestHubKeyRemovedFromTheListLosesItsOpenConnection(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	a.hub = &KeySet{}
	a.serve()
	a.hub.Set([]HubPeer{{Key: b.node.pub}})
	cli := client(b.node, a)
	cli.Transport.(*http.Transport).DisableKeepAlives = false

	if code, _, _ := tryGet(cli, a.url()+PathStatus); code != http.StatusOK {
		t.Fatalf("listed key: status %d", code)
	}
	a.hub.Set(nil)
	if code, _, _ := tryGet(cli, a.url()+PathStatus); code == http.StatusOK {
		t.Errorf("a key removed from the list was still served on its open connection")
	}
}

func TestHubPeerWhoseStatusDisagreesWithItsEntryIsRefused(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	b.cfg.Peers = nil
	a.hub = &KeySet{}
	a.serve()
	a.hub.Set([]HubPeer{{Key: b.node.pub}})
	a.seedN(2, 64510)
	p, err := NewPuller(PullerOptions{
		Cfg: b.cfg, Node: b.node, Store: b.store, Origins: func() []uint32 { return []uint32{64510} },
		Now: b.clock, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Trips: b.trips, Jitter: func() float64 { return 1 },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)

	p.SetHub([]HubPeer{{URL: a.url(), Key: a.node.pub, ASN: 64999, Source: SourceHub}})
	p.Round(context.Background())

	st := p.Peers()[0]
	if st.Failures != 1 || !strings.Contains(st.LastError, "64501") || len(pulledRows(t, b, a.node)) != 0 {
		t.Errorf("peer = %+v", st)
	}
}

func TestStaticPeersSurviveSetHub(t *testing.T) {
	a := newMember(t, 64501, nil)
	b := newMember(t, 64502, nil)
	a.serve(b.node)
	p := b.puller(a)
	p.SetHub([]HubPeer{{URL: "https://192.0.2.31:9444", Key: testNode(t).pub, ASN: 64503, Source: SourceSnapshot}})
	st := p.Peers()
	if len(st) != 2 || st[0].Source != SourceConfig || st[1].Source != SourceSnapshot {
		t.Errorf("peers = %+v", st)
	}
	p.SetHub(nil)
	if st := p.Peers(); len(st) != 1 || st[0].Source != SourceConfig {
		t.Errorf("peers = %+v", st)
	}
}

// tryGet is get that reports a failed connection as status 0.
func tryGet(c *http.Client, url string) (int, http.Header, []byte) {
	res, err := c.Get(url)
	if err != nil {
		return 0, nil, nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

// A node with herd.hub wires the hub list into both the puller and the
// pull API's pinned keys, and reports it in its status.
func TestHerdWiresTheHubIntoPullAndServe(t *testing.T) {
	cfg := testCfg(t, func(c *config.Herd) {
		c.KeyFile = filepath.Join(t.TempDir(), "node.key")
		c.Hub = &config.HerdHub{URL: "https://127.0.0.1:1/herd.json", Refresh: time.Hour, MaxPeers: 16}
	})
	h, err := New(Options{
		Cfg: cfg, ASN: 64496, Store: testStore(t), RIB: &fakeRIB{ready: true}, Rules: defaultRules(),
		Now: func() time.Time { return t0 }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.Status(context.Background()).Hub == nil || len(h.pull.Peers()) != 1 {
		t.Fatalf("before a refresh: %+v, %d peers", h.Status(context.Background()).Hub, len(h.pull.Peers()))
	}

	peer, raw := entryFor(t, 64501, "https://192.0.2.31:9444")
	h.hub.o.Snapshot = listOf(t, raw)
	h.hub.Refresh(context.Background())

	st := h.Status(context.Background())
	if st.Hub.Source != SourceSnapshot || st.Hub.Peers != 1 || st.Hub.LastError == "" {
		t.Errorf("hub status = %+v", st.Hub)
	}
	if len(st.Peers) != 2 || st.Peers[0].Source != SourceConfig || st.Peers[1].Source != SourceSnapshot || st.Peers[1].KeyID != peer.ID() {
		t.Errorf("peers = %+v", st.Peers)
	}
	if !h.srv.o.Hub.Has(peer.ID()) {
		t.Error("the hub peer's key is not accepted by the pull API")
	}
}

func TestHerdWithoutAHubHasNone(t *testing.T) {
	cfg := testCfg(t, func(c *config.Herd) { c.KeyFile = filepath.Join(t.TempDir(), "node.key") })
	h, err := New(Options{Cfg: cfg, ASN: 64496, Store: testStore(t), RIB: &fakeRIB{ready: true}, Rules: defaultRules()})
	if err != nil {
		t.Fatal(err)
	}
	if h.hub != nil || h.Status(context.Background()).Hub != nil || h.srv.o.Hub != nil {
		t.Error("hub state exists without herd.hub")
	}
}
