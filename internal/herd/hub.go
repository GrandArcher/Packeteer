package herd

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// snapshot is the hub list as of the release. A node that cannot reach
// the hub at start uses it; every entry in it is checked like any other,
// so a stale snapshot only loses its expired entries.
//
//go:embed hub_snapshot.json
var snapshot []byte

// MaxHubEntries bounds the entries read from one list.
const MaxHubEntries = 4096

// Where a peer came from.
const (
	SourceConfig   = "config"
	SourceHub      = "hub"
	SourceSnapshot = "snapshot"
)

// HubList is the document the hub serves. It is unsigned: the hub is not
// trusted, and every entry in it is signed by its own member.
type HubList struct {
	Schema      string            `json:"schema"`
	GeneratedAt time.Time         `json:"generated_at"`
	Entries     []json.RawMessage `json:"entries"`
}

// ParseHubList returns the entries of a list that pass CheckEntry at now,
// and how many did not. A list that is not a hub document is an error.
func ParseHubList(raw []byte, now time.Time) ([]Entry, int, error) {
	if len(raw) > MaxHubBytes {
		return nil, 0, fmt.Errorf("hub list is larger than %d bytes", MaxHubBytes)
	}
	var l HubList
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, 0, fmt.Errorf("hub list: %w", err)
	}
	if l.Schema != HubSchema {
		return nil, 0, fmt.Errorf("hub list schema %q is not %s", l.Schema, HubSchema)
	}
	if len(l.Entries) > MaxHubEntries {
		return nil, 0, fmt.Errorf("hub list holds more than %d entries", MaxHubEntries)
	}
	var out []Entry
	rejected := 0
	for _, r := range l.Entries {
		e, err := CheckEntry(r, now)
		if err != nil {
			rejected++
			continue
		}
		out = append(out, e)
	}
	return out, rejected, nil
}

// BuildHubList is the list document of the given entry documents, in the
// order given. The caller has checked them.
func BuildHubList(entries [][]byte, now time.Time) ([]byte, error) {
	l := HubList{Schema: HubSchema, GeneratedAt: now.UTC().Truncate(time.Second), Entries: make([]json.RawMessage, len(entries))}
	for i, e := range entries {
		l.Entries[i] = e
	}
	return json.MarshalIndent(l, "", "  ")
}

// HubPeer is a peer taken from the hub list.
type HubPeer struct {
	URL    string
	Key    ed25519.PublicKey
	ASN    uint32
	Source string
}

// KeySet is the keys of the current hub peers, which may connect to the
// pull API like a static peer. It is replaced on every refresh.
type KeySet struct {
	mu  sync.RWMutex
	ids map[string]bool
}

// Has reports whether id is a hub peer's key id. A nil set has none.
func (k *KeySet) Has(id string) bool {
	if k == nil {
		return false
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.ids[id]
}

// Set replaces the keys with those of peers.
func (k *KeySet) Set(peers []HubPeer) {
	ids := make(map[string]bool, len(peers))
	for _, p := range peers {
		ids[KeyID(p.Key)] = true
	}
	k.mu.Lock()
	k.ids = ids
	k.mu.Unlock()
}

// selectPeers picks the nodes to use from verified entries: not this
// node's own entry or ASN, one entry per ASN (the newest), each key once,
// nothing skip refuses, and at most max nodes. Which entries win a full
// cap depends on self, so members do not all pick the same ones.
func selectPeers(entries []Entry, self string, selfASN uint32, skip func(keyID, url string) bool, max int, source string) []HubPeer {
	newest := map[uint32]Entry{}
	for _, e := range entries {
		if cur, ok := newest[e.ASN]; !ok || e.Issued.After(cur.Issued) || (e.Issued.Equal(cur.Issued) && e.Signer > cur.Signer) {
			newest[e.ASN] = e
		}
	}
	type ranked struct {
		e    Entry
		rank [sha256.Size]byte
	}
	list := make([]ranked, 0, len(newest))
	for asn, e := range newest {
		if asn != selfASN {
			list = append(list, ranked{e, sha256.Sum256(fmt.Appendf(nil, "%s/%d", self, asn))})
		}
	}
	sort.Slice(list, func(i, j int) bool { return string(list[i].rank[:]) < string(list[j].rank[:]) })
	var out []HubPeer
	seen := map[string]bool{self: true}
	for _, r := range list {
		for _, n := range r.e.Nodes {
			if len(out) >= max {
				return out
			}
			k, _ := config.ParseHerdKey(n.Key)
			id := KeyID(k)
			if seen[id] || skip(id, n.URL) {
				continue
			}
			seen[id] = true
			out = append(out, HubPeer{URL: n.URL, Key: k, ASN: r.e.ASN, Source: source})
		}
	}
	return out
}

// HubOptions wires the hub client.
type HubOptions struct {
	Cfg *config.HerdHub
	// Self is this node's key id and ASN; its own entry is never used.
	Self string
	ASN  uint32
	// Skip refuses a node already known, such as a static peer.
	Skip func(keyID, url string) bool
	// Apply receives the peers to use, on every refresh.
	Apply func([]HubPeer)
	// Client fetches the list; nil takes a client that follows only https
	// redirects.
	Client *http.Client
	// Snapshot is the list used when the hub has never answered; nil takes
	// the one built into the release.
	Snapshot []byte
	Now      func() time.Time
	Log      *slog.Logger
	Event    func(string)
}

// HubStatus is the hub client's state for the status API.
type HubStatus struct {
	URL       string    `json:"url"`
	Source    string    `json:"source,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitzero"`
	Listed    int       `json:"listed"`
	Rejected  int       `json:"rejected"`
	Peers     int       `json:"peers"`
	LastError string    `json:"last_error,omitempty"`
}

// Hub fetches the hub list on a schedule and hands the verified peers to
// Apply. A failed fetch keeps the last list, dropping entries as they
// expire; the built-in snapshot is used only before the first success.
type Hub struct {
	o     HubOptions
	guard *guard

	mu      sync.Mutex
	entries []Entry
	st      HubStatus
}

// NewHub returns a Hub; Run starts it.
func NewHub(o HubOptions) *Hub {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Snapshot == nil {
		o.Snapshot = snapshot
	}
	if o.Client == nil {
		o.Client = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if req.URL.Scheme != "https" || len(via) > 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}
	return &Hub{o: o, guard: newGuard(o.Log, o.Event), st: HubStatus{URL: o.Cfg.URL}}
}

// Status is the hub client's state.
func (h *Hub) Status() HubStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.st
}

// Run refreshes at once and then every Cfg.Refresh until ctx ends.
func (h *Hub) Run(ctx context.Context) {
	h.guard.run(ctx, "hub", func(ctx context.Context) {
		t := time.NewTicker(h.o.Cfg.Refresh)
		defer t.Stop()
		for {
			h.Refresh(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
}

// Refresh fetches the list once and applies it.
func (h *Hub) Refresh(ctx context.Context) {
	now := h.o.Now()
	raw, err := h.fetch(ctx)
	if err == nil {
		var entries []Entry
		var rejected int
		if entries, rejected, err = ParseHubList(raw, now); err == nil {
			h.load(entries, rejected, SourceHub, now)
			return
		}
	}
	h.o.Log.Warn("herd hub refresh failed", "url", h.o.Cfg.URL, "err", err)
	h.mu.Lock()
	h.st.LastError = err.Error()
	first := h.st.Source == ""
	h.mu.Unlock()
	if !first {
		h.apply(now)
		return
	}
	if entries, rejected, serr := ParseHubList(h.o.Snapshot, now); serr == nil {
		h.load(entries, rejected, SourceSnapshot, now)
	}
}

// load replaces the list and applies it.
func (h *Hub) load(entries []Entry, rejected int, source string, now time.Time) {
	h.mu.Lock()
	if source == SourceHub {
		h.st.LastError = ""
	}
	h.entries = entries
	h.st.Source, h.st.FetchedAt, h.st.Rejected = source, now, rejected
	h.mu.Unlock()
	h.apply(now)
}

// apply drops the entries that have expired at now and hands the
// selection from the rest to Apply.
func (h *Hub) apply(now time.Time) {
	h.mu.Lock()
	live := h.entries[:0:0]
	for _, e := range h.entries {
		if e.Expires.After(now) {
			live = append(live, e)
		}
	}
	h.entries = live
	src := h.st.Source
	h.mu.Unlock()

	peers := selectPeers(live, h.o.Self, h.o.ASN, h.o.Skip, h.o.Cfg.MaxPeers, src)
	h.o.Apply(peers)
	h.mu.Lock()
	h.st.Listed, h.st.Peers = len(live), len(peers)
	h.mu.Unlock()
}

func (h *Hub) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.o.Cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := h.o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return nil, fmt.Errorf("hub answered %s", res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, MaxHubBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxHubBytes {
		return nil, errors.New("hub list is larger than the size limit")
	}
	return body, nil
}
