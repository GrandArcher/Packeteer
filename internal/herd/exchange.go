package herd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// PathPeers is the peer exchange endpoint of the pull API (#672).
const PathPeers = "/herd/v1/peers"

// MaxRelayed bounds the entries in one peer list, served or read. A list
// with more is refused whole.
const MaxRelayed = 64

// Relayed is one member entry in a peer list: the entry exactly as its own
// node signed it, and how long ago the relayer last reached that node. The
// relayer cannot alter an entry, only withhold it.
type Relayed struct {
	Entry      json.RawMessage `json:"entry"`
	AgeSeconds int64           `json:"age_s"`
}

// PeerList is the signed peer exchange document.
type PeerList struct {
	Schema      string    `json:"schema"`
	Member      string    `json:"member"`
	GeneratedAt time.Time `json:"generated_at"`
	Entries     []Relayed `json:"entries"`
	Signature   string    `json:"signature,omitempty"`
}

// learned is an entry taken from peer exchange: who relayed it and when it
// was last relayed by anyone.
type learned struct {
	e    Entry
	via  string
	seen time.Time
}

// ExchangeOptions wires peer exchange.
type ExchangeOptions struct {
	// Max caps the members learned this way (herd.hub.exchange_peers).
	Max int
	// Self is this node's key id and ASN; its own entry is never used.
	Self    string
	SelfASN uint32
	// Skip refuses a node already known as a static or hub peer.
	Skip func(keyID, url string) bool
	// Agrees refuses an entry for an ASN the hub pinned to other keys.
	Agrees func(Entry) bool
	// Life is how long an entry stays after the last relayer listed it. A
	// relayer lists only nodes it reached recently, so a silent member
	// ages out.
	Life  time.Duration
	Trips *Trips
	Log   *slog.Logger
}

// Exchange is the members learned from peers' peer lists: one entry per
// ASN, each checked like a hub entry (strict fields, size, expiry, its own
// node's signature), at most Max of them.
type Exchange struct {
	o ExchangeOptions

	mu    sync.Mutex
	known map[uint32]learned
}

// NewExchange returns an empty Exchange.
func NewExchange(o ExchangeOptions) *Exchange {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	return &Exchange{o: o, known: map[uint32]learned{}}
}

// Offer checks the entries relayer via listed and keeps the usable ones.
// It returns how many it refused: malformed, oversized, expired, badly
// signed, against a hub pin, or for an ASN already held by unrelated
// keys. This node's own entry and entries it already has are not refused.
func (x *Exchange) Offer(via string, entries []json.RawMessage, now time.Time) int {
	refused := 0
	refuse := func(err error) {
		refused++
		x.o.Trips.Add("exchange_refused", via)
		x.o.Log.Warn("herd peer exchange: entry refused", "relayer", via, "err", err)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, raw := range entries {
		e, err := CheckEntry(raw, now)
		if err != nil {
			refuse(err)
			continue
		}
		if e.ASN == x.o.SelfASN || e.has(x.o.Self) {
			continue
		}
		if x.o.Agrees != nil && !x.o.Agrees(e) {
			refuse(fmt.Errorf("entry asn %d: the hub pinned this ASN to other keys", e.ASN))
			continue
		}
		cur, ok := x.known[e.ASN]
		switch {
		case !ok && len(x.known) >= x.o.Max:
			x.o.Trips.Add("exchange_peers", via)
			continue
		case !ok, cur.e.Signature == e.Signature:
		case !cur.e.hasKey(e.Signer):
			refuse(fmt.Errorf("entry asn %d: signed by a key the known entry does not list", e.ASN))
			continue
		case !e.Issued.After(cur.e.Issued):
			cur.seen = now
			x.known[e.ASN] = cur
			continue
		}
		x.known[e.ASN] = learned{e: e, via: via, seen: now}
	}
	return refused
}

// Peers drops the entries that expired or that no relayer listed within
// Life, and returns the nodes of the rest that Skip does not refuse.
func (x *Exchange) Peers(now time.Time) []HubPeer {
	x.mu.Lock()
	entries := make([]Entry, 0, len(x.known))
	for asn, l := range x.known {
		if !l.e.Expires.After(now) || now.Sub(l.seen) > x.o.Life {
			delete(x.known, asn)
			continue
		}
		entries = append(entries, l.e)
	}
	x.mu.Unlock()
	return selectPeers(entries, x.o.Self, x.o.SelfASN, x.o.Skip, x.o.Max, SourceExchange)
}

// has reports whether the node with key id is one of e's nodes.
func (e Entry) has(id string) bool {
	for _, n := range e.Nodes {
		if k, err := config.ParseHerdKey(n.Key); err == nil && KeyID(k) == id {
			return true
		}
	}
	return false
}

func (e Entry) hasKey(key string) bool {
	for _, n := range e.Nodes {
		if n.Key == key {
			return true
		}
	}
	return false
}

// openPeerList checks a peer list from pe: its signature, member, and
// size, and returns the entries.
func openPeerList(raw []byte, pe *peer) ([]json.RawMessage, error) {
	if err := verifyDocument(pe.pub, raw); err != nil {
		return nil, fmt.Errorf("peers: %w", err)
	}
	var l PeerList
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("peers: %w", err)
	}
	switch {
	case l.Schema != Schema:
		return nil, fmt.Errorf("peers schema %q", l.Schema)
	case l.Member != pe.id:
		return nil, errors.New("peers are signed for another member")
	case len(l.Entries) > MaxRelayed:
		return nil, fmt.Errorf("peer list holds %d entries, over %d", len(l.Entries), MaxRelayed)
	}
	out := make([]json.RawMessage, len(l.Entries))
	for i, r := range l.Entries {
		out[i] = r.Entry
	}
	return out, nil
}
