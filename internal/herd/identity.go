package herd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// IdentitySchema is the document of validated RPKI Signed Checklists
// (RFC 9323) a node reads to verify member identities (#672).
const IdentitySchema = "packeteer-herd-rsc/1"

// Bounds on the checklist document.
const (
	MaxIdentityBytes  = 4 << 20
	maxChecklists     = 4096
	maxChecklistItems = 64
)

// Checklist is one RSC a relying party validated: the ASNs in its EE
// certificate's resources, the SHA-256 digests it signs, and the end of its
// validity. A digest that equals a node's key id (the SHA-256 of its
// public key) binds that key to each of the ASNs.
type Checklist struct {
	ASNs     []uint32  `json:"asns"`
	Digests  []string  `json:"digests"`
	NotAfter time.Time `json:"not_after"`
}

// IdentityList is the checklist document. It carries what a relying party
// already validated, so it is only as trusted as the https source it came
// from; the RSC objects themselves are not checked here.
type IdentityList struct {
	Schema      string      `json:"schema"`
	GeneratedAt time.Time   `json:"generated_at"`
	Checklists  []Checklist `json:"checklists"`
}

type binding struct {
	asn uint32
	key string
}

// ParseIdentityList returns every (ASN, key id) binding of raw with the
// latest end of validity among the checklists that hold it. Strict fields;
// a malformed checklist fails the whole document, so a broken source
// verifies nobody instead of a part of the herd.
func ParseIdentityList(raw []byte) (map[binding]time.Time, error) {
	if len(raw) > MaxIdentityBytes {
		return nil, fmt.Errorf("checklist document is larger than %d bytes", MaxIdentityBytes)
	}
	var l IdentityList
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("checklist document: %w", err)
	}
	switch {
	case l.Schema != IdentitySchema:
		return nil, fmt.Errorf("checklist schema %q is not %s", l.Schema, IdentitySchema)
	case len(l.Checklists) > maxChecklists:
		return nil, fmt.Errorf("checklist document holds more than %d checklists", maxChecklists)
	}
	out := map[binding]time.Time{}
	for i, c := range l.Checklists {
		if len(c.ASNs) == 0 || len(c.ASNs) > maxChecklistItems || len(c.Digests) == 0 || len(c.Digests) > maxChecklistItems || c.NotAfter.IsZero() {
			return nil, fmt.Errorf("checklists[%d]: needs 1 to %d asns and digests and a not_after", i, maxChecklistItems)
		}
		for _, d := range c.Digests {
			if !sha256Hex.MatchString(d) {
				return nil, fmt.Errorf("checklists[%d]: digest %q is not 64 lowercase hex digits", i, d)
			}
		}
		for _, a := range c.ASNs {
			if a == 0 {
				return nil, fmt.Errorf("checklists[%d]: asn 0", i)
			}
			for _, d := range c.Digests {
				if b := (binding{a, d}); c.NotAfter.After(out[b]) {
					out[b] = c.NotAfter
				}
			}
		}
	}
	return out, nil
}

// IdentityStatus is the identity source's state for the status API.
type IdentityStatus struct {
	URL       string    `json:"url"`
	FetchedAt time.Time `json:"fetched_at,omitzero"`
	Bindings  int       `json:"bindings"`
	LastError string    `json:"last_error,omitempty"`
}

// Identities fetches the checklist document on a schedule. A failed fetch
// keeps the last document; a binding stops verifying at its not_after.
// Before the first success nobody is verified.
type Identities struct {
	cfg    *config.HerdIdentity
	client *http.Client
	now    func() time.Time
	log    *slog.Logger
	guard  *guard

	mu  sync.RWMutex
	set map[binding]time.Time
	st  IdentityStatus
}

// NewIdentities returns the identity source of cfg; Run starts it.
func NewIdentities(cfg *config.HerdIdentity, now func() time.Time, log *slog.Logger, event func(string)) *Identities {
	return &Identities{cfg: cfg, client: httpsClient(), now: now, log: log, guard: newGuard(log, event), st: IdentityStatus{URL: statusURL(cfg.URL)}}
}

// Verified reports whether the node key keyID is bound to asn by a
// checklist that is still valid. A nil source verifies nobody.
func (s *Identities) Verified(asn uint32, keyID string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.set[binding{asn, keyID}].After(s.now())
}

// Status is the identity source's state.
func (s *Identities) Status() IdentityStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st
}

// Run refreshes at once and then every Refresh until ctx ends.
func (s *Identities) Run(ctx context.Context) {
	s.guard.run(ctx, "identity", func(ctx context.Context) {
		t := time.NewTicker(s.cfg.Refresh)
		defer t.Stop()
		for {
			s.Refresh(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	})
}

// Refresh fetches the document once.
func (s *Identities) Refresh(ctx context.Context) {
	raw, err := fetchDoc(ctx, s.client, s.cfg.URL, "identity source", MaxIdentityBytes)
	var set map[binding]time.Time
	if err == nil {
		set, err = ParseIdentityList(raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.st.LastError = err.Error()
		s.log.Warn("herd identity refresh failed", "url", s.st.URL, "err", err)
		return
	}
	s.set = set
	s.st.FetchedAt, s.st.Bindings, s.st.LastError = s.now(), len(set), ""
}
