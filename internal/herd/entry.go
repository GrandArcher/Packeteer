package herd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// Hub schemas and bounds (#261, docs/herd-hub.md).
const (
	EntrySchema = "packeteer-herd-entry/1"
	HubSchema   = "packeteer-herd-hub/1"

	// MaxEntryLife is how far ahead an entry may expire. A member that
	// leaves is gone from the list at most this long after its last entry.
	MaxEntryLife  = 180 * 24 * time.Hour
	MaxEntryNodes = 4
	// MaxEntryBytes bounds one entry document.
	MaxEntryBytes = 16 << 10
	// MaxHubBytes bounds the list document a node reads.
	MaxHubBytes = 4 << 20

	issuedSkew = 5 * time.Minute
)

// ErrExpired is wrapped by the error of an entry whose expiry has passed.
var ErrExpired = errors.New("expired")

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// EntryNode is one node of a member: its pinned key and pull API address.
type EntryNode struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

// EntryIdentity points at the member's identity statement and the RSC
// (RFC 9323) that signs its digest. Nodes carry the reference; they do
// not validate RPKI objects yet, so no hub peer counts as verified.
type EntryIdentity struct {
	StatementURL    string `json:"statement_url"`
	StatementSHA256 string `json:"statement_sha256"`
	RSCURL          string `json:"rsc_url"`
}

// Entry is a member's peer entry for the hub list. It is signed by one of
// its own node keys, so the hub can add and remove entries but not forge
// or alter them.
type Entry struct {
	Schema        string         `json:"schema"`
	ASN           uint32         `json:"asn"`
	Nodes         []EntryNode    `json:"nodes"`
	Identity      *EntryIdentity `json:"identity,omitempty"`
	RetentionDays int            `json:"retention_days"`
	Classes       []string       `json:"classes"`
	Issued        time.Time      `json:"issued"`
	Expires       time.Time      `json:"expires"`
	// Signer is the node key that made Signature; it is one of Nodes.
	Signer    string `json:"signer"`
	Signature string `json:"signature,omitempty"`
}

// SignEntry fills the schema and signer, signs e with the node key, and
// returns the entry document. Times are cut to whole seconds, UTC.
func (n *Node) SignEntry(e Entry) ([]byte, error) {
	e.Schema, e.Signer, e.Signature = EntrySchema, n.PublicKey(), ""
	e.Issued, e.Expires = e.Issued.UTC().Truncate(time.Second), e.Expires.UTC().Truncate(time.Second)
	sig, err := n.sign(e)
	if err != nil {
		return nil, err
	}
	e.Signature = sig
	return json.MarshalIndent(e, "", "  ")
}

// CheckEntry decodes and verifies one entry document at time now: strict
// fields, bounded size, valid values, an unexpired signed lifetime within
// MaxEntryLife, and a signature by one of its own node keys. It is the
// check a node runs on every hub entry and the hub's CI runs on every
// submission.
func CheckEntry(raw []byte, now time.Time) (Entry, error) {
	var e Entry
	if len(raw) > MaxEntryBytes {
		return e, fmt.Errorf("entry is larger than %d bytes", MaxEntryBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("entry: %w", err)
	}
	if dec.More() {
		return e, errors.New("entry: trailing data")
	}
	if err := e.validate(now); err != nil {
		return e, err
	}
	signer, _ := config.ParseHerdKey(e.Signer)
	if err := verifyDocument(ed25519.PublicKey(signer), raw); err != nil {
		return e, fmt.Errorf("entry asn %d: %w", e.ASN, err)
	}
	return e, nil
}

func (e *Entry) validate(now time.Time) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("entry asn %d: "+format, append([]any{e.ASN}, a...)...)
	}
	if e.Schema != EntrySchema {
		return bad("schema %q is not %s", e.Schema, EntrySchema)
	}
	if e.ASN == 0 {
		return errors.New("entry: asn must not be 0")
	}
	if len(e.Nodes) == 0 || len(e.Nodes) > MaxEntryNodes {
		return bad("needs 1 to %d nodes", MaxEntryNodes)
	}
	keys, urls := map[string]bool{}, map[string]bool{}
	for i, n := range e.Nodes {
		if _, err := config.ParseHerdKey(n.Key); err != nil {
			return bad("nodes[%d]: key %s", i, err)
		}
		if err := checkEndpoint(n.URL); err != nil {
			return bad("nodes[%d]: url %q %s", i, n.URL, err)
		}
		if keys[n.Key] || urls[n.URL] {
			return bad("nodes[%d]: duplicate key or url", i)
		}
		keys[n.Key], urls[n.URL] = true, true
	}
	if !keys[e.Signer] {
		return bad("signer is not one of the nodes")
	}
	if id := e.Identity; id != nil {
		for _, u := range []string{id.StatementURL, id.RSCURL} {
			p, err := url.Parse(u)
			if err != nil || p.Scheme != "https" || p.Host == "" || p.User != nil {
				return bad("identity url %q must be https", u)
			}
		}
		if !sha256Hex.MatchString(id.StatementSHA256) {
			return bad("identity statement_sha256 must be 64 lowercase hex digits")
		}
	}
	if e.RetentionDays < config.MinHerdRetentionDays || e.RetentionDays > config.MaxHerdRetentionDays {
		return bad("retention_days %d must be between %d and %d", e.RetentionDays, config.MinHerdRetentionDays, config.MaxHerdRetentionDays)
	}
	if len(e.Classes) == 0 {
		return bad("needs at least one data class")
	}
	for i, c := range e.Classes {
		if c != config.HerdMeasurements && c != config.HerdPaths {
			return bad("classes[%d]: %q must be %s or %s", i, c, config.HerdMeasurements, config.HerdPaths)
		}
		if slices.Index(e.Classes, c) != i {
			return bad("classes[%d]: %q repeated", i, c)
		}
	}
	switch {
	case e.Issued.IsZero() || e.Issued.After(now.Add(issuedSkew)):
		return bad("issued %s is missing or in the future", e.Issued.Format(time.RFC3339))
	case !e.Expires.After(e.Issued) || e.Expires.Sub(e.Issued) > MaxEntryLife || e.Expires.Sub(now) > MaxEntryLife+issuedSkew:
		return bad("expires must be after issued and within %s", MaxEntryLife)
	case !e.Expires.After(now):
		return bad("%w at %s", ErrExpired, e.Expires.Format(time.RFC3339))
	}
	return nil
}

// checkEndpoint is config.CheckHerdURL plus a refusal of the localhost
// names and of IP literals no peer could be at: a hostile list must not
// make a node probe its own or its operator's internal services. Other
// host names are not resolved here.
func checkEndpoint(s string) error {
	if err := config.CheckHerdURL(s); err != nil {
		return err
	}
	u, _ := url.Parse(s)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return errors.New("is not a routable address")
	}
	if a, err := netip.ParseAddr(host); err == nil && (a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsPrivate()) {
		return errors.New("is not a routable address")
	}
	return nil
}
