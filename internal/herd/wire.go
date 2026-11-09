package herd

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Query is what a pull asks for. The envelope echoes it inside the signed
// body, so a reply to one query cannot be replayed as the answer to
// another. From is the effective start (clipped to retention).
type Query struct {
	OriginASN   uint32 `json:"origin_asn,omitempty"`
	Prefix      string `json:"prefix,omitempty"`
	Match       string `json:"match,omitempty"`
	ProviderASN uint32 `json:"provider_asn,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Limit       int    `json:"limit,omitempty"`
	Cursor      string `json:"cursor,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
}

// Envelope is every response of the records endpoint: one signed document.
type Envelope struct {
	Schema        string    `json:"schema"`
	Member        string    `json:"member"`
	ASN           uint32    `json:"asn"`
	GeneratedAt   time.Time `json:"generated_at"`
	RetentionDays int       `json:"retention_days"`
	Granularity   string    `json:"granularity"`
	Query         Query     `json:"query"`
	Records       []Record  `json:"records"`
	NextCursor    string    `json:"next_cursor,omitempty"`
	Signature     string    `json:"signature,omitempty"`
}

// Status is the signed status document liveness checks fetch.
type Status struct {
	Schema        string    `json:"schema"`
	Member        string    `json:"member"`
	ASN           uint32    `json:"asn"`
	GeneratedAt   time.Time `json:"generated_at"`
	RetentionDays int       `json:"retention_days"`
	Granularity   string    `json:"granularity"`
	Classes       []string  `json:"classes"`
	Discovery     string    `json:"discovery"`
	Vantage       string    `json:"vantage"`
	Signature     string    `json:"signature,omitempty"`
}

// Paths of the pull API.
const (
	PathStatus  = "/herd/v1/status"
	PathRecords = "/herd/v1/records"
)

// Match modes of a prefix query.
const (
	MatchExact    = "exact"
	MatchCovering = "covering"
	MatchCovered  = "covered"
)

const (
	maxCursor = 512
	maxNonce  = 64
)

var queryKeys = []string{"origin_asn", "prefix", "match", "provider_asn", "from", "to", "limit", "cursor", "nonce"}

// ParseQuery is the strict parser of a records request: unknown keys,
// repeated keys, and malformed values are errors.
func ParseQuery(raw string) (Query, error) {
	var q Query
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return q, errors.New("malformed query")
	}
	for k, v := range vals {
		if !slices.Contains(queryKeys, k) {
			return q, fmt.Errorf("unknown parameter %q", k)
		}
		if len(v) != 1 {
			return q, fmt.Errorf("parameter %q repeated", k)
		}
	}
	asn := func(k string) (uint32, error) {
		s := vals.Get(k)
		if s == "" {
			return 0, nil
		}
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return 0, fmt.Errorf("%s %q is not an ASN", k, s)
		}
		return uint32(n), nil
	}
	if q.OriginASN, err = asn("origin_asn"); err != nil {
		return q, err
	}
	if q.ProviderASN, err = asn("provider_asn"); err != nil {
		return q, err
	}
	if s := vals.Get("prefix"); s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return q, fmt.Errorf("prefix %q", s)
		}
		q.Prefix = p.String()
		q.Match = MatchExact
	}
	if s := vals.Get("match"); s != "" {
		if q.Prefix == "" || (s != MatchExact && s != MatchCovering && s != MatchCovered) {
			return q, fmt.Errorf("match %q needs a prefix and must be exact, covering, or covered", s)
		}
		q.Match = s
	}
	for _, k := range []string{"from", "to"} {
		s := vals.Get(k)
		if s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return q, fmt.Errorf("%s %q is not an RFC 3339 time", k, s)
		}
		if k == "from" {
			q.From = t.UTC().Format(time.RFC3339Nano)
		} else {
			q.To = t.UTC().Format(time.RFC3339Nano)
		}
	}
	if s := vals.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return q, fmt.Errorf("limit %q", s)
		}
		q.Limit = n
	}
	if q.Cursor = vals.Get("cursor"); len(q.Cursor) > maxCursor {
		return q, errors.New("cursor too long")
	}
	if q.Nonce = vals.Get("nonce"); len(q.Nonce) > maxNonce || strings.ContainsAny(q.Nonce, " \t\r\n") {
		return q, errors.New("bad nonce")
	}
	return q, nil
}

// Values is q as the query string a puller sends.
func (q Query) Values() string {
	v := url.Values{}
	set := func(k, s string) {
		if s != "" {
			v.Set(k, s)
		}
	}
	if q.OriginASN != 0 {
		set("origin_asn", strconv.FormatUint(uint64(q.OriginASN), 10))
	}
	if q.ProviderASN != 0 {
		set("provider_asn", strconv.FormatUint(uint64(q.ProviderASN), 10))
	}
	set("prefix", q.Prefix)
	if q.Prefix != "" {
		set("match", q.Match)
	}
	set("from", q.From)
	set("to", q.To)
	if q.Limit != 0 {
		set("limit", strconv.Itoa(q.Limit))
	}
	set("cursor", q.Cursor)
	set("nonce", q.Nonce)
	return v.Encode()
}

// cursorKey is the position after a row: the fields the store orders by.
type cursorKey struct {
	Prefix   string `json:"p,omitempty"`
	Provider uint32 `json:"a,omitempty"`
	TimeMS   int64  `json:"t"`
	Member   string `json:"m,omitempty"`
	ID       string `json:"i"`
}

func encodeCursor(k cursorKey) string {
	b, _ := json.Marshal(k)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(s string) (cursorKey, error) {
	var k cursorKey
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return k, errors.New("bad cursor")
	}
	if err := json.Unmarshal(b, &k); err != nil || k.ID == "" {
		return k, errors.New("bad cursor")
	}
	if k.Prefix != "" {
		if _, err := netip.ParsePrefix(k.Prefix); err != nil {
			return k, errors.New("bad cursor")
		}
	}
	return k, nil
}
