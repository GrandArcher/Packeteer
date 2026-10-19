package herd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// View limits: the rows read for one request, and what each vantage shows.
const (
	viewRows    = 5000
	viewHistory = 20
)

// VantageRow is one record in a vantage, with where it came from.
type VantageRow struct {
	ID          string     `json:"id"`
	Time        time.Time  `json:"time"`
	AgeSeconds  float64    `json:"age_seconds"`
	Prefix      string     `json:"prefix,omitempty"`
	OriginASN   uint32     `json:"origin_asn,omitempty"`
	Routes      int        `json:"routes,omitempty"`
	ASPath      []uint32   `json:"as_path,omitempty"`
	ASPaths     [][]uint32 `json:"as_paths,omitempty"`
	Sent        int        `json:"sent"`
	LossPct     *float64   `json:"loss_pct,omitempty"`
	RTTMinMs    *float64   `json:"rtt_min_ms,omitempty"`
	RTTAvgMs    *float64   `json:"rtt_avg_ms,omitempty"`
	RTTMaxMs    *float64   `json:"rtt_max_ms,omitempty"`
	JitterMs    *float64   `json:"jitter_ms,omitempty"`
	Failed      bool       `json:"failed,omitempty"`
	FetchedAt   *time.Time `json:"fetched_at,omitempty"`
	GeneratedAt *time.Time `json:"generated_at,omitempty"`
	Signature   string     `json:"signature,omitempty"`
}

// Vantage is the records of one (member, country, provider ASN, method).
// Vantages are never merged: each lists its own numbers next to the others.
type Vantage struct {
	// Member is the signing node's key id, or "local" for this node.
	Member      string `json:"member"`
	Local       bool   `json:"local"`
	ASN         uint32 `json:"asn"`
	Identity    string `json:"identity"`
	Country     string `json:"country"`
	ProviderASN uint32 `json:"provider_asn,omitempty"`
	Method      string `json:"method"`
	Records     int    `json:"records"`
	// Latest is the newest record; History is the newest first, up to 20.
	Latest  VantageRow   `json:"latest"`
	History []VantageRow `json:"history"`
}

// VantageView is the read-only per-vantage view.
type VantageView struct {
	Enabled   bool      `json:"enabled"`
	AsOf      time.Time `json:"as_of"`
	Vantages  []Vantage `json:"vantages"`
	Truncated bool      `json:"truncated,omitempty"`
}

type vkey struct {
	member, country, method string
	provider                uint32
}

// BuildView groups the stored records that match raw by vantage. self is
// this node's ASN; peers maps key id to the peer's claimed ASN. Rows from a
// member that is not a configured peer (a removed one) are left out.
func BuildView(ctx context.Context, st plugin.HerdStore, raw string, self uint32, peers map[string]uint32, now time.Time) (VantageView, error) {
	v := VantageView{Enabled: true, AsOf: now, Vantages: []Vantage{}}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return v, errors.New("malformed query")
	}
	for k := range vals {
		if !slices.Contains([]string{"origin_asn", "prefix", "match", "provider_asn", "from"}, k) {
			return v, fmt.Errorf("unknown parameter %q", k)
		}
	}
	q := plugin.HerdQuery{AnyMember: true, From: now.Add(-24 * time.Hour), Limit: viewRows + 1}
	for _, k := range []string{"origin_asn", "provider_asn"} {
		if s := vals.Get(k); s != "" {
			n, err := strconv.ParseUint(s, 10, 32)
			if err != nil || n == 0 {
				return v, fmt.Errorf("%s %q is not an ASN", k, s)
			}
			if k == "origin_asn" {
				q.OriginASN = uint32(n)
			} else {
				q.ProviderASN = uint32(n)
			}
		}
	}
	if s := vals.Get("prefix"); s != "" {
		p, err := netip.ParsePrefix(s)
		if err != nil || p != p.Masked() {
			return v, fmt.Errorf("prefix %q", s)
		}
		q.Prefix, q.Match = p, vals.Get("match")
		if q.Match == "" {
			q.Match = MatchExact
		}
		if !slices.Contains([]string{MatchExact, MatchCovering, MatchCovered}, q.Match) {
			return v, fmt.Errorf("match %q", q.Match)
		}
	}
	if s := vals.Get("from"); s != "" {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return v, fmt.Errorf("from %q", s)
		}
		q.From = t
	}
	if q.OriginASN == 0 && !q.Prefix.IsValid() {
		return v, errors.New("name an origin_asn or a prefix")
	}
	rows, err := st.HerdRecords(ctx, q)
	if err != nil {
		return v, err
	}
	if len(rows) > viewRows {
		rows, v.Truncated = rows[:viewRows], true
	}
	groups := map[vkey]*Vantage{}
	for _, row := range rows {
		var rec Record
		var vr VantageRow
		member, asn, identity := "local", self, "local"
		if row.Member == "" {
			if json.Unmarshal(row.Body, &rec) != nil {
				continue
			}
		} else {
			peerASN, ok := peers[row.Member]
			if !ok {
				continue
			}
			var pb pulledBody
			if json.Unmarshal(row.Body, &pb) != nil {
				continue
			}
			rec, member, asn, identity = pb.Record, row.Member, peerASN, "pinned_key"
			vr.FetchedAt, vr.GeneratedAt, vr.Signature = &pb.FetchedAt, &pb.GeneratedAt, pb.Signature
		}
		vr.ID, vr.Time, vr.AgeSeconds = rec.ID, row.Time, max(now.Sub(row.Time).Seconds(), 0)
		vr.Prefix, vr.OriginASN, vr.Routes, vr.ASPath, vr.ASPaths = rec.Prefix, rec.OriginASN, rec.Routes, rec.ASPath, rec.ASPaths
		vr.Sent, vr.LossPct, vr.RTTMinMs, vr.RTTAvgMs, vr.RTTMaxMs, vr.JitterMs, vr.Failed =
			rec.Sent, rec.LossPct, rec.RTTMinMs, rec.RTTAvgMs, rec.RTTMaxMs, rec.JitterMs, rec.Failed
		k := vkey{member, rec.Vantage, rec.Method, rec.ProviderASN}
		g := groups[k]
		if g == nil {
			g = &Vantage{Member: member, Local: member == "local", ASN: asn, Identity: identity, Country: rec.Vantage, ProviderASN: rec.ProviderASN, Method: rec.Method}
			groups[k] = g
		}
		g.Records++
		g.History = append(g.History, vr)
	}
	for _, g := range groups {
		sort.SliceStable(g.History, func(i, j int) bool { return g.History[i].Time.After(g.History[j].Time) })
		g.Latest = g.History[0]
		g.History = g.History[:min(len(g.History), viewHistory)]
		v.Vantages = append(v.Vantages, *g)
	}
	sort.Slice(v.Vantages, func(i, j int) bool {
		a, b := v.Vantages[i], v.Vantages[j]
		if a.Local != b.Local {
			return a.Local
		}
		if a.Member != b.Member {
			return a.Member < b.Member
		}
		if a.Country != b.Country {
			return a.Country < b.Country
		}
		if a.ProviderASN != b.ProviderASN {
			return a.ProviderASN < b.ProviderASN
		}
		return a.Method < b.Method
	})
	return v, nil
}
