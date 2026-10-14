package exchange

import (
	"cmp"
	"encoding/csv"
	"io"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Transit is a configured provider that is not an exchange peer. Cost is
// its price per Mbps, nil when none is configured.
type Transit struct {
	Name string
	Cost *float64
}

// OffloadPeer is an exchange peer that could carry a prefix instead.
type OffloadPeer struct {
	Exchange string
	Name     string
}

// OffloadInput is what Offload reads. Nothing in it is written back.
type OffloadInput struct {
	Volumes  []plugin.PrefixVolume
	Transits []Transit
	Peers    []OffloadPeer
	// Exit is the provider the prefix's traffic leaves through now.
	Exit func(netip.Prefix) string
	// Advertises is the route check: the peer shows the exact prefix, on a
	// path whose first AS is its own.
	Advertises func(p netip.Prefix, peer string) bool
}

// OffloadPeerRef names a peer that advertises a candidate prefix.
type OffloadPeerRef struct {
	Exchange string `json:"exchange"`
	Peer     string `json:"peer"`
}

// OffloadRow is one prefix that leaves through a transit while an
// exchange peer advertises it.
type OffloadRow struct {
	Prefix  string           `json:"prefix"`
	Bytes   uint64           `json:"bytes"`
	Mbps    float64          `json:"mbps"`
	Transit string           `json:"transit"`
	Peers   []OffloadPeerRef `json:"peers"`
	// EstSavings is the transit's cost per Mbps times Mbps. Nil when the
	// transit has no cost. It is an estimate for the report: nothing is
	// steered by it.
	EstSavings *float64 `json:"est_savings,omitempty"`
}

// Offload is the transit-to-exchange offload report (#152).
type Offload struct {
	// Prefixes, Bytes, Mbps, and EstSavings total every candidate, not
	// only the rows returned.
	Prefixes   int      `json:"prefixes"`
	Bytes      uint64   `json:"bytes"`
	Mbps       float64  `json:"mbps"`
	EstSavings *float64 `json:"est_savings,omitempty"`
	// Truncated is true when Rows holds fewer than Prefixes rows.
	Truncated bool         `json:"truncated"`
	Rows      []OffloadRow `json:"rows"`
}

// BuildOffload lists, by bytes, the prefixes whose exit is a transit while
// an exchange peer advertises the exact prefix, cut at limit rows. A prefix
// with no bytes, or whose exit is not a transit, is not a candidate. It
// reads only; the decision engine never sees it.
func BuildOffload(in OffloadInput, limit int) Offload {
	cost := map[string]*float64{}
	for _, t := range in.Transits {
		cost[t.Name] = t.Cost
	}
	out := Offload{Rows: []OffloadRow{}}
	var rows []OffloadRow
	for _, v := range in.Volumes {
		if v.Bytes == 0 {
			continue
		}
		transit := in.Exit(v.Prefix)
		c, ok := cost[transit]
		if !ok {
			continue
		}
		var peers []OffloadPeerRef
		for _, p := range in.Peers {
			if in.Advertises(v.Prefix, p.Name) {
				peers = append(peers, OffloadPeerRef{Exchange: p.Exchange, Peer: p.Name})
			}
		}
		if len(peers) == 0 {
			continue
		}
		row := OffloadRow{Prefix: v.Prefix.String(), Bytes: v.Bytes, Mbps: round(v.Mbps()), Transit: transit, Peers: peers}
		out.Prefixes++
		out.Bytes += v.Bytes
		out.Mbps += v.Mbps()
		if c != nil {
			s := *c * v.Mbps()
			row.EstSavings = &s
			sum := s
			if out.EstSavings != nil {
				sum += *out.EstSavings
			}
			out.EstSavings = &sum
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b OffloadRow) int {
		if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
			return c
		}
		return cmp.Compare(a.Prefix, b.Prefix)
	})
	if limit > 0 && len(rows) > limit {
		rows, out.Truncated = rows[:limit], true
	}
	for i := range rows {
		if rows[i].EstSavings != nil {
			rows[i].EstSavings = roundPtr(rows[i].EstSavings)
		}
	}
	out.Mbps = round(out.Mbps)
	out.EstSavings = roundPtr(out.EstSavings)
	if rows != nil {
		out.Rows = rows
	}
	return out
}

func round(v float64) float64 { return math.Round(v*100) / 100 }

func roundPtr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	r := round(*v)
	return &r
}

// WriteCSV writes the rows, one per prefix, with the peers joined by a
// space as exchange/peer. est_savings is empty when the transit has no cost.
func (o Offload) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"prefix", "bytes", "mbps", "transit", "peers", "est_savings"})
	for _, r := range o.Rows {
		peers := make([]string, len(r.Peers))
		for i, p := range r.Peers {
			peers[i] = p.Exchange + "/" + p.Peer
		}
		saving := ""
		if r.EstSavings != nil {
			saving = strconv.FormatFloat(*r.EstSavings, 'f', 2, 64)
		}
		_ = cw.Write([]string{r.Prefix, strconv.FormatUint(r.Bytes, 10), strconv.FormatFloat(r.Mbps, 'f', 2, 64), r.Transit, strings.Join(peers, " "), saving})
	}
	cw.Flush()
	return cw.Error()
}
