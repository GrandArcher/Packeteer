// Package exchange builds Internet exchange statistics (#27): per peer,
// the prefixes the router shows through its next hop, the observed first
// AS, probe-source health, and active improvements; plus next hops on the
// peering LAN that are not configured peers ("discovered"). It only reads
// state. A discovered next hop is never probed or used for an improvement:
// it becomes a provider only when the operator lists it as a peer.
package exchange

import (
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/rib"
)

// Exchange is one configured exchange.
type Exchange struct {
	Name  string
	LANs  []netip.Prefix
	Peers []Peer
}

// Peer is one configured peer (a provider).
type Peer struct {
	Name    string
	ASN     uint32
	NextHop netip.Addr
}

// Stats is one exchange's statistics.
type Stats struct {
	Name string   `json:"name"`
	LANs []string `json:"lans"`
	// Prefixes is the number of distinct (next hop, prefix) paths seen on
	// the peering LAN, configured peers and discovered ones together.
	Prefixes     int          `json:"prefixes"`
	Improvements int          `json:"improvements"`
	Peers        []PeerStats  `json:"peers"`
	Discovered   []Discovered `json:"discovered"`
	// Degraded is true while enough peers fail their next-hop probe to
	// point at the exchange or our port, not one member (#149).
	// DegradedPeers are those peers and DegradedSince is when it began.
	Degraded      bool      `json:"degraded"`
	DegradedPeers []string  `json:"degraded_peers"`
	DegradedSince time.Time `json:"degraded_since,omitzero"`
}

// PeerStats is one configured peer.
type PeerStats struct {
	Name    string `json:"name"`
	ASN     uint32 `json:"asn"`
	NextHop string `json:"next_hop"`
	// ObservedASN is the most common first AS on paths through the next
	// hop, when it differs from ASN (a misconfigured peer: its paths fail
	// the route check).
	ObservedASN uint32 `json:"observed_asn,omitempty"`
	// Prefixes is the number of prefixes the router shows through the
	// peer's next hop (add-path or BMP make inactive paths visible).
	Prefixes int  `json:"prefixes"`
	Up       bool `json:"up"` // probe source up
	// AdjRIBIn is the router's own Adj-RIB-In route count for the peer's
	// session, from a BMP Statistics Report (#147). 0 when no report has
	// been seen. It is a session count, not the next-hop prefix count.
	AdjRIBIn int `json:"adj_rib_in,omitempty"`
	// Improvements is the number of active improvements onto the peer.
	Improvements int `json:"improvements"`
	// Moves are those improvements and MovedMbps the observed rate of
	// their prefixes together. A prefix whose rate no source reports adds
	// nothing, so MovedMbps is a floor.
	MovedMbps float64 `json:"moved_mbps"`
	Moves     []Move  `json:"moves"`
	// Via is how the router shows this peer (#146): route_server,
	// bilateral, or unknown when the paths disagree, only iBGP add-path
	// has been seen, or the peer has no path. Display only. It is not a
	// route check and it never changes an improvement.
	Via string `json:"via"`
	// Reach is the latest probe of the peer's next hop from its source_ip
	// (#149). Measurement only.
	Reach PeerReach `json:"reach"`
	// Availability compares the route server and bilateral feeds (#156).
	Availability Availability `json:"availability"`
}

// Flags on a member whose route server feed lacks prefixes it sends over a
// bilateral session (#156). Packeteer cannot tell whether the route server,
// the member's export policy, or an import filter dropped them.
const (
	// FlagRSPartial: paths arrive via a route server, and some prefixes
	// arrive only bilaterally.
	FlagRSPartial = "rs_partial"
	// FlagRSMissing: no path arrives via a route server although the
	// exchange shows route server paths for other members, and some
	// prefixes arrive bilaterally.
	FlagRSMissing = "rs_missing"
)

// Availability counts the prefixes through one member's next hop by how
// the router learned them (#156). Same next hop, so this is availability,
// not latency. Only BMP Adj-RIB-In paths are classified, so a peer that is
// not set to bmp: prefer or only shows zeros.
type Availability struct {
	RouteServerOnly int    `json:"route_server_only"`
	BilateralOnly   int    `json:"bilateral_only"`
	Both            int    `json:"both"`
	Flag            string `json:"flag,omitempty"`
}

// availability counts one next hop. rsSeen is true when some member of the
// exchange has a path via a route server.
func availability(h rib.NextHopCount, rsSeen bool) Availability {
	a := Availability{RouteServerOnly: h.RouteServerOnly, BilateralOnly: h.BilateralOnly, Both: h.Both}
	switch {
	case a.BilateralOnly == 0:
	case a.RouteServerOnly+a.Both > 0:
		a.Flag = FlagRSPartial
	case rsSeen:
		a.Flag = FlagRSMissing
	}
	return a
}

// Move is one active improvement onto a peer.
type Move struct {
	Prefix     string    `json:"prefix"`
	Since      time.Time `json:"since,omitzero"`
	VolumeMbps float64   `json:"volume_mbps,omitempty"`
}

// Discovered is a next hop on the peering LAN that no peer uses. It has no
// Availability: the RIB keeps BMP Adj-RIB-In paths only for configured
// providers, so there is nothing to classify.
type Discovered struct {
	NextHop  string `json:"next_hop"`
	ASN      uint32 `json:"asn,omitempty"`
	Prefixes int    `json:"prefixes"`
	// Via is the session type seen for this next hop, as on a peer (#154).
	Via string `json:"via"`
}

// Build joins the configured exchanges with next hop counts from the RIB
// (rib.View.NextHops over every exchange LAN), provider health, and the
// active improvements per provider. health is Health.Snapshot, nil when no
// next hop is probed.
func Build(exs []Exchange, hops []rib.NextHopCount, up map[string]bool, improvements map[string][]Move, health map[string]ExchangeHealth) []Stats {
	out := make([]Stats, 0, len(exs))
	for _, ex := range exs {
		st := Stats{Name: ex.Name, LANs: []string{}, Peers: []PeerStats{}, Discovered: []Discovered{}, DegradedPeers: []string{}}
		hl := health[ex.Name]
		st.Degraded, st.DegradedSince = hl.Degraded, hl.Since
		st.DegradedPeers = append(st.DegradedPeers, hl.DegradedPeers...)
		for _, l := range ex.LANs {
			st.LANs = append(st.LANs, l.String())
		}
		byHop := map[netip.Addr]rib.NextHopCount{}
		rsSeen := false
		for _, h := range hops {
			if inLANs(ex.LANs, h.NextHop) {
				byHop[h.NextHop] = h
				st.Prefixes += h.Prefixes
				rsSeen = rsSeen || h.RouteServerOnly+h.Both > 0
			}
		}
		used := map[netip.Addr]bool{}
		for _, p := range ex.Peers {
			nh := p.NextHop.Unmap()
			used[nh] = true
			h := byHop[nh]
			moves := improvements[p.Name]
			if moves == nil {
				moves = []Move{}
			}
			ps := PeerStats{Name: p.Name, ASN: p.ASN, NextHop: nh.String(), Prefixes: h.Prefixes, Up: up[p.Name], Improvements: len(moves), Moves: moves, Via: h.Via, Availability: availability(h, rsSeen), Reach: PeerReach{State: ReachUnknown}}
			if r, ok := hl.Peers[p.Name]; ok {
				ps.Reach = r
			}
			for _, m := range moves {
				ps.MovedMbps += m.VolumeMbps
			}
			if ps.Via == "" {
				ps.Via = rib.ViaUnknown
			}
			if h.ASN != 0 && h.ASN != p.ASN {
				ps.ObservedASN = h.ASN
			}
			st.Improvements += ps.Improvements
			st.Peers = append(st.Peers, ps)
		}
		for nh, h := range byHop {
			if !used[nh] {
				via := h.Via
				if via == "" {
					via = rib.ViaUnknown
				}
				st.Discovered = append(st.Discovered, Discovered{NextHop: nh.String(), ASN: h.ASN, Prefixes: h.Prefixes, Via: via})
			}
		}
		sort.Slice(st.Discovered, func(i, j int) bool {
			a, b := st.Discovered[i], st.Discovered[j]
			if a.Prefixes != b.Prefixes {
				return a.Prefixes > b.Prefixes
			}
			return netip.MustParseAddr(a.NextHop).Less(netip.MustParseAddr(b.NextHop))
		})
		out = append(out, st)
	}
	return out
}

// LANs is every exchange's peering LANs, for rib.View.NextHops.
func LANs(exs []Exchange) []netip.Prefix {
	var out []netip.Prefix
	for _, ex := range exs {
		out = append(out, ex.LANs...)
	}
	return out
}

func inLANs(lans []netip.Prefix, a netip.Addr) bool {
	for _, l := range lans {
		if l.Contains(a) {
			return true
		}
	}
	return false
}
