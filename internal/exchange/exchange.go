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
	// Improvements is the number of active improvements onto the peer.
	Improvements int `json:"improvements"`
	// Via is how the router shows this peer (#146): route_server,
	// bilateral, or unknown when the paths disagree, only iBGP add-path
	// has been seen, or the peer has no path. Display only. It is not a
	// route check and it never changes an improvement.
	Via string `json:"via"`
}

// Discovered is a next hop on the peering LAN that no peer uses.
type Discovered struct {
	NextHop  string `json:"next_hop"`
	ASN      uint32 `json:"asn,omitempty"`
	Prefixes int    `json:"prefixes"`
}

// Build joins the configured exchanges with next hop counts from the RIB
// (rib.View.NextHops over every exchange LAN), provider health, and the
// active improvements per provider.
func Build(exs []Exchange, hops []rib.NextHopCount, up map[string]bool, improvements map[string]int) []Stats {
	out := make([]Stats, 0, len(exs))
	for _, ex := range exs {
		st := Stats{Name: ex.Name, LANs: []string{}, Peers: []PeerStats{}, Discovered: []Discovered{}}
		for _, l := range ex.LANs {
			st.LANs = append(st.LANs, l.String())
		}
		byHop := map[netip.Addr]rib.NextHopCount{}
		for _, h := range hops {
			if inLANs(ex.LANs, h.NextHop) {
				byHop[h.NextHop] = h
				st.Prefixes += h.Prefixes
			}
		}
		used := map[netip.Addr]bool{}
		for _, p := range ex.Peers {
			nh := p.NextHop.Unmap()
			used[nh] = true
			h := byHop[nh]
			ps := PeerStats{Name: p.Name, ASN: p.ASN, NextHop: nh.String(), Prefixes: h.Prefixes, Up: up[p.Name], Improvements: improvements[p.Name], Via: h.Via}
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
				st.Discovered = append(st.Discovered, Discovered{NextHop: nh.String(), ASN: h.ASN, Prefixes: h.Prefixes})
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
