package config

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// expandExchanges appends every exchange peer to Providers and replaces an
// exchange name in a neighbor's providers or next_hops with its peers
// (#27). It runs once, in Parse, before validation; broken entries are
// expanded as they are and reported by Validate.
func (c *Config) expandExchanges() {
	if len(c.Exchanges) == 0 {
		return
	}
	addPath := slices.ContainsFunc(c.BGP.Neighbors, func(n BGPNeighbor) bool { return n.AddPath })
	peers := map[string][]string{}
	for _, ex := range c.Exchanges {
		bmp := strings.ToLower(strings.TrimSpace(ex.BMP))
		for _, p := range ex.Peers {
			c.Providers = append(c.Providers, Provider{
				Name: p.Name, SourceIP: p.SourceIP, NextHop: p.NextHop, Exclude: p.Exclude,
				Group: ex.Group, Precedence: p.Precedence, Cost: p.Cost, BMP: ex.BMP,
				// The add-path route check reads the iBGP paths; with bmp
				// only they are ignored, and BMP alone checks the peer.
				AddPath:  addPath && bmp != BMPOnly,
				Exchange: ex.Name, PeerASN: p.ASN,
			})
			peers[ex.Name] = append(peers[ex.Name], p.Name)
		}
	}
	for i := range c.BGP.Neighbors {
		n := &c.BGP.Neighbors[i]
		var list []string
		for _, name := range n.Providers {
			if ps, ok := peers[name]; ok {
				list = append(list, ps...)
			} else {
				list = append(list, name)
			}
		}
		n.Providers = list
		for _, name := range slices.Sorted(maps.Keys(n.NextHops)) {
			ps, ok := peers[name]
			if !ok {
				continue
			}
			nh := n.NextHops[name]
			delete(n.NextHops, name)
			for _, p := range ps {
				if _, set := n.NextHops[p]; !set {
					n.NextHops[p] = nh
				}
			}
		}
	}
}

// validateExchanges checks the exchange entries. The peers themselves are
// providers by now and get the provider checks (unique name, source_ip,
// next_hop, bmp, cost, precedence) there.
func (c *Config) validateExchanges(add func(string, ...any)) {
	if len(c.Exchanges) == 0 {
		return
	}
	if len(c.BGP.Neighbors) == 0 {
		add("exchanges require bgp.neighbors (a peer is used only while the router shows its path for the prefix)")
	}
	addPath := slices.ContainsFunc(c.BGP.Neighbors, func(n BGPNeighbor) bool { return n.AddPath })
	own := map[string]bool{}
	for _, p := range c.Providers {
		if p.Exchange == "" {
			own[p.Name] = true
		}
	}
	names := map[string]bool{}
	for i, ex := range c.Exchanges {
		label := fmt.Sprintf("exchanges[%d]", i)
		switch {
		case ex.Name == "":
			add("%s: name is required", label)
		case !validProviderGroup(ex.Name):
			add("%s: name %q must be 1-64 characters of letters, digits, '_', '.' or '-', starting with a letter or digit", label, ex.Name)
		case names[ex.Name]:
			add("%s (%s): duplicate exchange name", label, ex.Name)
		case own[ex.Name]:
			add("%s (%s): name is also a provider name", label, ex.Name)
		}
		if ex.Name != "" {
			label = fmt.Sprintf("exchanges[%d] (%s)", i, ex.Name)
			names[ex.Name] = true
		}
		var lans []netip.Prefix
		if len(ex.LANs) == 0 {
			add("%s: lans: at least one peering LAN prefix is required", label)
		}
		for j, s := range ex.LANs {
			p, err := netip.ParsePrefix(s)
			if err != nil || p != p.Masked() {
				add("%s: lans[%d]: %q is not a CIDR without host bits", label, j, s)
				continue
			}
			lans = append(lans, p)
		}
		bmp := strings.ToLower(strings.TrimSpace(ex.BMP))
		if !addPath && bmp != BMPPrefer && bmp != BMPOnly {
			add("%s: peers need their paths visible: set add_path on a bgp.neighbors entry, or bmp: prefer or only with rib_sources", label)
		}
		if len(ex.Peers) == 0 {
			add("%s: peers: at least one peer is required", label)
		}
		for j, p := range ex.Peers {
			pl := fmt.Sprintf("%s: peers[%d]", label, j)
			if p.Name != "" {
				pl = fmt.Sprintf("%s: peers[%d] (%s)", label, j, p.Name)
			}
			if p.ASN == 0 {
				add("%s: asn is required (the first AS on the peer's paths)", pl)
			}
			nh, err := netip.ParseAddr(p.NextHop)
			if err != nil {
				continue // reported with the providers
			}
			if len(lans) > 0 && !slices.ContainsFunc(lans, func(l netip.Prefix) bool { return l.Contains(nh) }) {
				add("%s: next_hop %s is not inside the exchange lans", pl, nh)
			}
		}
	}
}

// ExchangeLANs parses an exchange's peering LANs, skipping invalid ones
// (Validate reports them).
func (e Exchange) ExchangeLANs() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range e.LANs {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}
