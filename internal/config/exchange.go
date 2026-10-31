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
			cost := p.Cost
			if ex.Port != nil && ex.Port.PortCost != nil {
				cost = new(float64)
			}
			c.Providers = append(c.Providers, Provider{
				Name: p.Name, SourceIP: p.SourceIP, NextHop: p.NextHop, Exclude: p.Exclude,
				Group: ex.Group, Precedence: p.Precedence, Cost: cost, BMP: ex.BMP,
				PathCheck: p.PathCheck, FwMark: p.FwMark, DSCP: p.DSCP,
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

// DefaultExchangeMaxPrefixWarnPct is the share of a peer's max_prefix at
// which exchange.max_prefix fires (#147).
const DefaultExchangeMaxPrefixWarnPct = 90

// defaultExchangeMaxPrefix fills in the warning share for each exchange.
func (c *Config) defaultExchangeMaxPrefix() {
	for i := range c.Exchanges {
		if c.Exchanges[i].MaxPrefixWarnPct == 0 {
			c.Exchanges[i].MaxPrefixWarnPct = DefaultExchangeMaxPrefixWarnPct
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
	// Peers included: a neighbor list naming both would be ambiguous.
	own := map[string]bool{}
	for _, p := range c.Providers {
		own[p.Name] = true
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
		if ex.MaxPrefixWarnPct < 1 || ex.MaxPrefixWarnPct > 100 {
			add("%s: max_prefix_warn_pct %d must be between 1 and 100", label, ex.MaxPrefixWarnPct)
		}
		if len(ex.Peers) == 0 {
			add("%s: peers: at least one peer is required", label)
		}
		validateExchangePort(ex, label, add)
		validateLocalLANAddrs(ex, lans, label, add)
		for j, p := range ex.Peers {
			pl := fmt.Sprintf("%s: peers[%d]", label, j)
			if p.Name != "" {
				pl = fmt.Sprintf("%s: peers[%d] (%s)", label, j, p.Name)
			}
			if p.ASN == 0 {
				add("%s: asn is required (the first AS on the peer's paths)", pl)
			}
			if p.MaxPrefix < 0 {
				add("%s: max_prefix %d must not be negative", pl, p.MaxPrefix)
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

// validateLocalLANAddrs checks that each own address is an address on one
// of the exchange's LANs, listed once, and not a peer's next hop.
func validateLocalLANAddrs(ex Exchange, lans []netip.Prefix, label string, add func(string, ...any)) {
	hops := map[netip.Addr]bool{}
	for _, p := range ex.Peers {
		if a, err := netip.ParseAddr(p.NextHop); err == nil {
			hops[a] = true
		}
	}
	seen := map[netip.Addr]bool{}
	for i, s := range ex.LocalLANAddrs {
		a, err := netip.ParseAddr(s)
		switch {
		case err != nil || a.Zone() != "":
			add("%s: local_lan_addrs[%d]: %q is not an IP address", label, i, s)
		case len(lans) > 0 && !slices.ContainsFunc(lans, func(l netip.Prefix) bool { return l.Contains(a) }):
			add("%s: local_lan_addrs[%d]: %s is not inside the exchange lans", label, i, a)
		case seen[a]:
			add("%s: local_lan_addrs[%d]: %s is listed twice", label, i, a)
		case hops[a]:
			add("%s: local_lan_addrs[%d]: %s is a peer next_hop, not this network's address", label, i, a)
		}
		seen[a] = true
	}
}

// maxPortMbps matches the snmp telemetry bound on a commit.
const maxPortMbps = 1e8

func validateExchangePort(ex Exchange, label string, add func(string, ...any)) {
	pt := ex.Port
	if pt == nil {
		return
	}
	if !(pt.CapacityMbps > 0 && pt.CapacityMbps <= maxPortMbps) { // also rejects NaN
		add("%s: port.capacity_mbps must be greater than 0 and at most %.0f", label, maxPortMbps)
	}
	if !(pt.CommitMbps >= 0 && pt.CommitMbps <= pt.CapacityMbps) {
		add("%s: port.commit_mbps %v must be between 0 and capacity_mbps", label, pt.CommitMbps)
	}
	if pt.PortCost == nil {
		return
	}
	if !(*pt.PortCost >= 0 && *pt.PortCost <= 1e9) {
		add("%s: port.port_cost %v must be between 0 and 1000000000", label, *pt.PortCost)
	}
	for j, p := range ex.Peers {
		if p.Cost != nil {
			add("%s: peers[%d] (%s): cost conflicts with port.port_cost (the port fee is the cost; the peer's marginal cost is 0)", label, j, p.Name)
		}
	}
}
