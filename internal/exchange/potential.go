package exchange

import (
	"cmp"
	"encoding/csv"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Classes of a destination origin ASN in the potential-peers report (#154).
// They say how the exchanges show the ASN, not what to do about it.
const (
	// ClassRouteServer: a member with this AS has paths via a route server.
	// If its traffic takes no LAN path, check our route server session or
	// filters.
	ClassRouteServer = "route_server"
	// ClassBilateral: members with this AS were seen only on bilateral
	// sessions, so it is not on the route server as far as the view shows.
	// A candidate for a peering request.
	ClassBilateral = "bilateral"
	// ClassUnknown: a member with this AS is on a LAN, but the view cannot
	// tell the session type (no BMP Adj-RIB-In paths).
	ClassUnknown = "unknown"
	// ClassAbsent: no configured peer or LAN member has this AS.
	ClassAbsent = "absent"
)

// ValidPotentialClass reports whether c is a class, for the API filter.
func ValidPotentialClass(c string) bool {
	switch c {
	case ClassRouteServer, ClassBilateral, ClassUnknown, ClassAbsent:
		return true
	}
	return false
}

// PotentialInput is what BuildPotentialPeers reads. Nothing in it is
// written back.
type PotentialInput struct {
	Volumes []plugin.PrefixVolume
	// Origin is the origin AS of the learned route that covers the prefix;
	// false when there is none or it is not a destination.
	Origin func(netip.Prefix) (uint32, bool)
	// OnLAN reports whether some learned path for the covering route has a
	// next hop on an exchange LAN.
	OnLAN func(netip.Prefix) bool
	// Exchanges supply the members: configured peers and discovered LAN
	// next hops.
	Exchanges []Stats
}

// MemberRef is an exchange member with the AS of a row.
type MemberRef struct {
	Exchange string `json:"exchange"`
	// Peer names the configured peer; empty for a discovered next hop.
	Peer    string `json:"peer,omitempty"`
	NextHop string `json:"next_hop"`
	Via     string `json:"via"`
}

// PotentialRow is one destination origin AS.
type PotentialRow struct {
	ASN   uint32  `json:"asn"`
	Class string  `json:"class"`
	Bytes uint64  `json:"bytes"`
	Mbps  float64 `json:"mbps"`
	// Prefixes counts the AS's prefixes with traffic, and LANPrefixes and
	// LANBytes those that have a learned path through an exchange LAN today.
	Prefixes    int         `json:"prefixes"`
	LANPrefixes int         `json:"lan_prefixes"`
	LANBytes    uint64      `json:"lan_bytes"`
	Members     []MemberRef `json:"members"`
}

// ClassTotal is the ASNs and bytes of one class.
type ClassTotal struct {
	ASNs  int    `json:"asns"`
	Bytes uint64 `json:"bytes"`
}

// PotentialPeers is the report (#154).
type PotentialPeers struct {
	// ASNs, Bytes, and Mbps total the rows of the asked class, before any
	// cut. Classes totals every class.
	ASNs    int                   `json:"asns"`
	Bytes   uint64                `json:"bytes"`
	Mbps    float64               `json:"mbps"`
	Classes map[string]ClassTotal `json:"classes"`
	// UnattributedBytes had no covering learned route or an origin the
	// caller skips (the local AS), so they belong to no row.
	UnattributedBytes uint64 `json:"unattributed_bytes"`
	// Truncated is true when Rows holds fewer than ASNs rows.
	Truncated bool           `json:"truncated"`
	Rows      []PotentialRow `json:"rows"`
}

// BuildPotentialPeers ranks destination origin ASNs by flow bytes and
// joins each with the exchange members that carry its AS and with whether
// its prefixes have a path through an exchange LAN today. class "" keeps
// every class. It is a report: no session is opened and nothing is
// announced.
func BuildPotentialPeers(in PotentialInput, class string, limit int) PotentialPeers {
	members := map[uint32][]MemberRef{}
	for _, ex := range in.Exchanges {
		for _, p := range ex.Peers {
			if p.ASN != 0 {
				members[p.ASN] = append(members[p.ASN], MemberRef{Exchange: ex.Name, Peer: p.Name, NextHop: p.NextHop, Via: p.Via})
			}
		}
		for _, d := range ex.Discovered {
			if d.ASN != 0 {
				members[d.ASN] = append(members[d.ASN], MemberRef{Exchange: ex.Name, NextHop: d.NextHop, Via: d.Via})
			}
		}
	}
	out := PotentialPeers{Classes: map[string]ClassTotal{}, Rows: []PotentialRow{}}
	byASN := map[uint32]*PotentialRow{}
	for _, v := range in.Volumes {
		if v.Bytes == 0 {
			continue
		}
		asn, ok := in.Origin(v.Prefix)
		if !ok {
			out.UnattributedBytes += v.Bytes
			continue
		}
		r := byASN[asn]
		if r == nil {
			r = &PotentialRow{ASN: asn, Members: []MemberRef{}}
			if m := members[asn]; m != nil {
				r.Members = m
			}
			r.Class = classOf(r.Members)
			byASN[asn] = r
		}
		r.Bytes += v.Bytes
		r.Mbps += v.Mbps()
		r.Prefixes++
		if in.OnLAN(v.Prefix) {
			r.LANPrefixes++
			r.LANBytes += v.Bytes
		}
	}
	var rows []PotentialRow
	for _, r := range byASN {
		t := out.Classes[r.Class]
		t.ASNs++
		t.Bytes += r.Bytes
		out.Classes[r.Class] = t
		if class != "" && r.Class != class {
			continue
		}
		out.ASNs++
		out.Bytes += r.Bytes
		out.Mbps += r.Mbps
		rows = append(rows, *r)
	}
	slices.SortFunc(rows, func(a, b PotentialRow) int {
		if c := cmp.Compare(b.Bytes, a.Bytes); c != 0 {
			return c
		}
		return cmp.Compare(a.ASN, b.ASN)
	})
	if limit > 0 && len(rows) > limit {
		rows, out.Truncated = rows[:limit], true
	}
	for i := range rows {
		rows[i].Mbps = round(rows[i].Mbps)
	}
	out.Mbps = round(out.Mbps)
	if rows != nil {
		out.Rows = rows
	}
	return out
}

// classOf is route_server when any member shows a route server, else
// bilateral when any member is bilateral, else unknown; absent without a
// member.
func classOf(members []MemberRef) string {
	if len(members) == 0 {
		return ClassAbsent
	}
	class := ClassUnknown
	for _, m := range members {
		switch m.Via {
		case rib.ViaRouteServer:
			return ClassRouteServer
		case rib.ViaBilateral:
			class = ClassBilateral
		}
	}
	return class
}

// WriteCSV writes the rows, with the members joined by a space as
// exchange/peer-or-next-hop.
func (r PotentialPeers) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"asn", "class", "bytes", "mbps", "prefixes", "lan_prefixes", "lan_bytes", "members"})
	for _, row := range r.Rows {
		ms := make([]string, len(row.Members))
		for i, m := range row.Members {
			who := m.Peer
			if who == "" {
				who = m.NextHop
			}
			ms[i] = m.Exchange + "/" + who
		}
		_ = cw.Write([]string{
			"AS" + strconv.FormatUint(uint64(row.ASN), 10), row.Class,
			strconv.FormatUint(row.Bytes, 10), strconv.FormatFloat(row.Mbps, 'f', 2, 64),
			strconv.Itoa(row.Prefixes), strconv.Itoa(row.LANPrefixes), strconv.FormatUint(row.LANBytes, 10),
			strings.Join(ms, " "),
		})
	}
	cw.Flush()
	return cw.Error()
}
