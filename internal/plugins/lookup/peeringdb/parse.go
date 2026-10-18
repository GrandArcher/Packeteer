package peeringdb

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

type rawIX struct {
	id                  int
	name, city, country string
}

type rawNet struct {
	id, orgID               int
	asn                     uint32
	name, policy, policyURL string
	p4, p6                  *int
}

type rawLan struct {
	netID, ixID int
	asn         uint32
	ip4, ip6    string
	rs          bool
}

type rawIXF struct {
	asn    uint32
	name   string
	v4, v6 string
	rs     bool
}

type pdbEnvelope struct {
	Data json.RawMessage `json:"data"`
}

type pdbIX struct {
	ID      int      `json:"id"`
	Name    jsString `json:"name"`
	City    jsString `json:"city"`
	Country jsString `json:"country"`
	Status  jsString `json:"status"`
}

type pdbOrg struct {
	ID     int      `json:"id"`
	Name   jsString `json:"name"`
	Status jsString `json:"status"`
}

type pdbNet struct {
	ID        int      `json:"id"`
	OrgID     int      `json:"org_id"`
	Name      jsString `json:"name"`
	ASN       uint32   `json:"asn"`
	Info4     *int     `json:"info_prefixes4"`
	Info6     *int     `json:"info_prefixes6"`
	Policy    jsString `json:"policy_general"`
	PolicyURL jsString `json:"policy_url"`
	Status    jsString `json:"status"`
}

type pdbLan struct {
	NetID  int      `json:"net_id"`
	IXID   int      `json:"ix_id"`
	ASN    uint32   `json:"asn"`
	IP4    jsString `json:"ipaddr4"`
	IP6    jsString `json:"ipaddr6"`
	RS     bool     `json:"is_rs_peer"`
	Status jsString `json:"status"`
}

type ixfDoc struct {
	Version string      `json:"version"`
	Members []ixfMember `json:"member_list"`
}

type ixfMember struct {
	ASN   uint32    `json:"asnum"`
	Name  jsString  `json:"name"`
	Conns []ixfConn `json:"connection_list"`
}

type ixfConn struct {
	State string    `json:"state"`
	VLANs []ixfVLAN `json:"vlan_list"`
}

type ixfVLAN struct {
	V4 *ixfAddr `json:"ipv4"`
	V6 *ixfAddr `json:"ipv6"`
}

type ixfAddr struct {
	Address jsString `json:"address"`
	RS      bool     `json:"routeserver"`
}

// jsString accepts a JSON string or null. A number or object fails the
// document so a changed field type cannot be stored as a blank.
type jsString struct{ s string }

func (j *jsString) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		j.s = ""
		return nil
	}
	return json.Unmarshal(b, &j.s)
}

func decodeIX(body []byte) ([]rawIX, error) {
	var rows []pdbIX
	if err := decodeData(body, &rows); err != nil {
		return nil, err
	}
	out := make([]rawIX, 0, len(rows))
	for _, row := range rows {
		if row.Status.s != "ok" || row.ID <= 0 {
			continue
		}
		if err := bounds(row.Name.s, row.City.s, row.Country.s, "", ""); err != nil {
			return nil, err
		}
		out = append(out, rawIX{id: row.ID, name: row.Name.s, city: row.City.s, country: row.Country.s})
	}
	return out, nil
}

func decodeNet(body []byte) ([]rawNet, error) {
	var rows []pdbNet
	if err := decodeData(body, &rows); err != nil {
		return nil, err
	}
	out := make([]rawNet, 0, len(rows))
	for _, row := range rows {
		if row.Status.s != "ok" || row.ID <= 0 || row.ASN == 0 {
			continue
		}
		if err := bounds(row.Name.s, "", "", row.Policy.s, row.PolicyURL.s); err != nil {
			return nil, err
		}
		out = append(out, rawNet{
			id: row.ID, orgID: row.OrgID, asn: row.ASN, name: row.Name.s,
			policy: row.Policy.s, policyURL: row.PolicyURL.s, p4: row.Info4, p6: row.Info6,
		})
	}
	return out, nil
}

// decodeOrg returns org names by id.
func decodeOrg(body []byte) (map[int]string, error) {
	var rows []pdbOrg
	if err := decodeData(body, &rows); err != nil {
		return nil, err
	}
	out := make(map[int]string, len(rows))
	for _, row := range rows {
		if row.Status.s != "ok" || row.ID <= 0 {
			continue
		}
		if err := bounds(row.Name.s, "", "", "", ""); err != nil {
			return nil, err
		}
		out[row.ID] = row.Name.s
	}
	return out, nil
}

func decodeLAN(body []byte) ([]rawLan, error) {
	var rows []pdbLan
	if err := decodeData(body, &rows); err != nil {
		return nil, err
	}
	out := make([]rawLan, 0, len(rows))
	for _, row := range rows {
		if row.Status.s != "ok" || row.IXID <= 0 || row.ASN == 0 {
			continue
		}
		out = append(out, rawLan{netID: row.NetID, ixID: row.IXID, asn: row.ASN, ip4: row.IP4.s, ip6: row.IP6.s, rs: row.RS})
	}
	return out, nil
}

func decodeData(body []byte, dest any) error {
	var env pdbEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("lookup: invalid JSON")
	}
	if len(env.Data) == 0 || bytes.Equal(env.Data, []byte("null")) {
		return nil
	}
	if err := json.Unmarshal(env.Data, dest); err != nil {
		return fmt.Errorf("lookup: invalid JSON")
	}
	return nil
}

func bounds(name, city, country, policy, policyURL string) error {
	if len(name) > maxNameLen || len(city) > maxPlaceLen || len(country) > maxPlaceLen || len(policy) > maxPolicyLen || len(policyURL) > maxURLLen {
		return fmt.Errorf("lookup: field longer than the cap")
	}
	return nil
}

// decodeIXF parses one IX-F 1.0 export. Every kept member belongs to the
// exchange whose URL was configured. A bad address is skipped. A version
// mismatch, invalid JSON, or an over-long name fails the document.
func decodeIXF(body []byte) ([]rawIXF, error) {
	var doc ixfDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("lookup: invalid JSON")
	}
	if doc.Version != "1.0" {
		return nil, fmt.Errorf("lookup: IX-F version is not 1.0")
	}
	var out []rawIXF
	for _, m := range doc.Members {
		if m.ASN == 0 {
			continue
		}
		if err := bounds(m.Name.s, "", "", "", ""); err != nil {
			return nil, err
		}
		for _, c := range m.Conns {
			if !ixfActive(c.State) {
				continue
			}
			for _, vlan := range c.VLANs {
				row := rawIXF{asn: m.ASN, name: m.Name.s}
				var rs bool
				if vlan.V4 != nil {
					if addr, ok := cleanAddr(vlan.V4.Address.s, true); ok && addr != "" {
						row.v4 = addr
						rs = rs || vlan.V4.RS
					}
				}
				if vlan.V6 != nil {
					if addr, ok := cleanAddr(vlan.V6.Address.s, false); ok && addr != "" {
						row.v6 = addr
						rs = rs || vlan.V6.RS
					}
				}
				if row.v4 == "" && row.v6 == "" {
					continue
				}
				row.rs = rs
				out = append(out, row)
			}
		}
	}
	return out, nil
}

func ixfActive(state string) bool {
	switch state {
	case "", "active", "connected":
		return true
	default:
		return false
	}
}

// cleanAddr reports the address to store. An empty string is valid and
// means that family is absent. A bad address is not valid, so the caller
// drops that family and keeps the rest of the row.
func cleanAddr(raw string, want4 bool) (string, bool) {
	if raw == "" {
		return "", true
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return "", false
	}
	ip = ip.Unmap()
	if want4 && !ip.Is4() || !want4 && !ip.Is6() {
		return "", false
	}
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "", false
	}
	return ip.String(), true
}

func orgIDs(nets []rawNet) []int {
	seen := map[int]bool{}
	var ids []int
	for _, n := range nets {
		if n.orgID <= 0 || seen[n.orgID] {
			continue
		}
		seen[n.orgID] = true
		ids = append(ids, n.orgID)
	}
	sort.Ints(ids)
	return ids
}

func netIDs(lans []rawLan, ixOK map[int]bool) []int {
	seen := map[int]bool{}
	var ids []int
	for _, lan := range lans {
		if !ixOK[lan.ixID] || lan.netID <= 0 || seen[lan.netID] {
			continue
		}
		seen[lan.netID] = true
		ids = append(ids, lan.netID)
	}
	sort.Ints(ids)
	return ids
}

// assemble merges PeeringDB rows with optional IX-F rows. A PeeringDB
// field that is too long, or a PeeringDB result over the row cap, fails
// the refresh so the previous cache stays. An IX-F document that would
// pass the cap is recorded on that exchange and the PeeringDB rows are
// still returned.
func assemble(list []exch, ix []rawIX, nets []rawNet, orgs map[int]string, lans []rawLan, ixf map[string][]rawIXF, ixfErr map[string]string) (plugin.LookupView, error) {
	ixByID := map[int]rawIX{}
	for _, row := range ix {
		ixByID[row.id] = row
	}
	netByID := map[int]rawNet{}
	for _, row := range nets {
		netByID[row.id] = row
	}
	configured := map[int]exch{}
	for _, ex := range list {
		configured[ex.ixID] = ex
	}
	var members []plugin.LookupMembership
	for _, lan := range lans {
		ex, ok := configured[lan.ixID]
		if !ok {
			continue
		}
		meta, ixFound := ixByID[lan.ixID]
		if !ixFound {
			continue
		}
		v4, v4ok := cleanAddr(lan.ip4, true)
		v6, v6ok := cleanAddr(lan.ip6, false)
		if !v4ok {
			v4 = ""
		}
		if !v6ok {
			v6 = ""
		}
		if v4 == "" && v6 == "" {
			continue
		}
		m := plugin.LookupMembership{
			Exchange: ex.name, IXID: lan.ixID, IXName: meta.name,
			ASN: lan.asn, IPv4: v4, IPv6: v6, RouteServer: lan.rs,
		}
		if n, ok := netByID[lan.netID]; ok {
			m.Name = n.name
		}
		members = append(members, m)
	}
	if len(members) > maxMemberships || len(nets) > maxNets {
		return plugin.LookupView{}, fmt.Errorf("lookup: peeringdb result exceeds the row cap")
	}
	networks := networksFrom(nets, orgs)
	for _, ex := range list {
		rows := ixf[ex.name]
		if ixfErr[ex.name] != "" {
			continue
		}
		if len(rows) == 0 {
			continue
		}
		meta := ixByID[ex.ixID]
		merged, addedNets := mergeIXF(ex, meta.name, rows, slices.Clone(members), networks)
		if len(merged) > maxMemberships || len(networks)+len(addedNets) > maxNets {
			if ixfErr == nil {
				ixfErr = map[string]string{}
			}
			ixfErr[ex.name] = "lookup: IX-F result exceeds the row cap"
			continue
		}
		members = merged
		networks = append(networks, addedNets...)
	}
	members = dedupeMembers(members)
	networks = dedupeNetworks(networks)
	if len(members) > maxMemberships || len(networks) > maxNets {
		return plugin.LookupView{}, fmt.Errorf("lookup: peeringdb result exceeds the row cap")
	}
	exchanges := make([]plugin.LookupExchange, len(list))
	for i, ex := range list {
		e := plugin.LookupExchange{Name: ex.name, IXID: ex.ixID, IXFURL: ex.ixfURL, IXFError: ixfErr[ex.name]}
		if meta, ok := ixByID[ex.ixID]; ok {
			e.IXName = meta.name
			e.City = meta.city
			e.Country = meta.country
		} else {
			e.Error = "ix id not in peeringdb"
		}
		exchanges[i] = e
	}
	if members == nil {
		members = []plugin.LookupMembership{}
	}
	if networks == nil {
		networks = []plugin.LookupNetwork{}
	}
	return plugin.LookupView{Exchanges: exchanges, Networks: networks, Memberships: members}, nil
}

func networksFrom(nets []rawNet, orgs map[int]string) []plugin.LookupNetwork {
	out := make([]plugin.LookupNetwork, 0, len(nets))
	for _, n := range nets {
		out = append(out, plugin.LookupNetwork{
			ASN: n.asn, Name: n.name, Org: orgs[n.orgID], Policy: n.policy, PolicyURL: n.policyURL,
			InfoPrefixes4: n.p4, InfoPrefixes6: n.p6,
		})
	}
	return out
}

// mergeIXF attaches IX-F addresses to PeeringDB rows that share a concrete
// address, filling an empty family and OR-ing the route-server flag. A
// different concrete address stays its own row. Networks are added only
// for ASNs the directory did not already name. It changes members in place
// and returns the slice with the new rows appended.
func mergeIXF(ex exch, ixName string, rows []rawIXF, members []plugin.LookupMembership, networks []plugin.LookupNetwork) ([]plugin.LookupMembership, []plugin.LookupNetwork) {
	known := map[uint32]bool{}
	for _, n := range networks {
		known[n.ASN] = true
	}
	byASN := map[uint32][]int{}
	for i, m := range members {
		if m.Exchange == ex.name {
			byASN[m.ASN] = append(byASN[m.ASN], i)
		}
	}
	var addedNets []plugin.LookupNetwork
	for _, row := range rows {
		if i := matchRow(members, byASN[row.asn], row); i >= 0 {
			dst := &members[i]
			if dst.IPv4 == "" {
				dst.IPv4 = row.v4
			}
			if dst.IPv6 == "" {
				dst.IPv6 = row.v6
			}
			dst.RouteServer = dst.RouteServer || row.rs
			if dst.Name == "" {
				dst.Name = row.name
			}
		} else {
			byASN[row.asn] = append(byASN[row.asn], len(members))
			members = append(members, plugin.LookupMembership{
				Exchange: ex.name, IXID: ex.ixID, IXName: ixName,
				ASN: row.asn, Name: row.name, IPv4: row.v4, IPv6: row.v6, RouteServer: row.rs,
			})
		}
		if !known[row.asn] {
			known[row.asn] = true
			addedNets = append(addedNets, plugin.LookupNetwork{ASN: row.asn, Name: row.name})
		}
	}
	return members, addedNets
}

// matchRow returns the index in members, among the candidates, of the row
// that shares the most concrete addresses with row, or -1. A candidate
// that holds a different address in a family row also has is not a match.
func matchRow(members []plugin.LookupMembership, candidates []int, row rawIXF) int {
	best, score := -1, 0
	for _, i := range candidates {
		r := members[i]
		if row.v4 != "" && r.IPv4 != "" && r.IPv4 != row.v4 {
			continue
		}
		if row.v6 != "" && r.IPv6 != "" && r.IPv6 != row.v6 {
			continue
		}
		sh := 0
		if row.v4 != "" && r.IPv4 == row.v4 {
			sh++
		}
		if row.v6 != "" && r.IPv6 == row.v6 {
			sh++
		}
		if sh > score {
			best, score = i, sh
		}
	}
	return best
}

func dedupeMembers(in []plugin.LookupMembership) []plugin.LookupMembership {
	slices.SortFunc(in, func(a, b plugin.LookupMembership) int {
		if c := cmp.Compare(a.Exchange, b.Exchange); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ASN, b.ASN); c != 0 {
			return c
		}
		if c := cmp.Compare(a.IPv4, b.IPv4); c != 0 {
			return c
		}
		return cmp.Compare(a.IPv6, b.IPv6)
	})
	out := make([]plugin.LookupMembership, 0, len(in))
	for _, m := range in {
		if n := len(out); n > 0 {
			p := &out[n-1]
			if p.Exchange == m.Exchange && p.ASN == m.ASN && p.IPv4 == m.IPv4 && p.IPv6 == m.IPv6 {
				p.RouteServer = p.RouteServer || m.RouteServer
				if p.Name == "" {
					p.Name = m.Name
				}
				if p.IXName == "" {
					p.IXName = m.IXName
				}
				continue
			}
		}
		out = append(out, m)
	}
	return out
}

func dedupeNetworks(in []plugin.LookupNetwork) []plugin.LookupNetwork {
	slices.SortFunc(in, func(a, b plugin.LookupNetwork) int { return cmp.Compare(a.ASN, b.ASN) })
	out := make([]plugin.LookupNetwork, 0, len(in))
	for _, n := range in {
		if len(out) > 0 && out[len(out)-1].ASN == n.ASN {
			p := &out[len(out)-1]
			if p.Name == "" {
				p.Name = n.Name
			}
			if p.Org == "" {
				p.Org = n.Org
			}
			if p.Policy == "" {
				p.Policy = n.Policy
			}
			if p.PolicyURL == "" {
				p.PolicyURL = n.PolicyURL
			}
			if p.InfoPrefixes4 == nil {
				p.InfoPrefixes4 = n.InfoPrefixes4
			}
			if p.InfoPrefixes6 == nil {
				p.InfoPrefixes6 = n.InfoPrefixes6
			}
			continue
		}
		out = append(out, n)
	}
	return out
}
