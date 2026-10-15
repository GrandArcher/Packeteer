package ixf

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds on one document. A document past any of them is rejected whole;
// nothing is truncated into the served list.
const (
	maxMembers     = 20000
	maxIXPs        = 64
	maxSwitches    = 4000
	maxSwitchesIXP = 2000
	maxConns       = 64
	maxIfaces      = 64
	maxVLANs       = 32
	maxIXPVLANs    = 256
	maxString      = 256
)

type parsed struct {
	ixps      []plugin.IXPSite
	members   []plugin.IXPMember
	addresses int
}

type ixfDoc struct {
	Version json.RawMessage `json:"version"`
	IXPs    []ixfIXP        `json:"ixp_list"`
	Members []ixfMember     `json:"member_list"`
}

type ixfIXP struct {
	ID        int         `json:"ixp_id"`
	Shortname string      `json:"shortname"`
	Name      string      `json:"name"`
	VLANs     []ixfVLAN   `json:"vlan"`
	Switches  []ixfSwitch `json:"switch"`
}

type ixfVLAN struct {
	ID   int     `json:"id"`
	Name string  `json:"name"`
	IPv4 *ixfPfx `json:"ipv4"`
	IPv6 *ixfPfx `json:"ipv6"`
}

type ixfPfx struct {
	Prefix string `json:"prefix"`
	Mask   int    `json:"mask_length"`
}

type ixfSwitch struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Colo         string `json:"colo"`
	City         string `json:"city"`
	Country      string `json:"country"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Software     string `json:"software"`
}

type ixfMember struct {
	ASN         int64     `json:"asnum"`
	Name        string    `json:"name"`
	Connections []ixfConn `json:"connection_list"`
}

type ixfConn struct {
	IXPID int      `json:"ixp_id"`
	State string   `json:"state"`
	Ifs   []ixfIf  `json:"if_list"`
	VLANs []ixfMVL `json:"vlan_list"`
}

type ixfIf struct {
	SwitchID int  `json:"switch_id"`
	Speed    int  `json:"if_speed"`
	Phys     *int `json:"if_phys_speed"`
}

type ixfMVL struct {
	ID   int      `json:"vlan_id"`
	IPv4 *ixfAddr `json:"ipv4"`
	IPv6 *ixfAddr `json:"ipv6"`
}

type ixfAddr struct {
	Address     string `json:"address"`
	RouteServer bool   `json:"routeserver"`
	ASMacro     string `json:"as_macro"`
	MaxPrefix   int    `json:"max_prefix"`
}

type swInfo struct {
	name string
	colo string
}

// parseIXF reads an IX-F 1.0 document. Unknown JSON fields are ignored.
// Contact email, phone, and MAC addresses are not copied. Errors name a
// JSON path and do not include the field value.
func parseIXF(body []byte) (parsed, error) {
	var doc ixfDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return parsed{}, errors.New("member export: invalid JSON")
	}
	if string(doc.Version) != `"1.0"` {
		return parsed{}, errors.New(`member export: version must be "1.0"`)
	}
	if len(doc.IXPs) > maxIXPs {
		return parsed{}, fmt.Errorf("ixp_list: more than %d entries", maxIXPs)
	}
	if len(doc.Members) > maxMembers {
		return parsed{}, fmt.Errorf("member_list: more than %d entries", maxMembers)
	}
	switches := map[int]map[int]swInfo{}
	ixps := make([]plugin.IXPSite, 0, len(doc.IXPs))
	totalSW := 0
	for i, ix := range doc.IXPs {
		p := fmt.Sprintf("ixp_list[%d]", i)
		site, err := convIXP(p, ix)
		if err != nil {
			return parsed{}, err
		}
		if len(ix.Switches) > maxSwitchesIXP {
			return parsed{}, fmt.Errorf("%s.switch: more than %d entries", p, maxSwitchesIXP)
		}
		totalSW += len(ix.Switches)
		if totalSW > maxSwitches {
			return parsed{}, fmt.Errorf("ixp_list: more than %d switches", maxSwitches)
		}
		byID := map[int]swInfo{}
		for _, sw := range site.Switches {
			if _, ok := byID[sw.ID]; !ok {
				byID[sw.ID] = swInfo{name: sw.Name, colo: sw.Colo}
			}
		}
		switches[site.ID] = byID
		ixps = append(ixps, site)
	}
	slices.SortStableFunc(ixps, func(a, b plugin.IXPSite) int { return cmp.Compare(a.ID, b.ID) })

	members := make([]plugin.IXPMember, 0, len(doc.Members))
	addrs := 0
	for i, m := range doc.Members {
		p := fmt.Sprintf("member_list[%d]", i)
		mem, n, err := convMember(p, m, switches)
		if err != nil {
			return parsed{}, err
		}
		addrs += n
		members = append(members, mem)
	}
	slices.SortStableFunc(members, func(a, b plugin.IXPMember) int {
		if a.ASN != b.ASN {
			return cmp.Compare(a.ASN, b.ASN)
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return parsed{ixps: ixps, members: members, addresses: addrs}, nil
}

func convIXP(p string, in ixfIXP) (plugin.IXPSite, error) {
	if in.ID < 0 {
		return plugin.IXPSite{}, fmt.Errorf("%s.ixp_id is negative", p)
	}
	if err := clip(p+".shortname", in.Shortname); err != nil {
		return plugin.IXPSite{}, err
	}
	if err := clip(p+".name", in.Name); err != nil {
		return plugin.IXPSite{}, err
	}
	if len(in.VLANs) > maxIXPVLANs {
		return plugin.IXPSite{}, fmt.Errorf("%s.vlan: more than %d entries", p, maxIXPVLANs)
	}
	vlans := make([]plugin.IXPVLAN, 0, len(in.VLANs))
	for i, v := range in.VLANs {
		vp := fmt.Sprintf("%s.vlan[%d]", p, i)
		if err := clip(vp+".name", v.Name); err != nil {
			return plugin.IXPSite{}, err
		}
		out := plugin.IXPVLAN{ID: v.ID, Name: v.Name}
		var err error
		if out.IPv4, err = convPfx(vp+".ipv4", v.IPv4, 32); err != nil {
			return plugin.IXPSite{}, err
		}
		if out.IPv6, err = convPfx(vp+".ipv6", v.IPv6, 128); err != nil {
			return plugin.IXPSite{}, err
		}
		vlans = append(vlans, out)
	}
	slices.SortStableFunc(vlans, func(a, b plugin.IXPVLAN) int { return cmp.Compare(a.ID, b.ID) })
	sws := make([]plugin.IXPSwitch, 0, len(in.Switches))
	for i, s := range in.Switches {
		sp := fmt.Sprintf("%s.switch[%d]", p, i)
		if s.ID < 0 {
			return plugin.IXPSite{}, fmt.Errorf("%s.id is negative", sp)
		}
		for _, pair := range []struct{ path, val string }{
			{sp + ".name", s.Name}, {sp + ".colo", s.Colo}, {sp + ".city", s.City},
			{sp + ".country", s.Country}, {sp + ".manufacturer", s.Manufacturer},
			{sp + ".model", s.Model}, {sp + ".software", s.Software},
		} {
			if err := clip(pair.path, pair.val); err != nil {
				return plugin.IXPSite{}, err
			}
		}
		sws = append(sws, plugin.IXPSwitch{
			ID: s.ID, Name: s.Name, Colo: s.Colo, City: s.City, Country: s.Country,
			Manufacturer: s.Manufacturer, Model: s.Model, Software: s.Software,
		})
	}
	slices.SortStableFunc(sws, func(a, b plugin.IXPSwitch) int { return cmp.Compare(a.ID, b.ID) })
	return plugin.IXPSite{ID: in.ID, Shortname: in.Shortname, Name: in.Name, VLANs: vlans, Switches: sws}, nil
}

func convPfx(p string, in *ixfPfx, bits int) (string, error) {
	if in == nil {
		return "", nil
	}
	if err := clip(p+".prefix", in.Prefix); err != nil {
		return "", err
	}
	a, err := netip.ParseAddr(in.Prefix)
	if err != nil || a.Zone() != "" || a.BitLen() != bits {
		return "", fmt.Errorf("%s.prefix is not an IP address", p)
	}
	if in.Mask < 0 || in.Mask > bits {
		return "", fmt.Errorf("%s.mask_length is invalid", p)
	}
	// Unmap before PrefixFrom. An IPv4-mapped address in the IPv6 object
	// becomes IPv4: a mask above 32 is not a valid prefix, and a mask of
	// 0-32 would be stored as an IPv4 CIDR on the IPv6 field. convAddr
	// rejects that address.
	pfx := netip.PrefixFrom(a.Unmap(), in.Mask).Masked()
	if !pfx.IsValid() || pfx.Addr().BitLen() != bits {
		return "", fmt.Errorf("%s.prefix is not an IP address", p)
	}
	return pfx.String(), nil
}

func convMember(p string, in ixfMember, switches map[int]map[int]swInfo) (plugin.IXPMember, int, error) {
	if in.ASN <= 0 || in.ASN > 0xffffffff {
		return plugin.IXPMember{}, 0, fmt.Errorf("%s.asnum is invalid", p)
	}
	if err := clip(p+".name", in.Name); err != nil {
		return plugin.IXPMember{}, 0, err
	}
	if len(in.Connections) > maxConns {
		return plugin.IXPMember{}, 0, fmt.Errorf("%s.connection_list: more than %d entries", p, maxConns)
	}
	conns := make([]plugin.IXPConnection, 0, len(in.Connections))
	addrs := 0
	for i, c := range in.Connections {
		cp := fmt.Sprintf("%s.connection_list[%d]", p, i)
		conn, n, err := convConn(cp, c, switches)
		if err != nil {
			return plugin.IXPMember{}, 0, err
		}
		addrs += n
		conns = append(conns, conn)
	}
	slices.SortStableFunc(conns, func(a, b plugin.IXPConnection) int { return cmp.Compare(a.IXPID, b.IXPID) })
	return plugin.IXPMember{ASN: uint32(in.ASN), Name: in.Name, Connections: conns}, addrs, nil
}

func convConn(p string, in ixfConn, switches map[int]map[int]swInfo) (plugin.IXPConnection, int, error) {
	if err := clip(p+".state", in.State); err != nil {
		return plugin.IXPConnection{}, 0, err
	}
	if len(in.Ifs) > maxIfaces {
		return plugin.IXPConnection{}, 0, fmt.Errorf("%s.if_list: more than %d entries", p, maxIfaces)
	}
	if len(in.VLANs) > maxVLANs {
		return plugin.IXPConnection{}, 0, fmt.Errorf("%s.vlan_list: more than %d entries", p, maxVLANs)
	}
	ifaces := make([]plugin.IXPInterface, 0, len(in.Ifs))
	for i, iface := range in.Ifs {
		ip := fmt.Sprintf("%s.if_list[%d]", p, i)
		if iface.SwitchID < 0 {
			return plugin.IXPConnection{}, 0, fmt.Errorf("%s.switch_id is negative", ip)
		}
		if iface.Speed < 0 {
			return plugin.IXPConnection{}, 0, fmt.Errorf("%s.if_speed is negative", ip)
		}
		if iface.Phys != nil && *iface.Phys < 0 {
			return plugin.IXPConnection{}, 0, fmt.Errorf("%s.if_phys_speed is negative", ip)
		}
		out := plugin.IXPInterface{SwitchID: iface.SwitchID, SpeedMbps: iface.Speed, PhysSpeedMbps: iface.Phys}
		// switch_id is only meaningful on this connection's IXP. The same
		// id on another IXP is a different switch, and map iteration would
		// pick one of them at random.
		if info, ok := switches[in.IXPID][iface.SwitchID]; ok {
			out.Switch = info.name
			out.Colo = info.colo
		}
		ifaces = append(ifaces, out)
	}
	slices.SortStableFunc(ifaces, func(a, b plugin.IXPInterface) int { return cmp.Compare(a.SwitchID, b.SwitchID) })
	addresses := make([]plugin.IXPAddress, 0)
	for i, v := range in.VLANs {
		vp := fmt.Sprintf("%s.vlan_list[%d]", p, i)
		for _, fam := range []struct {
			name string
			addr *ixfAddr
		}{{"ipv4", v.IPv4}, {"ipv6", v.IPv6}} {
			if fam.addr == nil {
				continue
			}
			ap := vp + "." + fam.name
			a, err := convAddr(ap, fam.name, v.ID, fam.addr)
			if err != nil {
				return plugin.IXPConnection{}, 0, err
			}
			addresses = append(addresses, a)
		}
	}
	slices.SortStableFunc(addresses, func(a, b plugin.IXPAddress) int {
		if a.VLANID != b.VLANID {
			return cmp.Compare(a.VLANID, b.VLANID)
		}
		if a.Family != b.Family {
			return cmp.Compare(a.Family, b.Family)
		}
		return cmp.Compare(a.Address, b.Address)
	})
	return plugin.IXPConnection{IXPID: in.IXPID, State: in.State, Interfaces: ifaces, Addresses: addresses}, len(addresses), nil
}

func convAddr(p, family string, vlan int, in *ixfAddr) (plugin.IXPAddress, error) {
	if err := clip(p+".address", in.Address); err != nil {
		return plugin.IXPAddress{}, err
	}
	if err := clip(p+".as_macro", in.ASMacro); err != nil {
		return plugin.IXPAddress{}, err
	}
	if in.MaxPrefix < 0 {
		return plugin.IXPAddress{}, fmt.Errorf("%s.max_prefix is negative", p)
	}
	a, err := netip.ParseAddr(in.Address)
	if err != nil || a.Zone() != "" {
		return plugin.IXPAddress{}, fmt.Errorf("%s.address is not an IP address", p)
	}
	a = a.Unmap()
	switch family {
	case "ipv4":
		if !a.Is4() {
			return plugin.IXPAddress{}, fmt.Errorf("%s.address is not an IPv4 address", p)
		}
	case "ipv6":
		if !a.Is6() {
			return plugin.IXPAddress{}, fmt.Errorf("%s.address is not an IPv6 address", p)
		}
	}
	return plugin.IXPAddress{
		Family: family, Address: a.String(), VLANID: vlan,
		RouteServer: in.RouteServer, MaxPrefix: in.MaxPrefix, ASMacro: in.ASMacro,
	}, nil
}

func clip(path, s string) error {
	if len(s) > maxString {
		return fmt.Errorf("%s is longer than %d bytes", path, maxString)
	}
	return nil
}
