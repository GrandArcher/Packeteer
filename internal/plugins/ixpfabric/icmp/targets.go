package icmp

import (
	"net/netip"
	"sort"
	"time"

	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// IXP Manager's default Nagios ping thresholds. A parsed check_command
// replaces the pair for that host. Warning is the tolerance; critical RTT
// is the minimum per-packet timeout for a busy host so a slow reply is a
// reply and not a loss.
var (
	tolNormal = tolerance{warnRTT: 250 * time.Millisecond, warnLoss: 20, critRTT: 500 * time.Millisecond}
	tolBusy   = tolerance{warnRTT: 1000 * time.Millisecond, warnLoss: 80, critRTT: 2 * time.Second}
)

// tolerance is one host's ping warning and the critical RTT.
type tolerance struct {
	warnRTT  time.Duration
	warnLoss float64
	critRTT  time.Duration
}

// nagiosHost is one address in a Can Ping list.
type nagiosHost struct {
	canPing bool
	busy    bool
	tol     tolerance
	haveTol bool
}

type target struct {
	vantage  string
	source   netip.Addr
	addr     netip.Addr
	asn      uint32
	name     string
	family   string
	vlan     int
	ixp      int
	switches []plugin.FabricSwitch
	busy     bool
	tol      tolerance
}

func (t target) base(now time.Time) plugin.FabricSample {
	return plugin.FabricSample{
		Vantage: t.vantage, ASN: t.asn, Name: t.name, Address: t.addr.String(),
		Family: t.family, VLANID: t.vlan, IXPID: t.ixp, Switches: t.switches,
		BusyHost: t.busy, At: now,
	}
}

func (t target) measured(now time.Time, res plugin.ProbeResult) plugin.FabricSample {
	st := probe.Compute(res)
	s := t.base(now)
	s.Sent = st.Sent
	s.Received = st.Received
	s.LossPct = st.LossPct
	s.RTTMs = float64(st.RTTAvg) / float64(time.Millisecond)
	s.JitterMs = float64(st.Jitter) / float64(time.Millisecond)
	s.PastTolerance = pastTolerance(st, t.tol)
	return s
}

func (t target) errored(now time.Time, msg string) plugin.FabricSample {
	s := t.base(now)
	s.Error = msg
	return s
}

func pastTolerance(st probe.Stats, tol tolerance) bool {
	if st.Sent == 0 {
		return false
	}
	if st.LossPct >= tol.warnLoss {
		return true
	}
	return st.Received > 0 && st.RTTAvg >= tol.warnRTT
}

// selectTargets picks member LAN addresses a vantage may probe.
// An address outside the VLAN prefix is not a target: fabric probes stay
// on the peering LAN. Opt-out addresses are counted and not returned.
// The first member that owns an address wins.
func selectTargets(view plugin.MemberView, vantages []plugin.FabricVantage, parts map[string]map[string]nagiosHost) ([]target, int, []plugin.FabricVantageStatus) {
	statuses := make([]plugin.FabricVantageStatus, 0, len(vantages))
	var targets []target
	seen := map[string]bool{}
	optOut := 0
	// The lowest ASN that owns an address decides the opt-out and the name.
	order := make([]int, len(view.Members))
	for i := range view.Members {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return view.Members[order[i]].ASN < view.Members[order[j]].ASN
	})
	for _, v := range vantages {
		st := plugin.FabricVantageStatus{Name: v.Name, Address: v.Address.String(), VLANID: v.VLANID, IXPID: v.IXPID}
		vlan, ixpID, errMsg := findVLAN(view, v)
		if errMsg != "" {
			st.Error = errMsg
			statuses = append(statuses, st)
			continue
		}
		st.IXPID = ixpID
		pfx, ok := vlanPrefix(vlan, v.Address)
		if !ok || !pfx.Contains(v.Address) {
			st.Error = "vantage address is not on the peering LAN"
			statuses = append(statuses, st)
			continue
		}
		statuses = append(statuses, st)
		for _, mi := range order {
			m := view.Members[mi]
			for _, c := range m.Connections {
				if c.IXPID != ixpID || !upState(c.State) {
					continue
				}
				sw := switchesOf(c)
				for _, a := range c.Addresses {
					if a.VLANID != v.VLANID || !sameFamily(a.Family, v.Address) {
						continue
					}
					addr, err := netip.ParseAddr(a.Address)
					if err != nil {
						continue
					}
					addr = addr.Unmap()
					if !pfx.Contains(addr) || addr == v.Address {
						continue
					}
					key := v.Name + "/" + addr.String()
					if seen[key] {
						continue
					}
					seen[key] = true
					skip, busy, tol := pingRule(parts, a)
					if skip {
						optOut++
						continue
					}
					targets = append(targets, target{
						vantage: v.Name, source: v.Address, addr: addr, asn: m.ASN, name: m.Name,
						family: a.Family, vlan: a.VLANID, ixp: ixpID, switches: sw, busy: busy, tol: tol,
					})
				}
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].vantage != targets[j].vantage {
			return targets[i].vantage < targets[j].vantage
		}
		return targets[i].addr.Compare(targets[j].addr) < 0
	})
	return targets, optOut, statuses
}

func findVLAN(view plugin.MemberView, v plugin.FabricVantage) (plugin.IXPVLAN, int, string) {
	type hit struct {
		vlan plugin.IXPVLAN
		ixp  int
	}
	var hits []hit
	for _, site := range view.IXPs {
		if v.IXPID != 0 && site.ID != v.IXPID {
			continue
		}
		for _, vlan := range site.VLANs {
			if vlan.ID == v.VLANID {
				hits = append(hits, hit{vlan, site.ID})
			}
		}
	}
	switch len(hits) {
	case 0:
		return plugin.IXPVLAN{}, 0, "vlan_id is not in the member list"
	case 1:
		return hits[0].vlan, hits[0].ixp, ""
	default:
		return plugin.IXPVLAN{}, 0, "vlan_id is on more than one ixp; set ixp_id"
	}
}

func vlanPrefix(vlan plugin.IXPVLAN, addr netip.Addr) (netip.Prefix, bool) {
	raw := vlan.IPv4
	if addr.Is6() {
		raw = vlan.IPv6
	}
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p, true
}

func sameFamily(family string, addr netip.Addr) bool {
	if addr.Is4() {
		return family == "ipv4"
	}
	return family == "ipv6"
}

func upState(s string) bool {
	switch s {
	case "active", "connected", "operational":
		return true
	default:
		return false
	}
}

func switchesOf(c plugin.IXPConnection) []plugin.FabricSwitch {
	if len(c.Interfaces) == 0 {
		return nil
	}
	out := make([]plugin.FabricSwitch, len(c.Interfaces))
	for i, iface := range c.Interfaces {
		out[i] = plugin.FabricSwitch{ID: iface.SwitchID, Name: iface.Switch, Colo: iface.Colo}
	}
	return out
}

// pingRule applies an IX-F opt-out and, when the address is in a Can Ping
// list, that list. Either source can opt out. Nagios busy-host wins when
// the address is in the list; otherwise the IX-F busy_host flag does.
func pingRule(parts map[string]map[string]nagiosHost, a plugin.IXPAddress) (skip, busy bool, tol tolerance) {
	if a.CanPing != nil && !*a.CanPing {
		return true, false, tolerance{}
	}
	addr := a.Address
	if parsed, err := netip.ParseAddr(a.Address); err == nil {
		addr = parsed.Unmap().String()
	}
	var hit nagiosHost
	var ok bool
	if by := parts[famKey(a.VLANID, a.Family)]; by != nil {
		hit, ok = by[addr]
	}
	if ok && !hit.canPing {
		return true, false, tolerance{}
	}
	if ok {
		tol = hit.tol
		if !hit.haveTol {
			if hit.busy {
				tol = tolBusy
			} else {
				tol = tolNormal
			}
		}
		return false, hit.busy, tol
	}
	if a.BusyHost {
		return false, true, tolBusy
	}
	return false, false, tolNormal
}
