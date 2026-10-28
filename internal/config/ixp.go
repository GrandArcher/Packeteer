package config

import (
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Bounds for ixp.vantages (#162).
const (
	maxVantages = 64
	maxVLANID   = 1_000_000
)

// IXP is exchange-operator mode (#160). A non-nil value, including an
// empty block, is IXP mode. IXP mode never announces. Keys are members
// (#161), vantages and fabric (#162), routeservers (#164), and correlate
// (#163), and core and core_links (#167). Any other key is a parse error.
type IXP struct {
	Members      *PluginSpec `yaml:"members,omitempty"`
	Vantages     []Vantage   `yaml:"vantages,omitempty"`
	Fabric       *PluginSpec `yaml:"fabric,omitempty"`
	RouteServers *PluginSpec `yaml:"routeservers,omitempty"`
	Correlate    *PluginSpec `yaml:"correlate,omitempty"`
	Core         *PluginSpec `yaml:"core,omitempty"`
	CoreLinks    []CoreLink  `yaml:"core_links,omitempty"`
}

// CoreLink is one measured path from this site to another site's address
// across the exchange core (#167). Peer is the other site's federation
// instance name. Source is optional. MaxLossPct defaults to
// DefaultCoreMaxLossPct; MaxRTT zero means no RTT limit.
type CoreLink struct {
	Name       string        `yaml:"name"`
	Peer       string        `yaml:"peer"`
	Address    string        `yaml:"address"`
	Source     string        `yaml:"source,omitempty"`
	MaxLossPct float64       `yaml:"max_loss_pct,omitempty"`
	MaxRTT     time.Duration `yaml:"max_rtt,omitempty"`
}

// Bounds for ixp.core_links (#167).
const (
	maxCoreLinks          = 64
	maxCoreRTT            = 10 * time.Second
	DefaultCoreMaxLossPct = 10
)

// Vantage is one IX-owned monitoring address on a peering LAN (#162).
// Probes to member addresses on that VLAN are sourced from Address.
// IXPID 0 means the vlan id is unique in the member list.
type Vantage struct {
	Name    string `yaml:"name"`
	VLANID  int    `yaml:"vlan_id"`
	IXPID   int    `yaml:"ixp_id,omitempty"`
	Address string `yaml:"address"`
}

// validateIXP refuses every config that can announce or steer while the
// ixp block is set. Observe and suggest stay valid: neither announces.
// Neighbors are not required, so no RIB view is built when they are absent.
func (c *Config) validateIXP(add func(string, ...any)) {
	if c.IXP == nil {
		return
	}
	if c.Mode == ModeInject {
		add("ixp forbids mode inject: IXP mode is observe-only and never announces")
	}
	if c.Announcer != nil {
		add("ixp forbids announcer: IXP mode never announces")
	}
	if c.Mitigation != nil {
		add("ixp forbids mitigation: IXP mode never announces")
	}
	if c.Inbound != nil {
		add("ixp forbids inbound: IXP mode never announces")
	}
	if c.MoreSpecific != nil {
		add("ixp forbids more_specific: IXP mode never announces")
	}
	if c.Synthesize != nil {
		add("ixp forbids synthesize: IXP mode never announces")
	}
	c.validateVantages(add)
	c.validateCoreLinks(add)
	if c.IXP.Correlate != nil && c.IXP.Fabric == nil {
		add("ixp.correlate requires ixp.fabric")
	}
}

func (c *Config) validateVantages(add func(string, ...any)) {
	ix := c.IXP
	hasV := len(ix.Vantages) > 0
	hasF := ix.Fabric != nil
	switch {
	case hasV && !hasF:
		add("ixp.vantages requires ixp.fabric")
	case hasF && !hasV:
		add("ixp.fabric requires ixp.vantages")
	case hasF && ix.Members == nil:
		add("ixp.fabric requires ixp.members")
	}
	if len(ix.Vantages) > maxVantages {
		add("ixp.vantages: more than %d", maxVantages)
	}
	seenName := map[string]bool{}
	seenAddr := map[string]bool{}
	for i := range ix.Vantages {
		v := &ix.Vantages[i]
		p := fmt.Sprintf("ixp.vantages[%d]", i)
		if !plugin.ValidLabel(v.Name) {
			add("%s.name is invalid", p)
		} else if seenName[v.Name] {
			add("%s.name %q is duplicated", p, v.Name)
		}
		seenName[v.Name] = true
		if v.VLANID < 1 || v.VLANID > maxVLANID {
			add("%s.vlan_id is invalid", p)
		}
		if v.IXPID < 0 || v.IXPID > maxVLANID {
			add("%s.ixp_id is invalid", p)
		}
		addr, err := netip.ParseAddr(v.Address)
		if err != nil || addr.Zone() != "" {
			add("%s.address is not an IP address", p)
			continue
		}
		addr = addr.Unmap()
		if !usableVantage(addr) {
			add("%s.address is not a usable vantage address", p)
			continue
		}
		v.Address = addr.String()
		key := fmt.Sprintf("%d/%d/%s", v.IXPID, v.VLANID, v.Address)
		if seenAddr[key] {
			add("%s.address is duplicated on this vlan", p)
		}
		seenAddr[key] = true
	}
}

func usableVantage(a netip.Addr) bool {
	return a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsLinkLocalMulticast()
}

func (c *Config) validateCoreLinks(add func(string, ...any)) {
	ix := c.IXP
	hasC, hasL := ix.Core != nil, len(ix.CoreLinks) > 0
	switch {
	case hasL && !hasC:
		add("ixp.core_links requires ixp.core")
	case hasC && !hasL:
		add("ixp.core requires ixp.core_links")
	}
	if hasC && c.Federation == nil {
		add("ixp.core requires federation: a core link names the federation peer at the other site")
	}
	if len(ix.CoreLinks) > maxCoreLinks {
		add("ixp.core_links: more than %d", maxCoreLinks)
	}
	seen := map[string]bool{}
	for i := range ix.CoreLinks {
		l := &ix.CoreLinks[i]
		p := fmt.Sprintf("ixp.core_links[%d]", i)
		if !plugin.ValidLabel(l.Name) {
			add("%s.name is invalid", p)
		} else if seen[l.Name] {
			add("%s.name %q is duplicated", p, l.Name)
		}
		seen[l.Name] = true
		if !validName(l.Peer) {
			add("%s.peer is invalid", p)
		} else if l.Peer == c.Instance {
			add("%s.peer %q is this instance", p, l.Peer)
		}
		if a, err := netip.ParseAddr(l.Address); err != nil || a.Zone() != "" || !usableVantage(a.Unmap()) {
			add("%s.address is not a usable IP address", p)
		} else {
			l.Address = a.Unmap().String()
		}
		if l.Source != "" {
			if a, err := netip.ParseAddr(l.Source); err != nil || a.Zone() != "" || !usableVantage(a.Unmap()) {
				add("%s.source is not a usable IP address", p)
			} else {
				l.Source = a.Unmap().String()
			}
		}
		if l.MaxLossPct == 0 {
			l.MaxLossPct = DefaultCoreMaxLossPct
		}
		if math.IsNaN(l.MaxLossPct) || l.MaxLossPct < 0 || l.MaxLossPct > 100 {
			add("%s.max_loss_pct must be between 0 and 100", p)
		}
		if l.MaxRTT < 0 || l.MaxRTT > maxCoreRTT {
			add("%s.max_rtt must be between 0 and %s", p, maxCoreRTT)
		}
	}
}
