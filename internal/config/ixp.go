package config

import (
	"errors"
	"fmt"
	"net/netip"

	"gopkg.in/yaml.v3"

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
// (#163). Any other key is a parse error.
type IXP struct {
	Members      *PluginSpec `yaml:"members,omitempty"`
	Vantages     []Vantage   `yaml:"vantages,omitempty"`
	Fabric       *PluginSpec `yaml:"fabric,omitempty"`
	RouteServers *PluginSpec `yaml:"routeservers,omitempty"`
	Correlate    *PluginSpec `yaml:"correlate,omitempty"`
}

// Vantage is one IX-owned monitoring address on a peering LAN (#162).
// Probes to member addresses on that VLAN are sourced from Address.
// IXPID 0 means the vlan id is unique in the member list.
type Vantage struct {
	Name    string `yaml:"name"`
	VLANID  int    `yaml:"vlan_id"`
	IXPID   int    `yaml:"ixp_id,omitempty"`
	Address string `yaml:"address"`
}

// ixpForbidsSynthesize rejects a synthesize key when an ixp block is
// present. synthesize is not a field (#122); without this check the
// decode would only say the field is unknown, and an ixp file would
// not name the charter.
func ixpForbidsSynthesize(data []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return nil
	}
	m := doc.Content[0]
	if m.Kind != yaml.MappingNode {
		return nil
	}
	var ixp, synth bool
	for i := 0; i+1 < len(m.Content); i += 2 {
		val := m.Content[i+1]
		switch m.Content[i].Value {
		case "ixp":
			if val.Tag != "!!null" {
				ixp = true
			}
		case "synthesize":
			synth = true
		}
	}
	if ixp && synth {
		return errors.New("ixp forbids synthesize: IXP mode never announces")
	}
	return nil
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
	c.validateVantages(add)
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
