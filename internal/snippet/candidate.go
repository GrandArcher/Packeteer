package snippet

import (
	"bytes"
	"fmt"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"gopkg.in/yaml.v3"
)

// Answers are the setup-wizard fields the router side reads, as typed and
// not yet saved. Wizard is true while the wizard is open: Generate then
// replaces asn, router_id, packeteer_community, bgp.neighbors and sources,
// so those come from the answers and not from the text. Without Wizard the
// text is used as it is and the other fields are ignored. Generate also
// replaces providers; the IPv6 family still comes from the text's providers.
type Answers struct {
	Wizard   bool   `json:"wizard"`
	ASN      uint32 `json:"asn"`
	RouterID string `json:"router_id"`
	// Edge is the router's address (bgp.neighbors[0].address).
	Edge string `json:"edge"`
	// FlowListen is the wizard's flow collector, host:port.
	FlowListen string `json:"flow_listen"`
}

// ForCandidate returns the Params for config text that is not saved (the
// editor, or a wizard result). While the wizard is open the keys it owns
// are what Generate would write: the community is the wizard's rule for the
// AS number, one neighbor, and the flow source only when it is ticked. The
// text is read leniently, because it is part-way through setup: only the
// keys a snippet reads matter, and a missing one comes back as a
// *MissingError instead of a config validation error. Nothing is written.
func ForCandidate(text []byte, a Answers) ([]Params, error) {
	var cfg config.Config
	if len(bytes.TrimSpace(text)) > 0 {
		if err := yaml.Unmarshal(text, &cfg); err != nil {
			return nil, fmt.Errorf("the YAML does not parse: %w", err)
		}
	}
	if a.Wizard {
		cfg.ASN = a.ASN
		cfg.RouterID = a.RouterID
		cfg.PacketeerCommunity = configedit.WizardCommunity(a.ASN)
		cfg.BGP.Neighbors = nil
		if a.Edge != "" {
			cfg.BGP.Neighbors = []config.BGPNeighbor{{Address: a.Edge}}
		}
		cfg.Sources = nil
		if a.FlowListen != "" {
			var n yaml.Node
			if err := n.Encode(map[string]string{"listen": a.FlowListen}); err != nil {
				return nil, err
			}
			cfg.Sources = []config.PluginSpec{{Type: "flow", Config: n}}
		}
	}
	return ForConfig(&cfg)
}
