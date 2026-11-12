package snippet

import (
	"bytes"
	"fmt"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/configedit"
	"gopkg.in/yaml.v3"
)

// Answers are the setup-wizard fields the router side reads, as typed and
// not yet saved. A zero field was not answered and leaves the config text as
// it is.
type Answers struct {
	ASN      uint32 `json:"asn"`
	RouterID string `json:"router_id"`
	// Edge is the router's address (bgp.neighbors[0].address).
	Edge string `json:"edge"`
	// FlowListen is the wizard's flow collector, host:port.
	FlowListen string `json:"flow_listen"`
}

// ForCandidate returns the Params for config text that is not saved (the
// editor, or a wizard result) with the unsaved wizard answers laid over it.
// The text is read leniently, because it is part-way through setup: only the
// keys a snippet reads matter, and a missing one comes back as a
// *MissingError instead of a config validation error. Nothing is written.
func ForCandidate(text []byte, a Answers) ([]Params, error) {
	var cfg config.Config
	if len(bytes.TrimSpace(text)) > 0 {
		if err := yaml.Unmarshal(text, &cfg); err != nil {
			return nil, fmt.Errorf("the YAML does not parse: %w", err)
		}
	}
	if a.ASN != 0 {
		cfg.ASN = a.ASN
	}
	if a.RouterID != "" {
		cfg.RouterID = a.RouterID
	}
	// A community already in the text is what the router must match. Only
	// when it is empty does the wizard's own rule apply, as Generate would.
	if cfg.PacketeerCommunity == "" {
		cfg.PacketeerCommunity = configedit.WizardCommunity(cfg.ASN)
	}
	if a.Edge != "" {
		if len(cfg.BGP.Neighbors) == 0 {
			cfg.BGP.Neighbors = []config.BGPNeighbor{{}}
		}
		cfg.BGP.Neighbors[0].Address = a.Edge
	}
	if a.FlowListen != "" {
		var n yaml.Node
		if err := n.Encode(map[string]string{"listen": a.FlowListen}); err != nil {
			return nil, err
		}
		cfg.Sources = append([]config.PluginSpec{{Type: "flow", Config: n}}, cfg.Sources...)
	}
	return ForConfig(&cfg)
}
