// Package netbox is the built-in inventory plugin for NetBox. It GETs the
// circuit providers carrying one tag and reads the operator's values from
// their custom fields. It never announces and writes nothing to NetBox.
package netbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/plugins/inventory/invcommon"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "netbox"

// TokenEnv is the only place the API token is read from.
const TokenEnv = "PACKETEER_NETBOX_TOKEN"

// fieldPrefix starts the name of each custom field the plugin reads:
// packeteer_type, packeteer_source_ip, packeteer_next_hop, and
// packeteer_communities.
const fieldPrefix = "packeteer_"

func init() { plugin.Inventories.Register(TypeName, New) }

type source struct {
	client *invcommon.Client
	tag    string
}

// New validates the config and the token. It does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.Inventory, error) {
	var cfg invcommon.Common
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	s, err := invcommon.Validate(cfg, TokenEnv, getenv)
	if err != nil {
		return nil, err
	}
	// Tokens from NetBox 4.5 on start with nbt_ and use Bearer; older
	// ones use Token.
	scheme := "Token "
	if strings.HasPrefix(s.Token, "nbt_") {
		scheme = "Bearer "
	}
	return &source{client: invcommon.NewClient(s, scheme+s.Token), tag: s.Tag}, nil
}

type provider struct {
	Name         string         `json:"name"`
	Slug         string         `json:"slug"`
	ASNs         []asn          `json:"asns"`
	CustomFields map[string]any `json:"custom_fields"`
}

type asn struct {
	ASN uint32 `json:"asn"`
}

// Fetch reads the tagged providers. The provider's name is its NetBox slug
// and its ASN is the lowest one NetBox lists for it.
func (s *source) Fetch(ctx context.Context) (plugin.InventoryResult, error) {
	var (
		list  []plugin.InventoryProvider
		skips []plugin.InventorySkip
	)
	err := s.client.GetAll(ctx, "/api/circuits/providers/", url.Values{"tag": {s.tag}}, func(raw json.RawMessage) error {
		var p provider
		if err := json.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("provider record: %w", err)
		}
		name := p.Slug
		if !plugin.ValidLabel(name) {
			name = invcommon.Slug(p.Name)
		}
		if name == "" {
			skips = append(skips, plugin.InventorySkip{Name: p.Name, Reason: "no usable name"})
			return nil
		}
		var first uint32
		for _, a := range p.ASNs {
			if a.ASN != 0 && (first == 0 || a.ASN < first) {
				first = a.ASN
			}
		}
		bag := map[string]any{}
		for k, v := range p.CustomFields {
			if key, ok := strings.CutPrefix(k, fieldPrefix); ok {
				bag[key] = v
			}
		}
		ip, err := invcommon.Provider(name, first, bag)
		if err != nil {
			skips = append(skips, plugin.InventorySkip{Name: name, Reason: err.Error()})
			return nil
		}
		list = append(list, ip)
		return nil
	})
	if err != nil {
		return plugin.InventoryResult{}, err
	}
	return invcommon.Result(list, skips), nil
}
