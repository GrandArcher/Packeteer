// Package peeringmanager is the built-in inventory plugin for Peering
// Manager. It GETs the autonomous systems carrying one tag and reads the
// operator's values from each one's local context data. It never announces
// and writes nothing to Peering Manager.
package peeringmanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/GrandArcher/Packeteer/internal/plugins/inventory/invcommon"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "peeringmanager"

// TokenEnv is the only place the API token is read from.
const TokenEnv = "PACKETEER_PEERING_MANAGER_TOKEN"

// contextKey is the object in local_context_data that holds the values:
// {"packeteer": {"next_hop": "...", "source_ip": "...", ...}}.
const contextKey = "packeteer"

func init() { plugin.Inventories.Register(TypeName, New) }

type source struct {
	settings invcommon.Settings
	getenv   func(string) string
}

// New validates the config. It does not dial and does not read the token,
// which only Fetch needs.
func New(c plugin.Config, env plugin.Env) (plugin.Inventory, error) {
	var cfg invcommon.Common
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	s, err := invcommon.Validate(cfg)
	if err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return &source{settings: s, getenv: getenv}, nil
}

type autonomousSystem struct {
	ASN              uint32         `json:"asn"`
	Name             string         `json:"name"`
	Tags             []any          `json:"tags"`
	LocalContextData map[string]any `json:"local_context_data"`
}

// Fetch reads the autonomous systems and keeps those tagged with the
// configured tag; the tag is matched here because the filter name is not
// part of the documented API. The provider's name is the slug of the
// autonomous system's name.
func (s *source) Fetch(ctx context.Context) (plugin.InventoryResult, error) {
	token, err := invcommon.Token(s.settings, TokenEnv, s.getenv)
	if err != nil {
		return plugin.InventoryResult{}, err
	}
	var (
		list  []plugin.InventoryProvider
		skips []plugin.InventorySkip
	)
	err = invcommon.NewClient(s.settings, "Token", token).GetAll(ctx, "/api/peering/autonomous-systems/", url.Values{}, func(raw json.RawMessage) error {
		var a autonomousSystem
		if err := json.Unmarshal(raw, &a); err != nil {
			return fmt.Errorf("autonomous system record: %w", err)
		}
		if !tagged(a.Tags, s.settings.Tag) {
			return nil
		}
		name := invcommon.Slug(a.Name)
		if name == "" {
			skips = append(skips, plugin.InventorySkip{Name: a.Name, Reason: "no usable name"})
			return nil
		}
		bag, _ := a.LocalContextData[contextKey].(map[string]any)
		ip, err := invcommon.Provider(name, a.ASN, bag)
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

// tagged reports whether tags holds tag, as a string or as an object with
// a slug or a name.
func tagged(tags []any, tag string) bool {
	for _, t := range tags {
		switch v := t.(type) {
		case string:
			if v == tag {
				return true
			}
		case map[string]any:
			if v["slug"] == tag || v["name"] == tag {
				return true
			}
		}
	}
	return false
}
