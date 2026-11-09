// Package ripestat answers the non-BGP mode's covering-prefix question
// (#300) with the RIPEstat network-info data call: the prefix that RIPE
// RIS sees announced for an address. Each lookup sends one block's network
// address (the first address of a /24 or /48, never a flow's own
// address) to RIPE NCC, and the plugin spends at most rate_per_minute
// requests. It is read-only and never announces.
package ripestat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/outbound"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "ripestat"

// Defaults and bounds.
const (
	DefaultRatePerMinute = 10
	MaxRatePerMinute     = 60
	fetchTimeout         = 10 * time.Second
	maxBody              = 1 << 20
)

const defaultBase = "https://stat.ripe.net"

func init() { plugin.Coverings.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// RatePerMinute caps the lookups sent to RIPEstat (default 10, at most
	// 60).
	RatePerMinute int `yaml:"rate_per_minute"`
}

// Client is the covering plugin.
type Client struct {
	plugin.Base
	base  string
	http  *http.Client
	limit *rate.Limiter
}

// New is the plugin factory. It validates the config and sends nothing.
func New(c plugin.Config, _ plugin.Env) (plugin.Covering, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.RatePerMinute == 0 {
		cfg.RatePerMinute = DefaultRatePerMinute
	}
	if cfg.RatePerMinute < 1 || cfg.RatePerMinute > MaxRatePerMinute {
		return nil, fmt.Errorf("rate_per_minute %d must be between 1 and %d", cfg.RatePerMinute, MaxRatePerMinute)
	}
	return &Client{
		base:  defaultBase,
		http:  &http.Client{Timeout: fetchTimeout, CheckRedirect: outbound.SameHost},
		limit: rate.NewLimiter(rate.Limit(float64(cfg.RatePerMinute)/60), 1),
	}, nil
}

// response is the part of the network-info data call that matters.
type response struct {
	Data struct {
		Prefix string   `json:"prefix"`
		ASNs   []string `json:"asns"`
	} `json:"data"`
}

// Covering waits for the rate limit, then asks RIPEstat for the announced
// prefix that holds addr.
func (c *Client) Covering(ctx context.Context, addr netip.Addr) (plugin.Announced, error) {
	if err := c.limit.Wait(ctx); err != nil {
		return plugin.Announced{}, err
	}
	q := url.Values{}
	q.Set("resource", addr.String())
	q.Set("sourceapp", "packeteer")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/data/network-info/data.json?"+q.Encode(), nil)
	if err != nil {
		return plugin.Announced{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return plugin.Announced{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return plugin.Announced{}, fmt.Errorf("ripestat: %s", resp.Status)
	}
	var r response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&r); err != nil {
		return plugin.Announced{}, fmt.Errorf("ripestat: %w", err)
	}
	if r.Data.Prefix == "" {
		return plugin.Announced{}, fmt.Errorf("ripestat: no announced prefix for %s", addr)
	}
	p, err := netip.ParsePrefix(r.Data.Prefix)
	if err != nil {
		return plugin.Announced{}, fmt.Errorf("ripestat: prefix %q: %w", r.Data.Prefix, err)
	}
	out := plugin.Announced{Prefix: p.Masked()}
	// An address announced by several origins names none.
	if len(r.Data.ASNs) == 1 {
		if n, err := strconv.ParseUint(r.Data.ASNs[0], 10, 32); err == nil {
			out.Origin = uint32(n)
		}
	}
	return out, nil
}
