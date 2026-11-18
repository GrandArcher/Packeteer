// Package httpjson is the origin collector that reads one HTTP JSON endpoint
// (#671): the origin ASes a public collector set, such as RIPE RIS or
// RouteViews, sees for a prefix. Packeteer ships no client for a public
// service; the URL is an endpoint the operator runs or trusts, and the lab
// points it at stand-ins on an internal network. It only reads and is
// evidence only: it never announces and never changes a decision.
package httpjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/outbound"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "json"

// Defaults and bounds.
const (
	DefaultRatePerMinute = 60
	MaxRatePerMinute     = 600
	fetchTimeout         = 10 * time.Second
	maxBody              = 1 << 20
	maxOrigins           = 1000
)

func init() { plugin.OriginCollectors.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// URL is the endpoint, http or https. A lookup is a GET of URL with
	// the query parameter prefix=<prefix>.
	URL string `yaml:"url"`
	// RatePerMinute caps the lookups sent (default 60, at most 600).
	RatePerMinute int `yaml:"rate_per_minute"`
}

// Client is the collector plugin.
type Client struct {
	plugin.Base
	url   *url.URL
	http  *http.Client
	limit *rate.Limiter
}

// New is the plugin factory. It validates the config and sends nothing.
func New(c plugin.Config, _ plugin.Env) (plugin.OriginCollector, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("url %q must be an http or https URL", cfg.URL)
	}
	if u.User != nil {
		return nil, errors.New("url must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("url must not carry a query or fragment")
	}
	if cfg.RatePerMinute == 0 {
		cfg.RatePerMinute = DefaultRatePerMinute
	}
	if cfg.RatePerMinute < 1 || cfg.RatePerMinute > MaxRatePerMinute {
		return nil, fmt.Errorf("rate_per_minute %d must be between 1 and %d", cfg.RatePerMinute, MaxRatePerMinute)
	}
	return &Client{
		url:   u,
		http:  &http.Client{Timeout: fetchTimeout, CheckRedirect: outbound.SameHost},
		limit: rate.NewLimiter(rate.Limit(float64(cfg.RatePerMinute)/60), 1),
	}, nil
}

// response is the endpoint's answer. Prefix must be the one asked, so an
// answer for a covering or more specific prefix is never read as an answer
// for this one.
type response struct {
	Prefix  string   `json:"prefix"`
	Origins []uint32 `json:"origins"`
}

// Origins waits for the rate limit, then asks the endpoint.
func (c *Client) Origins(ctx context.Context, prefix netip.Prefix) ([]uint32, error) {
	prefix = prefix.Masked()
	if err := c.limit.Wait(ctx); err != nil {
		return nil, err
	}
	u := *c.url
	q := url.Values{}
	q.Set("prefix", prefix.String())
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("collector: %s", resp.Status)
	}
	var r response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&r); err != nil {
		return nil, fmt.Errorf("collector: %w", err)
	}
	got, err := netip.ParsePrefix(r.Prefix)
	if err != nil || got.Masked() != prefix {
		return nil, fmt.Errorf("collector: answer is for %q, not %s", r.Prefix, prefix)
	}
	if len(r.Origins) > maxOrigins {
		return nil, fmt.Errorf("collector: more than %d origins", maxOrigins)
	}
	return r.Origins, nil
}
