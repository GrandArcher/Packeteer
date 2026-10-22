// Package ripestat is the RIPEstat RPKI validation lookup (#200), a
// display-only last resort for the prefix card when no rpki.sources entry
// has fresh data. It is configured only as rpki.display_fallback and never
// feeds Decide, avoid_invalid, leak watch, or the exchange counts. Each
// lookup sends one prefix and origin AS to RIPE NCC, rate-limited, and the
// answer is cached for ttl. It never announces and never changes the
// learned RIB.
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
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "ripestat"

// Defaults and bounds.
const (
	DefaultRatePerMinute = 10
	MaxRatePerMinute     = 60
	DefaultTTL           = time.Hour
	MinTTL               = time.Minute
	MaxTTL               = 24 * time.Hour
	// maxEntries bounds the answer cache; queueLen the lookups waiting for
	// the rate limit. A full queue drops the request: the prefix card asks
	// again on its next refresh.
	maxEntries   = 10000
	queueLen     = 256
	fetchTimeout = 10 * time.Second
	maxBody      = 1 << 20
)

const defaultBase = "https://stat.ripe.net"

func init() { plugin.RPKIs.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// RatePerMinute caps the lookups sent to RIPEstat (default 10, at most
	// 60).
	RatePerMinute int `yaml:"rate_per_minute"`
	// TTL is how long an answer is shown before it is looked up again
	// (default 1h).
	TTL time.Duration `yaml:"ttl"`
}

type key struct {
	prefix netip.Prefix
	origin uint32
}

type entry struct {
	state plugin.RPKIValidity
	at    time.Time
}

// Client answers from its cache and looks up misses in the background.
type Client struct {
	plugin.Base

	name  string
	cfg   Config
	base  string
	http  *http.Client
	limit *rate.Limiter
	queue chan key

	mu      sync.Mutex
	cache   map[key]entry
	pending map[key]bool
	up      bool
	updated time.Time
	lastErr string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New is the plugin factory. It validates the config and sends nothing.
func New(c plugin.Config, env plugin.Env) (plugin.RPKI, error) {
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
	if cfg.TTL == 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.TTL < MinTTL || cfg.TTL > MaxTTL {
		return nil, fmt.Errorf("ttl %s must be between %s and %s", cfg.TTL, MinTTL, MaxTTL)
	}
	return &Client{
		name: env.Name, cfg: cfg, base: defaultBase,
		http:  &http.Client{Timeout: fetchTimeout},
		limit: rate.NewLimiter(rate.Limit(float64(cfg.RatePerMinute)/60), 1),
		queue: make(chan key, queueLen),
		cache: map[key]entry{}, pending: map[key]bool{},
	}, nil
}

// Start begins the lookup worker. It does not block.
func (c *Client) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.run(ctx)
	}()
	return nil
}

// Stop cancels the worker and waits for it. It returns when ctx expires.
func (c *Client) Stop(ctx context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Answer returns a cached answer younger than ttl with its lookup time.
// Otherwise it queues a lookup and returns unknown.
func (c *Client) Answer(prefix netip.Prefix, origin uint32) plugin.RPKIAnswer {
	k := key{prefix: prefix.Masked(), origin: origin}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.cache[k]; ok && time.Since(e.at) <= c.cfg.TTL {
		return plugin.RPKIAnswer{State: e.state, Source: c.name, Updated: e.at}
	}
	if !c.pending[k] {
		select {
		case c.queue <- k:
			c.pending[k] = true
		default:
		}
	}
	return plugin.RPKIAnswer{State: plugin.RPKIUnknown}
}

// Validate is Answer's state.
func (c *Client) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	return c.Answer(prefix, origin).State
}

// Status reports the last lookup. VRPs is the number of cached answers.
func (c *Client) Status() plugin.RPKIStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return plugin.RPKIStatus{Source: c.name, Up: c.up, VRPs: len(c.cache), Updated: c.updated, Error: c.lastErr}
}

func (c *Client) run(ctx context.Context) {
	for {
		var k key
		select {
		case <-ctx.Done():
			return
		case k = <-c.queue:
		}
		if err := c.limit.Wait(ctx); err != nil {
			return
		}
		state, err := c.lookup(ctx, k)
		now := time.Now()
		c.mu.Lock()
		delete(c.pending, k)
		if err != nil {
			if ctx.Err() == nil {
				c.up, c.lastErr = false, err.Error()
			}
		} else {
			c.storeLocked(k, entry{state: state, at: now})
			c.up, c.updated, c.lastErr = true, now, ""
		}
		c.mu.Unlock()
	}
}

// storeLocked keeps the cache under maxEntries: expired answers go first,
// then an arbitrary one.
func (c *Client) storeLocked(k key, e entry) {
	if _, ok := c.cache[k]; !ok && len(c.cache) >= maxEntries {
		for old, v := range c.cache {
			if time.Since(v.at) > c.cfg.TTL {
				delete(c.cache, old)
			}
		}
		for old := range c.cache {
			if len(c.cache) < maxEntries {
				break
			}
			delete(c.cache, old)
		}
	}
	c.cache[k] = e
}

// response is the part of the rpki-validation data call that matters.
type response struct {
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

func (c *Client) lookup(ctx context.Context, k key) (plugin.RPKIValidity, error) {
	q := url.Values{}
	q.Set("resource", "AS"+strconv.FormatUint(uint64(k.origin), 10))
	q.Set("prefix", k.prefix.String())
	q.Set("sourceapp", "packeteer")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/data/rpki-validation/data.json?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ripestat: %s", resp.Status)
	}
	var r response
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&r); err != nil {
		return "", fmt.Errorf("ripestat: %w", err)
	}
	// RIPEstat says unknown when no ROA covers the prefix, which RFC 6811
	// calls not found.
	switch r.Data.Status {
	case "valid":
		return plugin.RPKIValid, nil
	case "invalid_asn", "invalid_length":
		return plugin.RPKIInvalid, nil
	case "unknown":
		return plugin.RPKINotFound, nil
	}
	return "", fmt.Errorf("ripestat: unexpected status %q", r.Data.Status)
}
