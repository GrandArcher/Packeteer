// Package ringlg is the opt-in "Seen from NLNOG RING" panel (#283). It asks
// the public, read-only looking-glass API of the NLNOG RING for one prefix
// on demand and returns a short summary for display. The answer never
// reaches Decide, scoring, or any announcer.
//
// RING is run by volunteers, so use stays small: a global cap on upstream
// calls, a per-prefix cache measured in minutes, a short back-off after a
// failure, no background polling, and no batch queries. Every request names
// Packeteer in its User-Agent. The package never logs in to RING, opens SSH,
// or runs a command on a RING node, and it keeps no credentials: the public
// API needs none. RING can be down, so a failure is a state, not an error.
package ringlg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/linkout"
)

// Defaults and bounds for the ring_lg block.
const (
	DefaultRequestsPerMinute = 6
	MaxRequestsPerMinute     = 30
	DefaultCacheTTL          = 10 * time.Minute
	MinCacheTTL              = time.Minute
	MaxCacheTTL              = 24 * time.Hour
	DefaultTimeout           = 10 * time.Second
	MaxTimeout               = 30 * time.Second
)

const (
	endpoint = "https://lg.ring.nlnog.net/api/prefix"
	// failureTTL is how long a failed fetch is remembered, so a struggling
	// service is not asked again on every page view.
	failureTTL = time.Minute
	// maxCache bounds the in-memory cache; the oldest entry goes first.
	maxCache = 256
	// maxBody bounds what is read from RING.
	maxBody = 4 << 20
	// MaxRoutes bounds the rows returned for one prefix.
	MaxRoutes = 200
)

// Config is the ring_lg block.
type Config struct {
	// Enabled turns the panel on. Off, nothing calls RING.
	Enabled bool `yaml:"enabled"`
	// RequestsPerMinute caps upstream calls in any 60 seconds, across all
	// prefixes and viewers (default 6).
	RequestsPerMinute int `yaml:"requests_per_minute"`
	// CacheTTL is how long an answer for a prefix is reused (default 10m).
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// Timeout bounds one upstream call (default 10s).
	Timeout time.Duration `yaml:"timeout"`
}

// WithDefaults fills unset keys.
func (c Config) WithDefaults() Config {
	if c.RequestsPerMinute == 0 {
		c.RequestsPerMinute = DefaultRequestsPerMinute
	}
	if c.CacheTTL == 0 {
		c.CacheTTL = DefaultCacheTTL
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	return c
}

// Validate reports every problem with the block.
func (c Config) Validate(add func(string, ...any)) {
	if c.RequestsPerMinute < 0 || c.RequestsPerMinute > MaxRequestsPerMinute {
		add("ring_lg.requests_per_minute: %d is out of range (0 uses %d, at most %d)", c.RequestsPerMinute, DefaultRequestsPerMinute, MaxRequestsPerMinute)
	}
	if c.CacheTTL != 0 && (c.CacheTTL < MinCacheTTL || c.CacheTTL > MaxCacheTTL) {
		add("ring_lg.cache_ttl: %s is out of range (%s to %s)", c.CacheTTL, MinCacheTTL, MaxCacheTTL)
	}
	if c.Timeout < 0 || c.Timeout > MaxTimeout {
		add("ring_lg.timeout: %s is out of range (up to %s)", c.Timeout, MaxTimeout)
	}
}

// States of a Result.
const (
	StateOff         = "off"
	StateOK          = "ok"
	StateUnavailable = "unavailable"
)

// Route is one path RING shows for the prefix.
type Route struct {
	Prefix string `json:"prefix"`
	Peer   string `json:"peer"`
	// ASPath holds AS numbers only, nearest first.
	ASPath []string `json:"as_path"`
	Origin string   `json:"origin,omitempty"`
	// RPKI is RING's own origin validation state, such as "Valid".
	RPKI       string `json:"rpki,omitempty"`
	LastUpdate string `json:"last_update,omitempty"`
}

// Result is what the panel shows.
type Result struct {
	State  string `json:"state"`
	Prefix string `json:"prefix,omitempty"`
	// Message explains an unavailable state.
	Message string  `json:"message,omitempty"`
	Routes  []Route `json:"routes,omitempty"`
	// Truncated is set when RING returned more than MaxRoutes rows.
	Truncated bool     `json:"truncated,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	// Cached is set when no call was made for this request.
	Cached    bool      `json:"cached,omitempty"`
	FetchedAt time.Time `json:"fetched_at,omitzero"`
}

type cached struct {
	res     Result
	expires time.Time
}

// Client fetches and caches RING answers. Safe for concurrent use.
type Client struct {
	cfg  Config
	ua   string
	base string
	http *http.Client
	now  func() time.Time

	fetchMu sync.Mutex // serializes upstream calls so a cold prefix is fetched once

	mu    sync.Mutex
	cache map[string]cached
	order []string // cache keys, oldest first
	calls []time.Time
}

// New builds a client from a validated block. version goes in the
// User-Agent.
func New(cfg Config, version string) *Client {
	cfg = cfg.WithDefaults()
	return &Client{
		cfg:  cfg,
		ua:   "Packeteer/" + version + " (+https://github.com/GrandArcher/Packeteer)",
		base: endpoint,
		http: &http.Client{
			Timeout: cfg.Timeout,
			// Only the RING host is ever called.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:   time.Now,
		cache: map[string]cached{},
	}
}

// Enabled reports whether the block is on. A nil client is off.
func (c *Client) Enabled() bool { return c != nil && c.cfg.Enabled }

// Lookup returns the RING view of p. It makes no call when the panel is
// off, when p is a private or local prefix, when a fresh answer is cached,
// or when the call cap is spent.
func (c *Client) Lookup(ctx context.Context, p netip.Prefix) Result {
	if !c.Enabled() {
		return Result{State: StateOff}
	}
	p = p.Masked()
	res := Result{State: StateUnavailable, Prefix: p.String()}
	if linkout.InternalAddr(p.Addr()) {
		res.Message = "Private and local prefixes are never sent to NLNOG RING."
		return res
	}
	key := p.String()
	if r, ok := c.fresh(key); ok {
		return r
	}
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	if r, ok := c.fresh(key); ok {
		return r
	}
	if !c.spend() {
		res.Message = fmt.Sprintf("Not asked: Packeteer sends at most %d requests a minute to NLNOG RING. Try again shortly.", c.cfg.RequestsPerMinute)
		return res
	}
	out, err := c.fetch(ctx, p)
	now := c.now()
	ttl := c.cfg.CacheTTL
	if err != nil {
		out = res
		out.Message = "NLNOG RING did not answer: " + err.Error() + ". NLNOG RING services may be unavailable."
		ttl = min(failureTTL, ttl)
	} else {
		out.State = StateOK
		out.FetchedAt = now.UTC()
	}
	c.store(key, out, now.Add(ttl))
	return out
}

func (c *Client) fresh(key string) (Result, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || !c.now().Before(e.expires) {
		return Result{}, false
	}
	r := e.res
	r.Cached = true
	return r, true
}

func (c *Client) store(key string, r Result, expires time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.cache[key]; !ok {
		c.order = append(c.order, key)
		for len(c.order) > maxCache {
			delete(c.cache, c.order[0])
			c.order = c.order[1:]
		}
	}
	c.cache[key] = cached{res: r, expires: expires}
}

// spend books one upstream call against the cap, reporting false when
// requests_per_minute calls already happened in the last minute.
func (c *Client) spend() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	keep := c.calls[:0]
	for _, t := range c.calls {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	c.calls = keep
	if len(c.calls) >= c.cfg.RequestsPerMinute {
		return false
	}
	c.calls = append(c.calls, now)
	return true
}

type upstream struct {
	Prefix   string                     `json:"prefix"`
	Routes   map[string][]upstreamRoute `json:"routes"`
	Warnings []string                   `json:"warnings"`
}

type upstreamRoute struct {
	Peer       string     `json:"peer"`
	ASPath     [][]string `json:"aspath"`
	OVS        string     `json:"ovs"`
	LastUpdate string     `json:"last_update_at"`
}

func (c *Client) fetch(ctx context.Context, p netip.Prefix) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	q := url.Values{"q": {p.String()}, "match": {"exact"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"?"+q.Encode(), nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", c.ua)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		var ne interface{ Timeout() bool }
		if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			return Result{}, errors.New("timed out")
		}
		return Result{}, errors.New("request failed")
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return Result{}, errors.New("it is rate limiting requests (HTTP 429)")
	case resp.StatusCode != http.StatusOK:
		return Result{}, errors.New("HTTP " + strconv.Itoa(resp.StatusCode))
	}
	var up upstream
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&up); err != nil {
		return Result{}, errors.New("unreadable response")
	}
	return summarize(p, up), nil
}

func summarize(p netip.Prefix, up upstream) Result {
	res := Result{Prefix: p.String()}
	for _, w := range up.Warnings {
		if len(res.Warnings) < 5 {
			res.Warnings = append(res.Warnings, clip(w))
		}
	}
	// Map order is random; sort keys so the table is stable.
	for _, pfx := range slices.Sorted(maps.Keys(up.Routes)) {
		for _, r := range up.Routes[pfx] {
			if len(res.Routes) == MaxRoutes {
				res.Truncated = true
				return res
			}
			row := Route{Prefix: clip(pfx), Peer: clip(r.Peer), RPKI: clip(r.OVS), LastUpdate: clip(r.LastUpdate)}
			for _, hop := range r.ASPath {
				if len(hop) > 0 {
					row.ASPath = append(row.ASPath, clip(hop[0]))
				}
			}
			if n := len(row.ASPath); n > 0 {
				row.Origin = row.ASPath[n-1]
			}
			res.Routes = append(res.Routes, row)
		}
	}
	return res
}

// clip bounds third-party text before it is cached and shown.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return strings.ToValidUTF8(s[:120], "")
	}
	return s
}
