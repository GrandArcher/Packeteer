// Package vrpjson is the built-in HTTP JSON origin-validation plugin
// (#200). It fetches the validated ROA payloads an RPKI cache publishes as
// JSON (Routinator's /json, rpki-client's -j output) and answers RFC 6811
// origin-validation queries from its own cache. It only reads: it never
// announces and never changes the learned RIB.
package vrpjson

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "json"

// maxBody bounds one download. The public table as JSON is well under it.
const maxBody = 512 << 20

// publisherLag is how far the document's own time can trail a fetch: the
// publisher's regeneration cycle, 10m for Routinator's default refresh and
// 1h for rpki-client run hourly from cron. Staleness must cover it on top
// of refresh, or fresh data reads as stale between polls.
const publisherLag = time.Hour

func init() { plugin.RPKIs.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	// URL is the VRP JSON document, http or https.
	URL         string `yaml:"url"`
	rpki.Timing `yaml:",inline"`
}

// Client polls one VRP JSON document and keeps the last good one.
type Client struct {
	plugin.Base

	name string
	cfg  Config
	http *http.Client
	log  *slog.Logger

	mu      sync.Mutex
	cache   *rpki.VRPs
	up      bool
	updated time.Time
	lastErr string
	// lagWarned is set while fetched documents are too old for staleness,
	// so the warning is logged once per episode, not on every poll.
	lagWarned bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New is the plugin factory. It validates the config and does not fetch.
func New(c plugin.Config, env plugin.Env) (plugin.RPKI, error) {
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
	cfg.URL = u.String()
	if err := cfg.Normalize(publisherLag); err != nil {
		return nil, err
	}
	if env.Logger == nil {
		env.Logger = slog.Default()
	}
	return &Client{name: env.Name, cfg: cfg, http: &http.Client{Timeout: cfg.Timeout}, log: env.Logger, cache: rpki.NewVRPs()}, nil
}

// Start begins polling. It does not block.
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

// Stop cancels polling and waits for it. It returns when ctx expires.
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

// Validate returns the cached RFC 6811 state. Data older than staleness is
// unknown (fail open).
func (c *Client) Validate(prefix netip.Prefix, origin uint32) plugin.RPKIValidity {
	c.mu.Lock()
	stale := c.cfg.Stale(c.updated, time.Now())
	cache := c.cache
	c.mu.Unlock()
	if stale {
		return plugin.RPKIUnknown
	}
	return cache.Validate(prefix, origin)
}

// Status reports the source's health. Updated is when the document says
// it was generated, so a cache that keeps serving an old file goes stale.
func (c *Client) Status() plugin.RPKIStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return plugin.RPKIStatus{
		Source:  c.name,
		Up:      c.up,
		Stale:   c.cfg.Stale(c.updated, time.Now()),
		VRPs:    c.cache.Len(),
		Updated: c.updated,
		Error:   c.lastErr,
	}
}

func (c *Client) run(ctx context.Context) {
	t := time.NewTicker(c.cfg.Refresh)
	defer t.Stop()
	for {
		c.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// poll fetches the document. A failed fetch keeps the last good cache,
// which serves until staleness.
func (c *Client) poll(ctx context.Context) {
	table, generated, err := c.fetch(ctx)
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		if ctx.Err() == nil {
			c.up, c.lastErr = false, err.Error()
		}
		return
	}
	if generated.IsZero() || generated.After(now) {
		generated = now
	}
	c.cache, c.updated, c.up, c.lastErr = table, generated, true, ""
	// A publisher slower than publisherLag can still outrun staleness:
	// this document would read as stale before the next poll.
	age := now.Sub(generated)
	late := age+c.cfg.Refresh > c.cfg.Staleness
	if late && !c.lagWarned {
		c.log.Warn("rpki json document goes stale before the next poll: the publisher is not regenerating it, or staleness is not above its regeneration cycle plus refresh",
			"source", c.name, "age", age.Round(time.Second), "refresh", c.cfg.Refresh, "staleness", c.cfg.Staleness)
	}
	c.lagWarned = late
}

func (c *Client) fetch(ctx context.Context) (*rpki.VRPs, time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL, nil)
	if err != nil {
		return nil, time.Time{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Time{}, fmt.Errorf("GET %s: %s", c.cfg.URL, resp.Status)
	}
	return parse(io.LimitReader(resp.Body, maxBody))
}

// document is the part of the VRP JSON that matters. Routinator writes
// metadata.generated (Unix seconds); rpki-client writes
// metadata.buildtime (RFC 3339).
type document struct {
	Metadata struct {
		Generated int64  `json:"generated"`
		Buildtime string `json:"buildtime"`
	} `json:"metadata"`
	ROAs []roa `json:"roas"`
}

type roa struct {
	ASN       asn    `json:"asn"`
	Prefix    string `json:"prefix"`
	MaxLength uint8  `json:"maxLength"`
}

// asn is "AS64496" (Routinator) or 64496 (rpki-client).
type asn uint32

func (a *asn) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	s = strings.TrimPrefix(strings.ToUpper(s), "AS")
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return fmt.Errorf("asn %s: %w", b, err)
	}
	*a = asn(v)
	return nil
}

// parse reads a VRP JSON document into a new cache and returns the time
// the document says it was generated (zero when it does not say). A
// payload whose prefix does not parse, or whose max length is shorter
// than the prefix or longer than the address, fails the whole document,
// so a broken file never replaces a good cache.
func parse(r io.Reader) (*rpki.VRPs, time.Time, error) {
	var doc document
	dec := json.NewDecoder(r)
	if err := dec.Decode(&doc); err != nil {
		return nil, time.Time{}, fmt.Errorf("vrp json: %w", err)
	}
	if len(doc.ROAs) > rpki.MaxVRPs {
		return nil, time.Time{}, fmt.Errorf("vrp json: %d payloads exceeds %d", len(doc.ROAs), rpki.MaxVRPs)
	}
	changes := make([]rpki.Change, 0, len(doc.ROAs))
	for i, v := range doc.ROAs {
		p, err := netip.ParsePrefix(v.Prefix)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("vrp json: roas[%d]: %w", i, err)
		}
		if int(v.MaxLength) < p.Bits() || int(v.MaxLength) > p.Addr().BitLen() {
			return nil, time.Time{}, fmt.Errorf("vrp json: roas[%d]: maxLength %d does not fit %s", i, v.MaxLength, p)
		}
		changes = append(changes, rpki.Change{Prefix: p.Masked(), MaxLen: v.MaxLength, ASN: uint32(v.ASN)})
	}
	table := rpki.NewVRPs()
	table.Apply(changes)
	var generated time.Time
	switch {
	case doc.Metadata.Generated > 0:
		generated = time.Unix(doc.Metadata.Generated, 0)
	case doc.Metadata.Buildtime != "":
		if t, err := time.Parse(time.RFC3339, doc.Metadata.Buildtime); err == nil {
			generated = t
		}
	}
	return table, generated, nil
}
