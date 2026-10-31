// Package peeringdb is the built-in lookup plugin. It GETs PeeringDB
// net, netixlan, and ix records for the configured exchanges, and an
// optional IX-F member export per exchange, and serves them from an
// in-memory cache. It never announces and it is not a RIB source.
// Requests are GET only. Redirects are not followed, so the API key
// cannot be sent to another host.
package peeringdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "peeringdb"

// APIKeyEnv is the only place the PeeringDB key is read from. It is sent
// only as an Authorization header to the configured base host.
const APIKeyEnv = "PACKETEER_PEERINGDB_API_KEY"

// DefaultBaseURL is the PeeringDB API origin. peeringdb.com redirects;
// this host is requested directly.
const DefaultBaseURL = "https://www.peeringdb.com"

// Defaults and bounds. The pace is not a config knob: it is PeeringDB's
// published minimum gap, wider when there is no key.
const (
	DefaultRefresh  = 24 * time.Hour
	minRefresh      = time.Hour
	maxRefresh      = 24 * time.Hour
	DefaultTimeout  = 30 * time.Second
	minTimeout      = time.Second
	maxTimeout      = 2 * time.Minute
	DefaultMaxBytes = 8 << 20
	minMaxBytes     = 1024
	maxMaxBytes     = 32 << 20
	maxKeyLen       = 256
	maxExchanges    = 32
	maxNets         = 20000
	maxMemberships  = 20000
	maxNameLen      = 256
	maxPolicyLen    = 64
	maxURLLen       = 512
	maxPlaceLen     = 128
	netChunk        = 150
	staleFactor     = 3
	anonymousGap    = 3 * time.Second
	keyedGap        = 2 * time.Second
)

// errNoRedirect refuses every redirect. net/http would otherwise copy
// Authorization onto the next request.
var errNoRedirect = errors.New("redirects are not followed")

func init() { plugin.Lookups.Register(TypeName, New) }

// Config is the peeringdb plugin's config block.
type Config struct {
	BaseURL   string           `yaml:"base_url"`
	Refresh   time.Duration    `yaml:"refresh"`
	Timeout   time.Duration    `yaml:"timeout"`
	MaxBytes  int              `yaml:"max_bytes"`
	Exchanges []ExchangeConfig `yaml:"exchanges"`
}

// ExchangeConfig is one exchange to look up. Name is the label shown in
// the view; use the same name as exchanges[].name. IXID is the PeeringDB ix id.
type ExchangeConfig struct {
	Name   string `yaml:"name"`
	IXID   int    `yaml:"ix_id"`
	IXFURL string `yaml:"ixf_url"`
}

type exch struct {
	name   string
	ixID   int
	ixfURL string
}

// Source is the peeringdb directory cache.
type Source struct {
	log      *slog.Logger
	refresh  time.Duration
	maxBytes int64
	gap      time.Duration
	base     *url.URL
	apiKey   string
	list     []exch
	http     *http.Client
	// sleep replaces the inter-request wait in tests. Nil uses a timer.
	sleep func(ctx context.Context, d time.Duration) error

	mu      sync.Mutex
	view    plugin.LookupView
	lastReq time.Time
	cancel  context.CancelFunc
	done    chan struct{}
}

// New validates the config and the API key. It does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.Lookup, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	key, err := ParseKey(getenv(APIKeyEnv))
	if err != nil {
		return nil, err
	}
	base, err := ParseBase(cfg.BaseURL, key)
	if err != nil {
		return nil, err
	}
	if cfg.Refresh == 0 {
		cfg.Refresh = DefaultRefresh
	}
	if cfg.Refresh < minRefresh || cfg.Refresh > maxRefresh {
		return nil, fmt.Errorf("refresh %s must be between %s and %s", cfg.Refresh, minRefresh, maxRefresh)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout > maxTimeout {
		return nil, fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, minTimeout, maxTimeout)
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}
	if cfg.MaxBytes < minMaxBytes || cfg.MaxBytes > maxMaxBytes {
		return nil, fmt.Errorf("max_bytes %d must be between %d and %d", cfg.MaxBytes, minMaxBytes, maxMaxBytes)
	}
	list, err := normalizeExchanges(cfg.Exchanges, key)
	if err != nil {
		return nil, err
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	initial := make([]plugin.LookupExchange, len(list))
	for i, ex := range list {
		initial[i] = plugin.LookupExchange{Name: ex.name, IXID: ex.ixID, IXFURL: ex.ixfURL}
	}
	s := &Source{
		log: log, refresh: cfg.Refresh, maxBytes: int64(cfg.MaxBytes),
		gap: anonymousGap, base: base, apiKey: key, list: list,
		http: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errNoRedirect
			},
		},
		view: plugin.LookupView{
			Configured:  true,
			Anonymous:   key == "",
			BaseURL:     base.String(),
			Exchanges:   initial,
			Networks:    []plugin.LookupNetwork{},
			Memberships: []plugin.LookupMembership{},
		},
	}
	if key != "" {
		s.gap = keyedGap
	}
	return s, nil
}

func normalizeExchanges(in []ExchangeConfig, key string) ([]exch, error) {
	if len(in) == 0 {
		return nil, errors.New("exchanges is required")
	}
	if len(in) > maxExchanges {
		return nil, fmt.Errorf("exchanges %d exceeds %d", len(in), maxExchanges)
	}
	seenName := map[string]bool{}
	seenID := map[int]bool{}
	out := make([]exch, 0, len(in))
	for _, ex := range in {
		if !plugin.ValidLabel(ex.Name) {
			return nil, fmt.Errorf("exchange name %q is invalid", ex.Name)
		}
		if ex.IXID <= 0 {
			return nil, fmt.Errorf("exchange %s: ix_id must be positive", ex.Name)
		}
		if seenName[ex.Name] {
			return nil, fmt.Errorf("duplicate exchange name %q", ex.Name)
		}
		if seenID[ex.IXID] {
			return nil, fmt.Errorf("duplicate ix_id %d", ex.IXID)
		}
		ixfURL, err := parseIXFURL(ex.IXFURL, key)
		if err != nil {
			return nil, fmt.Errorf("exchange %s: %w", ex.Name, err)
		}
		seenName[ex.Name] = true
		seenID[ex.IXID] = true
		out = append(out, exch{name: ex.Name, ixID: ex.IXID, ixfURL: ixfURL})
	}
	return out, nil
}

// Start fetches once, then on each refresh. It does not block.
func (s *Source) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.mu.Lock()
	s.cancel = cancel
	s.done = done
	s.mu.Unlock()
	go s.loop(ctx, done)
	return nil
}

func (s *Source) loop(ctx context.Context, done chan struct{}) {
	defer close(done)
	s.fetch(ctx)
	t := time.NewTicker(s.refresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.fetch(ctx)
		}
	}
}

// Stop cancels the refresh loop and any request it is in, and waits for
// the loop to leave.
func (s *Source) Stop(ctx context.Context) error {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// View returns the latest cache. After three refresh intervals without a
// success the served networks and memberships are empty. Configured
// exchange names, ix ids, IX-F URLs, and errors stay.
func (s *Source) View() plugin.LookupView {
	s.mu.Lock()
	v := s.view
	refresh := s.refresh
	s.mu.Unlock()
	if v.Exchanges == nil {
		v.Exchanges = []plugin.LookupExchange{}
	}
	if v.Networks == nil {
		v.Networks = []plugin.LookupNetwork{}
	}
	if v.Memberships == nil {
		v.Memberships = []plugin.LookupMembership{}
	}
	if !v.Fetched.IsZero() && v.Error != "" && time.Since(v.Fetched) > staleFactor*refresh {
		v.Stale = true
		v.Error = "lookup is stale"
		v.Networks = []plugin.LookupNetwork{}
		v.Memberships = []plugin.LookupMembership{}
		v.NetworkCount = 0
		v.MembershipCount = 0
		ex := make([]plugin.LookupExchange, len(v.Exchanges))
		copy(ex, v.Exchanges)
		for i := range ex {
			ex[i].IXName = ""
			ex[i].City = ""
			ex[i].Country = ""
		}
		v.Exchanges = ex
	}
	return v
}

func (s *Source) fetch(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	v, err := s.pull(ctx)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		s.publishErr(err)
		return
	}
	s.mu.Lock()
	s.view.Fetched = time.Now()
	s.view.Error = ""
	s.view.Stale = false
	s.view.Exchanges = v.Exchanges
	s.view.Networks = v.Networks
	s.view.Memberships = v.Memberships
	s.view.NetworkCount = len(v.Networks)
	s.view.MembershipCount = len(v.Memberships)
	s.mu.Unlock()
}

func (s *Source) publishErr(err error) {
	s.mu.Lock()
	s.view.Error = Redact(err.Error(), s.apiKey)
	s.mu.Unlock()
	s.log.Warn("peeringdb lookup failed", "err", Redact(err.Error(), s.apiKey))
}

func (s *Source) pull(ctx context.Context) (plugin.LookupView, error) {
	ids := make([]int, len(s.list))
	for i, ex := range s.list {
		ids[i] = ex.ixID
	}
	idQuery := joinIDs(ids)
	ixBody, err := s.get(ctx, s.apiURL("/api/ix", "id__in="+idQuery), true)
	if err != nil {
		return plugin.LookupView{}, err
	}
	ix, err := decodeIX(ixBody)
	if err != nil {
		return plugin.LookupView{}, err
	}
	lanBody, err := s.get(ctx, s.apiURL("/api/netixlan", "ix_id__in="+idQuery+"&status=ok"), true)
	if err != nil {
		return plugin.LookupView{}, err
	}
	lans, err := decodeLAN(lanBody)
	if err != nil {
		return plugin.LookupView{}, err
	}
	ixOK := map[int]bool{}
	for _, row := range ix {
		ixOK[row.id] = true
	}
	var nets []rawNet
	for _, chunk := range chunks(netIDs(lans, ixOK), netChunk) {
		body, err := s.get(ctx, s.apiURL("/api/net", "id__in="+joinIDs(chunk)), true)
		if err != nil {
			return plugin.LookupView{}, err
		}
		part, err := decodeNet(body)
		if err != nil {
			return plugin.LookupView{}, err
		}
		nets = append(nets, part...)
	}
	orgs := map[int]string{}
	for _, chunk := range chunks(orgIDs(nets), netChunk) {
		body, err := s.get(ctx, s.apiURL("/api/org", "id__in="+joinIDs(chunk)), true)
		if err != nil {
			return plugin.LookupView{}, err
		}
		part, err := decodeOrg(body)
		if err != nil {
			return plugin.LookupView{}, err
		}
		maps.Copy(orgs, part)
	}
	ixfRows := map[string][]rawIXF{}
	ixfErr := map[string]string{}
	for _, ex := range s.list {
		if ex.ixfURL == "" {
			continue
		}
		body, err := s.get(ctx, ex.ixfURL, false)
		if ctx.Err() != nil {
			return plugin.LookupView{}, ctx.Err()
		}
		if err != nil {
			ixfErr[ex.name] = Redact(err.Error(), s.apiKey)
			continue
		}
		rows, err := decodeIXF(body)
		if err != nil {
			ixfErr[ex.name] = Redact(err.Error(), s.apiKey)
			continue
		}
		ixfRows[ex.name] = rows
	}
	return assemble(s.list, ix, nets, orgs, lans, ixfRows, ixfErr)
}

func (s *Source) apiURL(path, query string) string {
	u := *s.base
	u.Path = s.base.Path + path
	u.RawQuery = query
	return u.String()
}

func (s *Source) get(ctx context.Context, rawURL string, auth bool) ([]byte, error) {
	if err := s.wait(ctx); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("lookup: bad url")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packeteer")
	if auth {
		s.authorize(req)
	}
	resp, err := s.http.Do(req)
	s.stamp()
	if err != nil {
		if errors.Is(err, errNoRedirect) {
			return nil, errors.New("lookup: redirects are not followed")
		}
		return nil, errors.New("lookup: " + Redact(err.Error(), s.apiKey))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes+1))
	if err != nil {
		return nil, errors.New("lookup: read failed")
	}
	if int64(len(body)) > s.maxBytes {
		return nil, fmt.Errorf("lookup: response larger than %d bytes", s.maxBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lookup: HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// authorize attaches the key only when the request stays on the configured
// base. IX-F URLs are fetched with auth false and never reach this.
func (s *Source) authorize(req *http.Request) {
	if s.apiKey == "" || req.URL == nil {
		return
	}
	if req.URL.Scheme != s.base.Scheme || !strings.EqualFold(req.URL.Host, s.base.Host) {
		return
	}
	req.Header.Set("Authorization", "Api-Key "+s.apiKey)
}

func (s *Source) wait(ctx context.Context) error {
	s.mu.Lock()
	last, gap, sleep := s.lastReq, s.gap, s.sleep
	s.mu.Unlock()
	if last.IsZero() || gap <= 0 {
		return nil
	}
	d := gap - time.Since(last)
	if d <= 0 {
		return nil
	}
	if sleep != nil {
		return sleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Source) stamp() {
	s.mu.Lock()
	s.lastReq = time.Now()
	s.mu.Unlock()
}

func joinIDs(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ",")
}

func chunks(ids []int, n int) [][]int {
	if len(ids) == 0 {
		return nil
	}
	var out [][]int
	for len(ids) > 0 {
		end := n
		if end > len(ids) {
			end = len(ids)
		}
		out = append(out, ids[:end])
		ids = ids[end:]
	}
	return out
}
