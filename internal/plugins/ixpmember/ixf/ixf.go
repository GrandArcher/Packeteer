// Package ixf is the built-in ixp_member plugin. It GETs one IX-F 1.0
// member list, either IXP Manager's member export or one URL the operator
// names, and serves it read-only. It never announces and it is not a RIB
// source.
package ixf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
	"gopkg.in/yaml.v3"
)

// TypeName is the config type.
const TypeName = "ixf"

// exportPath is the only IXP Manager path this plugin requests.
const exportPath = "/api/v4/member-export/ixf/1.0"

// Defaults and bounds for the config knobs.
const (
	DefaultRefresh  = 15 * time.Minute
	minRefresh      = time.Minute
	maxRefresh      = 24 * time.Hour
	DefaultTimeout  = 30 * time.Second
	minTimeout      = time.Second
	maxTimeout      = 2 * time.Minute
	DefaultMaxBytes = 8 << 20
	minMaxBytes     = 1024
	maxMaxBytes     = 32 << 20
	keyWarnDays     = 14
	maxKeyLifeDays  = 366
	staleFactor     = 3
)

// errNoRedirect refuses every redirect. net/http would copy
// X-IXP-Manager-API-Key onto the next request.
var errNoRedirect = errors.New("redirects are not followed")

func init() { plugin.MemberSources.Register(TypeName, New) }

// Config is the ixf plugin's config block.
type Config struct {
	URL        string        `yaml:"url"`
	Refresh    time.Duration `yaml:"refresh"`
	MaxBytes   int           `yaml:"max_bytes"`
	Timeout    time.Duration `yaml:"timeout"`
	KeyExpires ymd           `yaml:"key_expires"`
}

// ymd accepts a quoted YYYY-MM-DD, an unquoted YAML date, or RFC3339.
// yaml.v3 tags an unquoted date as a timestamp; the node value is then
// the timestamp text, which parseExpires also accepts.
type ymd struct{ s string }

func (d *ymd) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag == "!!null" {
		d.s = ""
		return nil
	}
	if n.Kind != yaml.ScalarNode {
		return errors.New("key_expires must be YYYY-MM-DD")
	}
	d.s = n.Value
	return nil
}

// Source is the ixf member importer.
type Source struct {
	plugin.Base
	log      *slog.Logger
	refresh  time.Duration
	maxBytes int64
	fetchURL string
	manager  bool
	apiKey   string
	keyID    string
	expires  time.Time
	http     *http.Client

	mu      sync.Mutex
	view    plugin.MemberView
	sink    func(plugin.Event)
	keyNote keyState
	cancel  context.CancelFunc
	done    chan struct{}
}

type keyState int

const (
	keyNone keyState = iota
	keyOK
	keyExpiring
)

// New validates the config and the API key. It does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.MemberSource, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	apiKey := strings.TrimSpace(getenv(APIKeyEnv))
	fetchURL, manager, err := classifyURL(cfg.URL, apiKey)
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
	var ident string
	var expires time.Time
	switch {
	case apiKey != "" && cfg.KeyExpires.s == "":
		return nil, fmt.Errorf("key_expires is required when %s is set", APIKeyEnv)
	case apiKey == "" && cfg.KeyExpires.s != "":
		return nil, fmt.Errorf("key_expires is set but %s is not", APIKeyEnv)
	case apiKey != "":
		ident, err = parseAPIKey(apiKey)
		if err != nil {
			return nil, err
		}
		expires, err = parseExpires(cfg.KeyExpires.s, time.Now())
		if err != nil {
			return nil, err
		}
	}
	log := env.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Source{
		log: log, refresh: cfg.Refresh, maxBytes: int64(cfg.MaxBytes),
		fetchURL: fetchURL, manager: manager, apiKey: apiKey, keyID: ident, expires: expires,
		http: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errNoRedirect
			},
		},
		view: plugin.MemberView{
			Configured: true,
			URL:        viewURL(fetchURL),
			Manager:    manager,
			ManagerURL: managerBase(fetchURL, manager),
			KeyID:      ident,
			IXPs:       []plugin.IXPSite{},
			Members:    []plugin.IXPMember{},
		},
	}
	// Unset means absent from the API, not a zero time.
	if !expires.IsZero() {
		s.view.KeyExpires = &expires
	}
	return s, nil
}

// SetEventSink records where key-expiry events go. The controller calls
// it before Start. New does not emit: the sink is not set yet.
func (s *Source) SetEventSink(fn func(plugin.Event)) {
	s.mu.Lock()
	s.sink = fn
	s.mu.Unlock()
}

// Start fetches once, then on each refresh. It does not block.
func (s *Source) Start(ctx context.Context) error {
	s.noteKey(time.Now())
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
			s.noteKey(time.Now())
			s.fetch(ctx)
		}
	}
}

// Stop cancels the refresh loop and waits for it to leave.
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

// View returns the latest import. After three refresh intervals without a
// success the served list is empty, but the key id and the URL stay.
func (s *Source) View() plugin.MemberView {
	s.mu.Lock()
	v := s.view
	refresh := s.refresh
	s.mu.Unlock()
	// Copy the times so a caller cannot write through to the source's state.
	if v.Fetched != nil {
		t := *v.Fetched
		v.Fetched = &t
	}
	if v.KeyExpires != nil {
		t := *v.KeyExpires
		v.KeyExpires = &t
	}
	if v.IXPs == nil {
		v.IXPs = []plugin.IXPSite{}
	}
	if v.Members == nil {
		v.Members = []plugin.IXPMember{}
	}
	if v.Fetched != nil && v.Error != "" && time.Since(*v.Fetched) > staleFactor*refresh {
		v.Stale = true
		v.Error = "member list is stale"
		v.IXPs = []plugin.IXPSite{}
		v.Members = []plugin.IXPMember{}
		v.MemberCount = 0
		v.AddressCount = 0
	}
	return v
}

func (s *Source) fetch(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	body, err := s.get(ctx)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		s.publishErr(err)
		return
	}
	p, err := parseIXF(body)
	if err != nil {
		s.publishErr(err)
		return
	}
	s.mu.Lock()
	fetched := time.Now()
	s.view.Fetched = &fetched
	s.view.Error = ""
	s.view.Stale = false
	s.view.IXPs = p.ixps
	s.view.Members = p.members
	s.view.MemberCount = len(p.members)
	s.view.AddressCount = p.addresses
	s.mu.Unlock()
}

func (s *Source) publishErr(err error) {
	s.mu.Lock()
	s.view.Error = redact(err.Error(), s.apiKey)
	s.mu.Unlock()
}

func (s *Source) get(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.fetchURL, nil)
	if err != nil {
		return nil, errors.New("member export: bad url")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packeteer")
	if s.manager && s.apiKey != "" {
		req.Header.Set(apiKeyHeader, s.apiKey)
	}
	resp, err := s.http.Do(req)
	if err != nil {
		if errors.Is(err, errNoRedirect) {
			return nil, errors.New("member export: redirects are not followed")
		}
		// The client error carries the full request URL, query included.
		// The view serves this text, so keep only the cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, errors.New("member export: " + redact(err.Error(), s.apiKey))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes+1))
	if err != nil {
		return nil, errors.New("member export: read failed")
	}
	if int64(len(body)) > s.maxBytes {
		return nil, fmt.Errorf("member export: response larger than %d bytes", s.maxBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("member export: HTTP %d", resp.StatusCode)
	}
	return body, nil
}

// noteKey emits ixp.api_key_expiring or ixp.api_key_ok on a transition.
// The log and the event carry the identifier and the days left, never the secret.
func (s *Source) noteKey(now time.Time) {
	if s.keyID == "" {
		return
	}
	days := daysLeft(s.expires, now)
	next := keyOK
	kind := plugin.EventIXPKeyOK
	msg := fmt.Sprintf("IXP Manager API key %s is valid for %d days", s.keyID, days)
	if days <= keyWarnDays {
		next = keyExpiring
		kind = plugin.EventIXPKeyExpiring
		switch {
		case days < 0:
			msg = fmt.Sprintf("IXP Manager API key %s expired", s.keyID)
		case days == 0:
			msg = fmt.Sprintf("IXP Manager API key %s expires today", s.keyID)
		default:
			msg = fmt.Sprintf("IXP Manager API key %s expires in %d days", s.keyID, days)
		}
	}
	s.mu.Lock()
	if s.keyNote == next {
		s.mu.Unlock()
		return
	}
	s.keyNote = next
	sink := s.sink
	s.mu.Unlock()
	attrs := []any{"key_id", s.keyID, "expires", s.expires.UTC().Format("2006-01-02"), "days_left", days}
	if next == keyExpiring {
		s.log.Warn("IXP Manager API key expiry", attrs...)
	} else {
		s.log.Info("IXP Manager API key expiry", attrs...)
	}
	if sink != nil {
		sink(plugin.NewEvent(kind, now, msg, map[string]string{
			"identifier": s.keyID,
			"days_left":  strconv.Itoa(days),
		}))
	}
}

func daysLeft(expires, now time.Time) int {
	e := time.Date(expires.UTC().Year(), expires.UTC().Month(), expires.UTC().Day(), 0, 0, 0, 0, time.UTC)
	n := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	return int(e.Sub(n) / (24 * time.Hour))
}

func parseExpires(s string, now time.Time) (time.Time, error) {
	var t time.Time
	var err error
	if len(s) == 10 {
		t, err = time.Parse("2006-01-02", s)
	} else {
		var full time.Time
		full, err = time.Parse(time.RFC3339, s)
		if err == nil {
			u := full.UTC()
			t = time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
		}
	}
	if err != nil {
		return time.Time{}, errors.New("key_expires must be YYYY-MM-DD")
	}
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	if t.After(today.AddDate(0, 0, maxKeyLifeDays)) {
		return time.Time{}, errors.New("key_expires is more than 366 days ahead")
	}
	return t, nil
}
