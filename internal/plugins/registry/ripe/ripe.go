// Package ripe is the RIPE database registry plugin (#289). It reads
// nothing: it applies one confirmed route or route6 object creation or
// deletion through the RIPE database REST API (rest.db.ripe.net, or the
// TEST database), with the maintainer credentials from the environment.
// Findings come from the irr sources, not from here. It never announces
// and never changes the learned RIB.
package ripe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "ripe"

// Credentials are read from these variables, only when a change is pushed,
// and sent only as HTTP basic authentication to base_url.
const (
	UserEnv     = "PACKETEER_RIPE_USER"
	PasswordEnv = "PACKETEER_RIPE_PASSWORD"
)

// DefaultBaseURL is the RIPE database REST API.
const DefaultBaseURL = "https://rest.db.ripe.net"

// Defaults and bounds.
const (
	DefaultTimeout = 30 * time.Second
	minTimeout     = time.Second
	maxTimeout     = 2 * time.Minute
	maxBody        = 1 << 20
)

func init() { plugin.RegistryCheckers.Register(TypeName, New) }

// Config is the plugin's config block.
type Config struct {
	BaseURL string `yaml:"base_url"`
	// Source is the database: RIPE, or TEST for the RIPE test database.
	Source  string        `yaml:"source"`
	Timeout time.Duration `yaml:"timeout"`
}

// Pusher applies route object changes.
type Pusher struct {
	plugin.Base
	base   *url.URL
	source string
	getenv func(string) string
	http   *http.Client
	limit  *rate.Limiter
}

// New validates the config. It reads no credential and does not dial.
func New(c plugin.Config, env plugin.Env) (plugin.RegistryChecker, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("base_url must be an https URL with a host and no userinfo, query, or fragment")
	}
	base.Path = strings.TrimRight(base.Path, "/")
	switch cfg.Source = strings.ToUpper(cfg.Source); cfg.Source {
	case "":
		cfg.Source = "RIPE"
	case "RIPE", "TEST":
	default:
		return nil, fmt.Errorf("source %q must be RIPE or TEST", cfg.Source)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Timeout < minTimeout || cfg.Timeout > maxTimeout {
		return nil, fmt.Errorf("timeout %s must be between %s and %s", cfg.Timeout, minTimeout, maxTimeout)
	}
	getenv := env.Getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return &Pusher{
		base: base, source: cfg.Source, getenv: getenv,
		limit: rate.NewLimiter(rate.Every(time.Second), 1),
		http: &http.Client{
			Timeout: cfg.Timeout,
			// A redirect would carry the credentials to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// Check reports nothing: the findings for this registry come from the irr
// sources.
func (*Pusher) Check(context.Context, plugin.RegistryFacts) ([]plugin.RegistryFinding, error) {
	return nil, nil
}

// Push creates or deletes one route or route6 object in the configured
// database.
func (p *Pusher) Push(ctx context.Context, ch plugin.RegistryChange) error {
	if ch.Registry != TypeName || (ch.Op != "create_object" && ch.Op != "delete_object") || (ch.Class != "route" && ch.Class != "route6") {
		return plugin.ErrRegistryNoPush
	}
	user, pass := p.getenv(UserEnv), p.getenv(PasswordEnv)
	if user == "" || pass == "" {
		return fmt.Errorf("pushing needs %s and %s", UserEnv, PasswordEnv)
	}
	obj, err := p.parse(ch)
	if err != nil {
		return err
	}
	if err := p.limit.Wait(ctx); err != nil {
		return err
	}
	u := *p.base
	var req *http.Request
	if ch.Op == "create_object" {
		u.Path += "/" + strings.ToLower(p.source) + "/" + ch.Class
		body, err := json.Marshal(restObject(obj, p.source))
		if err != nil {
			return err
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
		if err != nil {
			return errors.New("ripe: bad url")
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		u.Path += "/" + strings.ToLower(p.source) + "/" + ch.Class + "/" + ch.Key
		u.RawQuery = url.Values{"reason": {"removed after operator confirmation in Packeteer"}}.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
		if err != nil {
			return errors.New("ripe: bad url")
		}
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "packeteer")
	resp, err := p.http.Do(req)
	if err != nil {
		return errors.New("ripe: " + strings.NewReplacer(user, "redacted", pass, "redacted").Replace(err.Error()))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("ripe: %s %s: HTTP %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	return nil
}

// parse checks that the object text is the single object the key names,
// in the configured database, so the confirmed diff is what is sent.
func (p *Pusher) parse(ch plugin.RegistryChange) (irr.Object, error) {
	var objs []irr.Object
	err := irr.ParseRPSL(strings.NewReader(ch.Object), func(o irr.Object) error {
		objs = append(objs, o)
		return nil
	})
	if err != nil || len(objs) != 1 {
		return nil, errors.New("ripe: the change must hold exactly one RPSL object")
	}
	o := objs[0]
	rt, ok := irr.Route(o)
	if o.Class() != ch.Class || !ok || ch.Key != fmt.Sprintf("%sAS%d", rt.Prefix, rt.Origin) {
		return nil, errors.New("ripe: the object does not match the key")
	}
	if !strings.EqualFold(o.Get("source"), p.source) {
		return nil, fmt.Errorf("ripe: the object's source is not %s", p.source)
	}
	return o, nil
}

// restObject is the JSON the REST API takes for one object.
func restObject(o irr.Object, source string) map[string]any {
	attrs := make([]map[string]string, 0, len(o))
	for _, a := range o {
		attrs = append(attrs, map[string]string{"name": a.Name, "value": a.Value})
	}
	return map[string]any{"objects": map[string]any{"object": []any{map[string]any{
		"source":     map[string]string{"id": source},
		"attributes": map[string]any{"attribute": attrs},
	}}}}
}
