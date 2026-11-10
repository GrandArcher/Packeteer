// Package mikrotik is the non-BGP mode's steerer for RouterOS 7 (#300). It
// keeps one static route per steered prefix through the router's REST API
// (/rest/ip/route and /rest/ipv6/route), each tagged with a fixed comment.
// It lists, changes, and deletes only tagged routes, and refuses to add a
// route for a prefix the operator already routes by hand, because a second
// route for the same prefix would share the traffic with it.
package mikrotik

import (
	"bytes"
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

	"github.com/GrandArcher/Packeteer/internal/outbound"
	"github.com/GrandArcher/Packeteer/internal/plugins/exporter/sinkcfg"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "mikrotik"

// Tag is the comment on every route this plugin owns.
const Tag = "packeteer-steer"

const (
	requestTimeout = 10 * time.Second
	maxBody        = 4 << 20
)

func init() { plugin.Steerers.Register(TypeName, New) }

// Config is the plugin's config block. The REST API carries the router
// login, so the URL must be https (http only to a loopback host).
type Config struct {
	URL         string `yaml:"url"`
	UsernameEnv string `yaml:"username_env"`
	PasswordEnv string `yaml:"password_env"`
	// CAFile is an absolute path to the PEM certificate that signed the
	// router's REST certificate. Without it the system roots are used.
	CAFile string `yaml:"ca_file"`
}

// Steerer is the RouterOS REST steerer.
type Steerer struct {
	plugin.Base
	base       string
	user, pass string
	http       *http.Client
}

// New is the plugin factory. It validates the config and contacts nothing.
func New(c plugin.Config, env plugin.Env) (plugin.Steerer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	u, err := sinkcfg.HTTPURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	if err := sinkcfg.TokenURL(u); err != nil {
		return nil, fmt.Errorf("url: %w", err)
	}
	if cfg.UsernameEnv == "" || cfg.PasswordEnv == "" {
		return nil, errors.New("username_env and password_env are required: the REST API needs a login")
	}
	user, pass, err := sinkcfg.Credentials(env.Getenv, cfg.UsernameEnv, cfg.PasswordEnv)
	if err != nil && !env.CheckOnly {
		return nil, err
	}
	tlsConf, err := sinkcfg.TLS(u.Scheme == "https", cfg.CAFile)
	if err != nil {
		return nil, err
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConf
	return &Steerer{
		base: strings.TrimRight(u.String(), "/") + "/rest", user: user, pass: pass,
		// The login must never follow a redirect to another host.
		http: &http.Client{Timeout: requestTimeout, Transport: tr, CheckRedirect: outbound.SameHost},
	}, nil
}

// row is one route as RouterOS lists it. Every value is a string.
type row struct {
	ID      string `json:".id"`
	Dst     string `json:"dst-address"`
	Gateway string `json:"gateway"`
	Comment string `json:"comment"`
}

func path(p netip.Prefix) string {
	if p.Addr().Is6() {
		return "/ipv6/route"
	}
	return "/ip/route"
}

func (s *Steerer) do(ctx context.Context, method, p string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.base+p, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(s.user, s.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("routeros %s %s: %s", method, p, httpError(resp.Status, data))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// httpError is the status and the router's one-line message, which holds
// no credentials.
func httpError(status string, body []byte) string {
	var m struct {
		Message string `json:"message"`
		Detail  string `json:"detail"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		if m.Detail != "" {
			return status + ": " + m.Message + " (" + m.Detail + ")"
		}
		return status + ": " + m.Message
	}
	return status
}

// routes lists the routes for dst. RouterOS filters by property in the
// query; the result is filtered again here so a router that ignores the
// filter cannot make this plugin touch a route it did not match.
func (s *Steerer) routes(ctx context.Context, p netip.Prefix) ([]row, error) {
	var rows []row
	q := url.Values{"dst-address": {p.Masked().String()}}
	if err := s.do(ctx, http.MethodGet, path(p)+"?"+q.Encode(), nil, &rows); err != nil {
		return nil, err
	}
	var out []row
	for _, r := range rows {
		if got, err := netip.ParsePrefix(r.Dst); err == nil && got.Masked() == p.Masked() {
			out = append(out, r)
		}
	}
	return out, nil
}

// Install adds the tagged route, or points the tagged route at the new
// gateway. It refuses a prefix that has a route it did not add.
func (s *Steerer) Install(ctx context.Context, r plugin.SteerRoute) error {
	p := r.Prefix.Masked()
	rows, err := s.routes(ctx, p)
	if err != nil {
		return err
	}
	var mine *row
	var errs []error
	for i := range rows {
		if rows[i].Comment != Tag {
			return fmt.Errorf("routeros already has a route for %s that %s did not add; remove it or leave the prefix out of the allowlist", p, Tag)
		}
		if mine == nil {
			mine = &rows[i]
		}
	}
	if mine == nil {
		return s.do(ctx, http.MethodPut, path(p), map[string]string{
			"dst-address": p.String(), "gateway": r.NextHop.String(), "comment": Tag,
		}, nil)
	}
	// A second tagged row would keep the old gateway and split the traffic.
	for _, extra := range rows {
		if extra.ID != mine.ID {
			errs = append(errs, s.do(ctx, http.MethodDelete, path(p)+"/"+url.PathEscape(extra.ID), nil, nil))
		}
	}
	if mine.Gateway != r.NextHop.String() {
		errs = append(errs, s.do(ctx, http.MethodPatch, path(p)+"/"+url.PathEscape(mine.ID), map[string]string{"gateway": r.NextHop.String()}, nil))
	}
	return errors.Join(errs...)
}

// Remove deletes the tagged routes for p.
func (s *Steerer) Remove(ctx context.Context, p netip.Prefix) error {
	rows, err := s.routes(ctx, p)
	if err != nil {
		return err
	}
	var errs []error
	for _, r := range rows {
		if r.Comment != Tag {
			continue
		}
		errs = append(errs, s.do(ctx, http.MethodDelete, path(p)+"/"+url.PathEscape(r.ID), nil, nil))
	}
	return errors.Join(errs...)
}

// Owned lists the tagged routes of both families.
func (s *Steerer) Owned(ctx context.Context) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range []string{"/ip/route", "/ipv6/route"} {
		var rows []row
		q := url.Values{"comment": {Tag}}
		if err := s.do(ctx, http.MethodGet, p+"?"+q.Encode(), nil, &rows); err != nil {
			return nil, err
		}
		for _, r := range rows {
			if pf, err := netip.ParsePrefix(r.Dst); err == nil && r.Comment == Tag {
				out = append(out, pf.Masked())
			}
		}
	}
	return out, nil
}
