// Package oidc is the OpenID Connect single sign-on plugin (#32). It runs
// the authorization code flow with PKCE against the operator's identity
// provider, verifies the ID token (signature, issuer, audience, expiry,
// nonce), and maps a claim (groups by default) to a Packeteer role. It
// only says who a user is; it never announces routes.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "oidc"

// Config is the plugin config block.
type Config struct {
	// Issuer is the provider's issuer URL. https is required, except
	// http on a loopback host (a lab).
	Issuer string `yaml:"issuer"`
	// ClientID is this application's client id at the provider.
	ClientID string `yaml:"client_id"`
	// ClientSecretEnv names the environment variable with the client
	// secret. The secret is never read from the config file.
	ClientSecretEnv string `yaml:"client_secret_env"`
	// RedirectURL is https://<packeteer>/auth/callback as registered at
	// the provider.
	RedirectURL string `yaml:"redirect_url"`
	// Scopes requested besides openid (default email, profile).
	Scopes []string `yaml:"scopes"`
	// UsernameClaim names the claim used as the account name (default
	// email). An email claim with email_verified false is refused.
	UsernameClaim string `yaml:"username_claim"`
	// RolesClaim names the claim with the user's groups (default groups).
	// It may be a string or a list of strings.
	RolesClaim string `yaml:"roles_claim"`
	// RoleMap maps a group to a role. The highest mapped role wins.
	RoleMap map[string]plugin.Role `yaml:"role_map"`
	// DefaultRole is granted when no group maps. Empty refuses the
	// sign-in.
	DefaultRole plugin.Role `yaml:"default_role"`
}

// Plugin is the OIDC SSO plugin.
type Plugin struct {
	plugin.Base
	cfg    Config
	secret string
	log    *slog.Logger
	client *http.Client

	mu       sync.Mutex
	provider *gooidc.Provider
}

func init() {
	plugin.SSOs.Register(TypeName, func(c plugin.Config, e plugin.Env) (plugin.SSO, error) {
		return New(c, e)
	})
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func checkURL(key, raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s %q is not an absolute URL", key, raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopback(u.Hostname()):
	default:
		return fmt.Errorf("%s %q must be https (http only on a loopback host)", key, raw)
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%s %q must not carry credentials or a fragment", key, raw)
	}
	return nil
}

// New validates the config and reads the client secret. It does not
// contact the provider.
func New(c plugin.Config, env plugin.Env) (*Plugin, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if err := checkURL("issuer", cfg.Issuer); err != nil {
		errs = append(errs, err)
	}
	if err := checkURL("redirect_url", cfg.RedirectURL); err != nil {
		errs = append(errs, err)
	} else if u, _ := url.Parse(cfg.RedirectURL); u.Path != "/auth/callback" {
		add("redirect_url %q must end in /auth/callback", cfg.RedirectURL)
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		add("client_id is required")
	}
	var secret string
	if cfg.ClientSecretEnv == "" {
		add("client_secret_env is required (the secret is read from the environment)")
	} else if env.Getenv != nil {
		secret = env.Getenv(cfg.ClientSecretEnv)
		if secret == "" {
			add("environment variable %s (client_secret_env) is empty", cfg.ClientSecretEnv)
		}
	}
	if cfg.UsernameClaim == "" {
		cfg.UsernameClaim = "email"
	}
	if cfg.RolesClaim == "" {
		cfg.RolesClaim = "groups"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"email", "profile"}
	}
	for _, sc := range cfg.Scopes {
		if sc == "" || strings.ContainsAny(sc, " \t") {
			add("scopes: %q is not a scope", sc)
		}
	}
	for g, r := range cfg.RoleMap {
		if !r.Valid() {
			add("role_map[%s]: %q must be viewer, operator, or admin", g, r)
		}
	}
	if cfg.DefaultRole != "" && !cfg.DefaultRole.Valid() {
		add("default_role %q must be viewer, operator, admin, or empty", cfg.DefaultRole)
	}
	if len(cfg.RoleMap) == 0 && cfg.DefaultRole == "" {
		add("role_map or default_role is required (otherwise nobody gets a role)")
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	p := &Plugin{cfg: cfg, secret: secret, client: &http.Client{Timeout: 15 * time.Second}}
	p.log = env.Logger
	if p.log == nil {
		p.log = slog.Default()
	}
	return p, nil
}

// Start reads the discovery document. A provider that is down does not
// stop the controller: discovery is retried at the next sign-in.
func (p *Plugin) Start(ctx context.Context) error {
	if _, err := p.discover(ctx); err != nil {
		p.log.Warn("oidc discovery failed; retrying at the next sign-in", "issuer", p.cfg.Issuer, "err", err)
	}
	return nil
}

func (p *Plugin) discover(ctx context.Context) (*gooidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, nil
	}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	prov, err := gooidc.NewProvider(gooidc.ClientContext(dctx, p.client), p.cfg.Issuer)
	if err != nil {
		return nil, err
	}
	p.provider = prov
	return prov, nil
}

func (p *Plugin) oauth(prov *gooidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID: p.cfg.ClientID, ClientSecret: p.secret, RedirectURL: p.cfg.RedirectURL,
		Endpoint: prov.Endpoint(), Scopes: append([]string{gooidc.ScopeOpenID}, p.cfg.Scopes...),
	}
}

// AuthURL implements plugin.SSO.
func (p *Plugin) AuthURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	prov, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	return p.oauth(prov).AuthCodeURL(state, gooidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange implements plugin.SSO.
func (p *Plugin) Exchange(ctx context.Context, code, nonce, verifier string) (plugin.SSOIdentity, error) {
	prov, err := p.discover(ctx)
	if err != nil {
		return plugin.SSOIdentity{}, err
	}
	ctx = gooidc.ClientContext(ctx, p.client)
	tok, err := p.oauth(prov).Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return plugin.SSOIdentity{}, fmt.Errorf("token exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return plugin.SSOIdentity{}, errors.New("token response has no id_token")
	}
	idt, err := prov.Verifier(&gooidc.Config{ClientID: p.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return plugin.SSOIdentity{}, fmt.Errorf("id token: %w", err)
	}
	if idt.Nonce != nonce {
		return plugin.SSOIdentity{}, errors.New("id token: nonce does not match")
	}
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return plugin.SSOIdentity{}, fmt.Errorf("id token claims: %w", err)
	}
	return p.identity(idt.Subject, claims)
}

// identity maps verified claims to an account name and role.
func (p *Plugin) identity(subject string, claims map[string]any) (plugin.SSOIdentity, error) {
	name, _ := claims[p.cfg.UsernameClaim].(string)
	if p.cfg.UsernameClaim == "sub" {
		name = subject
	}
	if name == "" {
		return plugin.SSOIdentity{}, fmt.Errorf("id token has no %s claim", p.cfg.UsernameClaim)
	}
	if p.cfg.UsernameClaim == "email" {
		if v, ok := claims["email_verified"].(bool); ok && !v {
			return plugin.SSOIdentity{}, errors.New("email is not verified at the identity provider")
		}
	}
	var groups []string
	switch g := claims[p.cfg.RolesClaim].(type) {
	case string:
		groups = []string{g}
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				groups = append(groups, s)
			}
		}
	}
	var role plugin.Role
	for _, g := range groups {
		if r, ok := p.cfg.RoleMap[g]; ok && (role == "" || r.Allows(role)) {
			role = r
		}
	}
	if role == "" {
		role = p.cfg.DefaultRole
	}
	if role == "" {
		return plugin.SSOIdentity{}, fmt.Errorf("user %s is in no group mapped to a role", name)
	}
	return plugin.SSOIdentity{User: name, Subject: subject, Role: role}, nil
}
