package config

import (
	"net/netip"
	"time"
)

// Auth bounds (#32). They match internal/auth.
const (
	MinSessionTTL = 5 * time.Minute
	MaxSessionTTL = 7 * 24 * time.Hour
	MinTokenTTL   = time.Hour
	MaxTokenTTL   = 365 * 24 * time.Hour
)

// Auth is role-based access to the ops HTTP server (#32). Users and API
// tokens live in the storage plugin; the first admin comes from the
// environment (PACKETEER_ADMIN_USER, PACKETEER_ADMIN_PASSWORD).
type Auth struct {
	// Enabled turns auth on. Unset it is true when the HTTP server runs
	// (DefaultAuth, #328); false keeps the single basic-auth account from
	// PACKETEER_HTTP_USER/PASSWORD, or no login at all: the explicit
	// opt-out and the rollback.
	Enabled *bool `yaml:"enabled"`
	// SessionTTL is how long an SSO sign-in lasts (default 12h, 5m-168h).
	SessionTTL time.Duration `yaml:"session_ttl"`
	// TokenTTL is an API token's lifetime when the request names none,
	// and the default is also bounded (default 2160h, 1h-8760h).
	TokenTTL time.Duration `yaml:"token_ttl"`
	// SSO is the single sign-on plugin (type oidc). Nil: local users only.
	SSO *PluginSpec `yaml:"sso"`
}

// AuthEnabled reports whether role-based access is on.
func (c *Config) AuthEnabled() bool {
	return c != nil && c.Auth != nil && c.Auth.Enabled != nil && *c.Auth.Enabled
}

// AuthOptedOut reports an explicit auth.enabled: false (#328).
func (c *Config) AuthOptedOut() bool {
	return c != nil && c.Auth != nil && c.Auth.Enabled != nil && !*c.Auth.Enabled
}

// DefaultAuth turns auth on, with sqlite storage, when the file has no
// auth.enabled value (#328). It leaves an explicit value alone, and it
// does nothing when the HTTP server is off or PACKETEER_HTTP_USER already
// protects it (basicAuth), so an existing install keeps starting. The
// controller calls it after the environment overrides are applied.
func (c *Config) DefaultAuth(basicAuth bool) {
	if (c.Auth != nil && c.Auth.Enabled != nil) || basicAuth || c.HTTPListen() == "" {
		return
	}
	if c.Auth == nil {
		c.Auth = &Auth{}
	}
	on := true
	c.Auth.Enabled = &on
	if c.Storage == nil {
		c.Storage = &PluginSpec{Type: "sqlite"}
	}
}

// HTTPAllowFrom parses http.allow_from. Validate has checked it.
func (c *Config) HTTPAllowFrom() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.HTTP.AllowFrom {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func (c *Config) validateAuth(add func(string, ...any)) {
	for i, s := range c.HTTP.AllowFrom {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			add("http.allow_from[%d]: %q is not a prefix (want e.g. 192.0.2.0/24 or 2001:db8::/32)", i, s)
			continue
		}
		if p != p.Masked() {
			add("http.allow_from[%d]: %q has host bits set (did you mean %s?)", i, s, p.Masked())
		}
	}
	a := c.Auth
	if a == nil {
		return
	}
	if a.SessionTTL != 0 && (a.SessionTTL < MinSessionTTL || a.SessionTTL > MaxSessionTTL) {
		add("auth.session_ttl %s must be between %s and %s", a.SessionTTL, MinSessionTTL, MaxSessionTTL)
	}
	if a.TokenTTL != 0 && (a.TokenTTL < MinTokenTTL || a.TokenTTL > MaxTokenTTL) {
		add("auth.token_ttl %s must be between %s and %s", a.TokenTTL, MinTokenTTL, MaxTokenTTL)
	}
	if a.SSO != nil && a.SSO.Type == "" {
		add("auth.sso.type is required")
	}
	if c.AuthEnabled() && c.Storage == nil {
		add("auth requires storage (users, tokens, and the audit log live there; e.g. storage: {type: sqlite})")
	}
	if !c.AuthEnabled() && a.SSO != nil {
		add("auth.sso needs auth.enabled: true")
	}
}
