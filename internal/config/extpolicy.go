package config

import (
	"net"
	"regexp"
	"time"
)

// DefaultPolicyTokenEnv is the environment variable that holds the external
// policy feed's bearer token unless token_env names another.
const DefaultPolicyTokenEnv = "PACKETEER_POLICY_TOKEN"

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ExternalPolicy publishes the outbound routes for the operator's own BGP
// daemon to apply (#232, docs/external-policy.md). It is a toggle beside
// the embedded announcer, not a mode: the feed carries routes only in
// mode inject, and they are the routes the announce controller puts on the
// wire. Nil or not enabled publishes nothing a consumer applies.
type ExternalPolicy struct {
	Enabled bool `yaml:"enabled"`
	// Listen is host:port of the TLS listener (JSON and gRPC).
	Listen   string `yaml:"listen"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// TokenEnv names the environment variable that holds the bearer token.
	TokenEnv string `yaml:"token_env"`
	// TTL is how long a consumer keeps the routes after the last decision
	// round renewed them. Zero is three probe intervals.
	TTL time.Duration `yaml:"ttl"`
}

// ExternalPolicyOn reports whether the feed is configured and enabled.
func (c *Config) ExternalPolicyOn() bool {
	return c != nil && c.ExternalPolicy != nil && c.ExternalPolicy.Enabled
}

func (c *Config) defaultExternalPolicy() {
	e := c.ExternalPolicy
	if e == nil {
		return
	}
	if e.TokenEnv == "" {
		e.TokenEnv = DefaultPolicyTokenEnv
	}
	if e.TTL == 0 {
		e.TTL = 3 * c.Probe.Interval
	}
}

// validateExternalPolicy checks the block whether or not it is enabled, so
// turning it on at runtime cannot fail on a key a restart would refuse.
// The decision loop renews the feed at least once per probe interval, and
// a heartbeat is a third of the TTL, so three intervals leave a slow round
// and a late heartbeat room before a healthy feed expires.
func (c *Config) validateExternalPolicy(add func(string, ...any)) {
	e := c.ExternalPolicy
	if e == nil {
		return
	}
	if _, port, err := net.SplitHostPort(e.Listen); err != nil || port == "" {
		add("external_policy.listen %q must be host:port", e.Listen)
	}
	if e.CertFile == "" || e.KeyFile == "" {
		add("external_policy requires cert_file and key_file (the feed is served over TLS only)")
	}
	if !envNameRE.MatchString(e.TokenEnv) {
		add("external_policy.token_env %q must be an environment variable name", e.TokenEnv)
	}
	if e.TTL < 3*c.Probe.Interval {
		add("external_policy.ttl %s must be at least three probe intervals (%s)", e.TTL, 3*c.Probe.Interval)
	}
}
