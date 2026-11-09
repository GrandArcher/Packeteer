package config

import (
	"strings"
	"testing"
	"time"
)

func TestAuthConfig(t *testing.T) {
	const storage = "storage:\n  type: sqlite\n"
	cfg, err := Parse([]byte(validYAML + storage + "auth:\n  enabled: true\nhttp:\n  allow_from: [127.0.0.0/8, 192.0.2.0/24, \"2001:db8::/32\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AuthEnabled() || len(cfg.HTTPAllowFrom()) != 3 || cfg.Mode != ModeObserve {
		t.Fatalf("auth %v allow %v mode %s", cfg.AuthEnabled(), cfg.HTTPAllowFrom(), cfg.Mode)
	}
	cfg, err = Parse([]byte(validYAML))
	if err != nil || cfg.AuthEnabled() || len(cfg.HTTPAllowFrom()) != 0 {
		t.Fatalf("defaults: %v %v", cfg.AuthEnabled(), err)
	}
	cfg, err = Parse([]byte(validYAML + "auth:\n  enabled: false\n"))
	if err != nil || cfg.AuthEnabled() {
		t.Fatalf("disabled: %v %v", cfg.AuthEnabled(), err)
	}
	good := storage + "auth:\n  enabled: true\n  session_ttl: 1h\n  token_ttl: 720h\n  sso:\n    type: oidc\n"
	if _, err := Parse([]byte(validYAML + good)); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"no storage":     {"auth:\n  enabled: true\n", "auth requires storage"},
		"allow_from":     {"http:\n  allow_from: [nope]\n", "http.allow_from[0]"},
		"host bits":      {"http:\n  allow_from: [192.0.2.1/24]\n", "host bits"},
		"session short":  {storage + "auth:\n  enabled: true\n  session_ttl: 1m\n", "auth.session_ttl"},
		"token long":     {storage + "auth:\n  enabled: true\n  token_ttl: " + (400 * 24 * time.Hour).String() + "\n", "auth.token_ttl"},
		"sso no type":    {storage + "auth:\n  enabled: true\n  sso: {config: {}}\n", "auth.sso.type"},
		"sso disabled":   {storage + "auth:\n  sso: {type: oidc}\n", "auth.sso needs auth.enabled"},
		"unknown key":    {storage + "auth:\n  enabled: true\n  users: []\n", "users"},
		"password field": {storage + "auth:\n  enabled: true\n  password: x\n", "password"},
	} {
		_, err := Parse([]byte(validYAML + tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
}
