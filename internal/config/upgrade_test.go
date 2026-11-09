package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func testPub() string {
	return base64.StdEncoding.EncodeToString(make(ed25519.PublicKey, ed25519.PublicKeySize))
}

func TestUpgradeDefaultsOff(t *testing.T) {
	cfg, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UpgradeEnabled() || cfg.Upgrade != nil {
		t.Fatalf("upgrade is on by default: %+v", cfg.Upgrade)
	}
}

func TestUpgradeDefaults(t *testing.T) {
	cfg, err := Parse([]byte(validYAML + "upgrade:\n  enabled: true\n  public_key: " + testPub() + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	u := cfg.Upgrade
	if !cfg.UpgradeEnabled() || u.Repo != DefaultUpgradeRepo || u.APIURL != DefaultUpgradeAPIURL || u.Dir != DefaultUpgradeDir || u.CheckInterval != 0 || u.AllowPrerelease {
		t.Fatalf("upgrade = %+v", u)
	}
}

func TestUpgradeErrors(t *testing.T) {
	for _, tc := range []struct{ block, want string }{
		{"enabled: true", "public_key is required"},
		{"enabled: true\n  public_key: not-base64!", "base64 Ed25519"},
		{"enabled: true\n  public_key: AAAA", "base64 Ed25519"},
		{"enabled: true\n  public_key: " + testPub() + "\n  repo: nope", "owner/name"},
		{"enabled: true\n  public_key: " + testPub() + "\n  api_url: http://api.example.net", "must be https"},
		{"enabled: true\n  public_key: " + testPub() + "\n  api_url: ftp://x", "must be https"},
		{"enabled: true\n  public_key: " + testPub() + "\n  dir: relative/dir", "absolute path"},
		{"enabled: true\n  public_key: " + testPub() + "\n  check_interval: 1m", "check_interval"},
		{"public_key: " + testPub() + "\n  check_interval: 24h", "needs upgrade.enabled"},
		{"enabled: true\n  public_key: " + testPub() + "\n  auto: true", "field auto not found"},
	} {
		_, err := Parse([]byte(validYAML + "upgrade:\n  " + tc.block + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.block, err, tc.want)
		}
	}
	// A loopback mirror may use http; a daily background check is fine.
	if _, err := Parse([]byte(validYAML + "upgrade:\n  enabled: true\n  public_key: " + testPub() + "\n  api_url: http://127.0.0.1:9/\n  check_interval: 24h\n")); err != nil {
		t.Fatal(err)
	}
}
