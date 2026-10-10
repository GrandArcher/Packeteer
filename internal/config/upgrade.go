package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// UI upgrade (#196). The block turns on the Settings page's version check,
// one-click upgrade, and rollback. It never announces: before any switch
// the controller withdraws through the same path as SIGTERM, and the new
// version starts in the configured mode and learns the RIB again before it
// injects.

// Upgrade defaults and bounds.
const (
	DefaultUpgradeRepo   = "GrandArcher/Packeteer"
	DefaultUpgradeAPIURL = "https://api.github.com"
	DefaultUpgradeDir    = "/var/lib/packeteer/upgrade"
	MinUpgradeCheckEvery = time.Hour
	MaxUpgradeCheckEvery = 30 * 24 * time.Hour
)

// Upgrade configures release checks and upgrades from the UI.
type Upgrade struct {
	// Enabled turns the feature on. Default false: the Settings page then
	// only shows the running version.
	Enabled bool `yaml:"enabled"`
	// PublicKey is the Ed25519 key (base64, 32 bytes) that signs each
	// release's SHA256SUMS. Required when enabled: a release whose
	// signature or checksum does not verify is never switched to.
	PublicKey string `yaml:"public_key"`
	// Repo is the GitHub repository whose releases are read, owner/name
	// (default GrandArcher/Packeteer).
	Repo string `yaml:"repo"`
	// APIURL is the GitHub API base (default https://api.github.com). It
	// must be https, or http on a loopback address for a local mirror.
	APIURL string `yaml:"api_url"`
	// Dir keeps staged versions and the switch state (default
	// /var/lib/packeteer/upgrade, the image's data volume).
	Dir string `yaml:"dir"`
	// CheckInterval turns on a background check that only notifies: the
	// Settings page shows the newer release. 0 (default) checks only when
	// an admin presses Check. Never upgrades by itself.
	CheckInterval time.Duration `yaml:"check_interval"`
	// AllowPrerelease lists pre-releases too (default false).
	AllowPrerelease bool `yaml:"allow_prerelease"`
}

var upgradeRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

// UpgradeEnabled reports whether the UI upgrade is on.
func (c *Config) UpgradeEnabled() bool { return c != nil && c.Upgrade != nil && c.Upgrade.Enabled }

func (c *Config) defaultUpgrade() {
	u := c.Upgrade
	if u == nil {
		return
	}
	u.PublicKey = strings.TrimSpace(u.PublicKey)
	if u.Repo == "" {
		u.Repo = DefaultUpgradeRepo
	}
	if u.APIURL == "" {
		u.APIURL = DefaultUpgradeAPIURL
	}
	u.APIURL = strings.TrimRight(u.APIURL, "/")
	if u.Dir == "" {
		u.Dir = DefaultUpgradeDir
	}
}

func (c *Config) validateUpgrade(add func(string, ...any)) {
	u := c.Upgrade
	if u == nil {
		return
	}
	if u.PublicKey != "" {
		if raw, err := base64.StdEncoding.DecodeString(u.PublicKey); err != nil || len(raw) != ed25519.PublicKeySize {
			add("upgrade.public_key must be a base64 Ed25519 public key (32 bytes)")
		}
	} else if u.Enabled {
		add("upgrade.public_key is required when upgrade.enabled is true: every release is verified against it before a switch")
	}
	if !upgradeRepo.MatchString(u.Repo) {
		add("upgrade.repo %q must be owner/name", u.Repo)
	}
	if pu, err := url.Parse(u.APIURL); err != nil || pu.Host == "" || pu.User != nil || pu.RawQuery != "" || pu.Fragment != "" {
		add("upgrade.api_url %q must be an https URL with a host", u.APIURL)
	} else if pu.Scheme != "https" && !(pu.Scheme == "http" && loopbackHost(pu.Hostname())) {
		add("upgrade.api_url %q must be https (http only for a loopback address)", u.APIURL)
	}
	if !filepath.IsAbs(u.Dir) {
		add("upgrade.dir %q must be an absolute path", u.Dir)
	}
	if u.CheckInterval != 0 && (u.CheckInterval < MinUpgradeCheckEvery || u.CheckInterval > MaxUpgradeCheckEvery) {
		add("upgrade.check_interval %s must be 0 (off) or between %s and %s", u.CheckInterval, MinUpgradeCheckEvery, MaxUpgradeCheckEvery)
	}
	if u.CheckInterval != 0 && !u.Enabled {
		add("upgrade.check_interval needs upgrade.enabled: true")
	}
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}
