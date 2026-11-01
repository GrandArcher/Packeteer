package config

import (
	"net/url"
	"path/filepath"
	"time"
)

// GeoIP update (#135). With url set, a country database is downloaded to
// path on start (when the file is missing or older than refresh) and again
// every refresh. It feeds the geoip_db files of country rules and never
// announces.

// GeoIP update defaults and bounds.
const (
	DefaultGeoIPRefresh = 7 * 24 * time.Hour
	MinGeoIPRefresh     = 24 * time.Hour
	MaxGeoIPRefresh     = 30 * 24 * time.Hour
)

// GeoIP configures the optional country database download.
type GeoIP struct {
	// Path is where the database is written: an absolute path on a
	// writable volume. Point geoip_db at the same file.
	Path string `yaml:"path"`
	// URL is the download address, https (http only on a loopback
	// address). Empty turns the download off.
	URL string `yaml:"url"`
	// Refresh is how often the file is fetched again (default 168h).
	Refresh time.Duration `yaml:"refresh"`
}

// GeoIPUpdateOn reports whether the database download is configured.
func (c *Config) GeoIPUpdateOn() bool { return c != nil && c.GeoIP.URL != "" }

func (c *Config) defaultGeoIP() {
	if c.GeoIP.URL != "" && c.GeoIP.Refresh == 0 {
		c.GeoIP.Refresh = DefaultGeoIPRefresh
	}
}

func (c *Config) validateGeoIP(add func(string, ...any)) {
	g := c.GeoIP
	if g.URL == "" {
		if g.Path != "" || g.Refresh != 0 {
			add("geoip.url is required when geoip.path or geoip.refresh is set")
		}
		return
	}
	if pu, err := url.Parse(g.URL); err != nil || pu.Host == "" || pu.User != nil || pu.Fragment != "" {
		add("geoip.url %q must be an https URL with a host, without credentials (the account comes from the environment)", g.URL)
	} else if !SecureURL(pu) {
		add("geoip.url %q must be https (http only for a loopback address)", g.URL)
	}
	if !filepath.IsAbs(g.Path) {
		add("geoip.path %q must be an absolute path on a writable volume", g.Path)
	}
	if g.Refresh < MinGeoIPRefresh || g.Refresh > MaxGeoIPRefresh {
		add("geoip.refresh %s must be between %s and %s", g.Refresh, MinGeoIPRefresh, MaxGeoIPRefresh)
	}
}
