package config

import (
	"strings"
	"testing"
	"time"
)

func TestGeoIPParsesWithDefaultRefresh(t *testing.T) {
	cfg, err := Parse([]byte(minimalYAML + "geoip:\n  path: /var/lib/packeteer/country.mmdb\n  url: https://geoip.example.net/country.mmdb.gz\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.GeoIPUpdateOn() || cfg.GeoIP.Refresh != 7*24*time.Hour || cfg.GeoIP.Path != "/var/lib/packeteer/country.mmdb" {
		t.Fatalf("geoip = %+v", cfg.GeoIP)
	}
	off, err := Parse([]byte(minimalYAML))
	if err != nil || off.GeoIPUpdateOn() {
		t.Fatalf("absent block: on=%v err=%v", off.GeoIPUpdateOn(), err)
	}
	local, err := Parse([]byte(minimalYAML + "geoip:\n  path: /tmp/c.mmdb\n  url: http://127.0.0.1:9/c.mmdb\n  refresh: 24h\n"))
	if err != nil || !local.GeoIPUpdateOn() {
		t.Fatalf("loopback http: %v", err)
	}
}

func TestGeoIPRejects(t *testing.T) {
	for name, tc := range map[string]struct{ block, want string }{
		"plain http":      {"path: /tmp/c.mmdb\n  url: http://geoip.example.net/c.mmdb", "must be https"},
		"credentials":     {"path: /tmp/c.mmdb\n  url: https://u:p@geoip.example.net/c.mmdb", "without credentials"},
		"no host":         {"path: /tmp/c.mmdb\n  url: https:///c.mmdb", "with a host"},
		"relative path":   {"path: c.mmdb\n  url: https://geoip.example.net/c.mmdb", "absolute path"},
		"no path":         {"url: https://geoip.example.net/c.mmdb", "absolute path"},
		"refresh too low": {"path: /tmp/c.mmdb\n  url: https://geoip.example.net/c.mmdb\n  refresh: 1h", "geoip.refresh"},
		"refresh too big": {"path: /tmp/c.mmdb\n  url: https://geoip.example.net/c.mmdb\n  refresh: 2160h", "geoip.refresh"},
		"path only":       {"path: /tmp/c.mmdb", "geoip.url is required"},
		"unknown key":     {"path: /tmp/c.mmdb\n  url: https://geoip.example.net/c.mmdb\n  key: x", "field key not found"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(minimalYAML + "geoip:\n  " + tc.block + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
