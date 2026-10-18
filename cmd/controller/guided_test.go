package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
)

// pageGeoYAML returns the candidate the settings GeoIP field posts to
// POST /api/config/validate (#329), read from settings.js so a change to the
// page string is what this test runs. Only the database may fail preflight;
// any other error would hide the geoip_db line the page shows.
func pageGeoYAML(t *testing.T, path string) string {
	t.Helper()
	js, err := os.ReadFile("../../internal/httpapi/web/settings.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var yml = ("(?:[^"\\]|\\.)*") \+ yamlQuote\(v\) \+ ("(?:[^"\\]|\\.)*");`).FindSubmatch(js)
	if m == nil {
		t.Fatal("bindGeo candidate YAML not found in settings.js")
	}
	head, err := strconv.Unquote(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	tail, err := strconv.Unquote(string(m[2]))
	if err != nil {
		t.Fatal(err)
	}
	return head + "'" + strings.ReplaceAll(path, "'", "''") + "'" + tail
}

func TestGuidedGeoIPCheck(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	getenv := func(string) string { return "" }
	missing := "/no/such/packeteer-country.mmdb"
	cfg, err := config.Parse([]byte(pageGeoYAML(t, missing)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = preflight(cfg, quiet, getenv, "", true)
	if err == nil || !strings.Contains(err.Error(), "geoip_db") {
		t.Fatalf("missing database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "it's country.mmdb")
	if err := os.WriteFile(path, geoiptest.Build(map[string]string{"192.0.2.0/24": "US"}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Parse([]byte(pageGeoYAML(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preflight(cfg, quiet, getenv, "", true); err != nil {
		t.Fatal(err)
	}
}
