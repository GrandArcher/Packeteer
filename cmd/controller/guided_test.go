package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
)

// guidedGeoYAML is the candidate the settings GeoIP field posts to
// POST /api/config/validate (#329). The path is quoted the way the page
// quotes it. The rest of the file has to pass; only the database is under test.
func guidedGeoYAML(path string) string {
	return "mode: observe\nasn: 64512\nrouter_id: 192.0.2.10\nproviders:\n  - name: lab-a\n    source_ip: 192.0.2.1\n    next_hop: 192.0.2.2\nprobe: {interval: 30s, timeout: 200ms, packets: 1}\nbgp:\n  neighbors:\n    - address: 192.0.2.254\nsources:\n  - type: static\n    config:\n      targets: [{prefix: 198.51.100.0/24}]\npolicies:\n  - type: rules\n    config:\n      geoip_db: '" + path + "'\n      rules:\n        - name: country\n          action: ignore\n          countries: [US]\n"
}

func TestGuidedGeoIPCheck(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	getenv := func(string) string { return "" }
	missing := "/no/such/packeteer-country.mmdb"
	cfg, err := config.Parse([]byte(guidedGeoYAML(missing)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = preflight(cfg, quiet, getenv, "", true)
	if err == nil || !strings.Contains(err.Error(), "geoip_db") {
		t.Fatalf("missing database: %v", err)
	}
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := os.WriteFile(path, geoiptest.Build(map[string]string{"192.0.2.0/24": "US"}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Parse([]byte(guidedGeoYAML(path)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preflight(cfg, quiet, getenv, "", true); err != nil {
		t.Fatal(err)
	}
}
