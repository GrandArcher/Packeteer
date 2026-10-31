package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip"
	"github.com/GrandArcher/Packeteer/internal/geoip/geoiptest"
)

func labCountryDB() []byte {
	return geoiptest.Build(map[string]string{"203.0.113.0/24": "XA"})
}

func rulesSpec(t *testing.T, db, rules string) config.PluginSpec {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(fmt.Sprintf("geoip_db: %s\nrules: %s\n", db, rules)), &n); err != nil {
		t.Fatal(err)
	}
	return config.PluginSpec{Type: "rules", Config: *n.Content[0]}
}

// #135: the downloaded file is the one a country rule reads. The lab server
// needs the account from the environment; the first download happens before
// the plugins are built.
func TestStartGeoIPFeedsCountryRules(t *testing.T) {
	var gotUser, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotKey, _ = r.BasicAuth()
		w.Write(labCountryDB())
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "country.mmdb")
	cfg := &config.Config{GeoIP: config.GeoIP{Path: path, URL: srv.URL, Refresh: config.MinGeoIPRefresh}}
	env := map[string]string{geoip.UserEnv: "100001", geoip.KeyEnv: "fake-key-not-real"}
	f, err := startGeoIP(context.Background(), cfg, func(k string) string { return env[k] }, discardLog())
	if err != nil || f == nil {
		t.Fatalf("startGeoIP = %v, %v", f, err)
	}
	if gotUser != "100001" || gotKey != "fake-key-not-real" {
		t.Fatalf("account sent = %q %q", gotUser, gotKey)
	}
	// rules.New opens the file, so the policy builds only because the
	// download landed first.
	policySet(t, [2]string{"rules", fmt.Sprintf("geoip_db: %s\nrules: [{name: xa, action: deny, providers: [transit-a], countries: [XA]}]", path)})
	if st := f.Status(); st.LastError != "" || st.LastCheck.IsZero() {
		t.Fatalf("status = %+v", st)
	}
}

func TestStartGeoIPOffAndRefusals(t *testing.T) {
	get := func(string) string { return "" }
	if f, err := startGeoIP(context.Background(), &config.Config{}, get, discardLog()); f != nil || err != nil {
		t.Fatalf("no url: %v %v", f, err)
	}
	cfg := &config.Config{GeoIP: config.GeoIP{Path: "/tmp/c.mmdb", URL: "https://geoip.example.net/c", Refresh: config.MinGeoIPRefresh}}
	_, err := startGeoIP(context.Background(), cfg, func(k string) string {
		if k == geoip.KeyEnv {
			return "fake-key-not-real"
		}
		return ""
	}, discardLog())
	if err == nil || !strings.Contains(err.Error(), geoip.UserEnv) {
		t.Fatalf("key without user: %v", err)
	}
}

// A failed first download does not stop the start and shows on the
// checklist; the file is untouched.
func TestStartGeoIPFailureShowsOnChecklist(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "country.mmdb")
	cfg := &config.Config{GeoIP: config.GeoIP{Path: path, URL: srv.URL, Refresh: config.MinGeoIPRefresh}}
	f, err := startGeoIP(context.Background(), cfg, func(string) string { return "" }, discardLog())
	if err != nil || f == nil {
		t.Fatalf("startGeoIP = %v, %v", f, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a file was written")
	}
	st := geoipSetup(cfg, f)()
	if !strings.Contains(st.UpdateError, "401") {
		t.Fatalf("state = %+v", st)
	}
}

func TestGeoIPSetup(t *testing.T) {
	dir := t.TempDir()
	have := filepath.Join(dir, "have.mmdb")
	if err := os.WriteFile(have, labCountryDB(), 0o644); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(dir, "gone.mmdb")

	if geoipSetup(&config.Config{}, nil) != nil {
		t.Fatal("a config without country rules or a download has a GeoIP check")
	}
	noCountries := &config.Config{Policies: []config.PluginSpec{rulesSpec(t, gone, `[{name: a, action: deny, prefixes: [203.0.113.0/24]}]`)}}
	if geoipSetup(noCountries, nil) != nil {
		t.Fatal("a policy without countries has a GeoIP check")
	}

	cfg := &config.Config{
		Policies: []config.PluginSpec{
			rulesSpec(t, have, `[{name: a, action: deny, countries: [XA]}]`),
			rulesSpec(t, gone, `[{name: b, action: deny, countries: [XA]}]`),
		},
		Mitigation: &config.Mitigation{GeoIPDB: gone + ".mit"},
	}
	st := geoipSetup(cfg, nil)()
	if len(st.Unreadable) != 2 || st.Unreadable[0] != gone || st.Unreadable[1] != gone+".mit" || st.UpdateError != "" {
		t.Fatalf("state = %+v", st)
	}
	if err := os.WriteFile(gone, labCountryDB(), 0o644); err != nil {
		t.Fatal(err)
	}
	if st := geoipSetup(cfg, nil)(); len(st.Unreadable) != 1 || st.Unreadable[0] != gone+".mit" {
		t.Fatalf("after mounting the file: %+v", st)
	}
}
