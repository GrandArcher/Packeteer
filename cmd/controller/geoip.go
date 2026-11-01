package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/geoip"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/plugins/policy/rules"
)

// geoipStartTimeout bounds the download made before the plugins are built.
const geoipStartTimeout = 3 * time.Minute

// startGeoIP builds the database download when geoip.url is set and makes
// the first fetch, so country rules find the file when the plugins read it.
// A failed fetch is logged and the start goes on: a rule that needs the
// file then refuses the start itself, with the file path in the error.
func startGeoIP(ctx context.Context, cfg *config.Config, getenv func(string) string, log *slog.Logger) (*geoip.Fetcher, error) {
	if !cfg.GeoIPUpdateOn() {
		return nil, nil
	}
	f, err := geoip.NewFetcher(cfg.GeoIP, getenv(geoip.UserEnv), getenv(geoip.KeyEnv), log)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithTimeout(ctx, geoipStartTimeout)
	defer cancel()
	if err := f.Start(sctx); err != nil {
		log.Warn("geoip: the first download failed", "path", cfg.GeoIP.Path, "error", err)
	}
	return f, nil
}

// geoipSetup is the checklist's view of the country databases: the files
// that country rules read, and the state of the download. Nil when neither
// exists.
func geoipSetup(cfg *config.Config, f *geoip.Fetcher) func() httpapi.GeoIPState {
	var files []string
	for _, p := range cfg.Policies {
		if p.Type != rules.TypeName {
			continue
		}
		var rc rules.Config
		if p.Config.Decode(&rc) != nil || rc.GeoIPDB == "" {
			continue
		}
		for _, r := range rc.Rules {
			if len(r.Countries) > 0 {
				files = append(files, rc.GeoIPDB)
				break
			}
		}
	}
	if m := cfg.Mitigation; m != nil && m.GeoIPDB != "" {
		files = append(files, m.GeoIPDB)
	}
	if len(files) == 0 && f == nil {
		return nil
	}
	return func() httpapi.GeoIPState {
		var st httpapi.GeoIPState
		for _, p := range files {
			if fh, err := os.Open(p); err != nil {
				st.Unreadable = append(st.Unreadable, p)
			} else {
				fh.Close()
			}
		}
		if f != nil {
			st.UpdateError = f.Status().LastError
		}
		return st
	}
}
