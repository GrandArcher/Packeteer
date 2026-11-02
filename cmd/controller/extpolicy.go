package main

import (
	"log/slog"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/extpolicy"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// newPolicyFeed builds the external policy feed and its server (#232) when
// the block is set. The token is read from the environment and never logged.
func newPolicyFeed(cfg *config.Config, getenv func(string) string, log *slog.Logger) (*extpolicy.Feed, *extpolicy.Server, error) {
	e := cfg.ExternalPolicy
	if e == nil {
		return nil, nil, nil
	}
	feed := extpolicy.New(e.Enabled, e.TTL, time.Now)
	srv, err := extpolicy.NewServer(feed, extpolicy.ServerConfig{
		Listen: e.Listen, CertFile: e.CertFile, KeyFile: e.KeyFile, Token: getenv(e.TokenEnv),
	}, log)
	if err != nil {
		return nil, nil, err
	}
	return feed, srv, nil
}

// announcingVia names what carries the outbound routes in inject mode: the
// announcer plugin, the feed, or both.
func announcingVia(cfg *config.Config, plugins *pluginhost.Set) string {
	via := ""
	if plugins != nil && plugins.Announcer != nil {
		via = plugins.Announcer.Type
	}
	if cfg.ExternalPolicyOn() {
		if via != "" {
			via += "+"
		}
		via += "external_policy"
	}
	return via
}

// setPolicyFeed applies a reload of external_policy.enabled or ttl. Turning
// the feed off makes every consumer drop its routes at once.
func setPolicyFeed(feed *extpolicy.Feed, next *config.Config, log *slog.Logger) {
	if feed == nil || next.ExternalPolicy == nil {
		return
	}
	before := feed.Routes()
	feed.SetRuntime(next.ExternalPolicy.Enabled, next.ExternalPolicy.TTL)
	if next.ExternalPolicy.Enabled {
		log.Warn("config reload: external policy feed on", "routes", feed.Routes(), "ttl", next.ExternalPolicy.TTL)
	} else {
		log.Warn("config reload: external policy feed off; consumers withdraw every route", "routes", before)
	}
}
