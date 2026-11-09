package main

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/threatfeed"
)

// newThreatFeeds returns nil when threat feeds (#134) are not configured.
// It checks each rule's action against the mitigation announcer's catalog
// so a rule that could never be added is refused at startup.
func newThreatFeeds(cfg *config.Config, plugins *pluginhost.Set, mit *mitigation.Controller, poke func(), log *slog.Logger) (*threatfeed.Controller, error) {
	t := cfg.ThreatFeeds
	if t == nil {
		return nil, nil
	}
	if mit == nil {
		return nil, errors.New("threat_feeds act only through threat mitigation, which is not configured")
	}
	var feeds []threatfeed.Feed
	for _, f := range plugins.ThreatFeeds {
		feeds = append(feeds, threatfeed.Feed{Name: f.Name, Type: f.Type, Plugin: f.Plugin})
	}
	var rules []threatfeed.Rule
	for i, r := range t.Rules {
		if err := checkRuleAction(r.Action, r.Target, mit); err != nil {
			return nil, fmt.Errorf("threat_feeds.rules[%d] (%s): %w", i, r.Name, err)
		}
		rules = append(rules, threatfeed.Rule{Name: r.Name, Feed: r.Feed, Match: r.Match, Prefixes: r.RulePrefixes(),
			Action: r.Action, Target: r.Target, RateMbps: r.RateMbps, TTL: r.TTL})
	}
	return threatfeed.New(threatfeed.Config{
		Interval:          t.Interval,
		MaxActive:         t.MaxActive,
		MaxActionsPerHour: t.MaxActionsPerHour,
		Feeds:             feeds,
		Rules:             rules,
		Leader:            haLeader(plugins),
		Poke:              poke,
	}, mit, log.With("component", "threat_feeds"))
}

// setThreatFeedRIB gives the feeds the RIB view once it exists.
func setThreatFeedRIB(tf *threatfeed.Controller, view *rib.View) {
	if tf == nil || view == nil {
		return
	}
	tf.SetRIB(ribGate{view})
}
