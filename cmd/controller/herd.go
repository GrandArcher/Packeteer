package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// herdBatch is the probe engine's OnBatch for herd (#260): nil when herd
// is off, so the engine then keeps no raw samples at all. The hand-off
// never blocks the probe loop; until herd is built, rounds are dropped.
func herdBatch(cfg *config.Config, h *atomic.Pointer[herd.Herd]) func([]probe.Result) {
	if !cfg.HerdOn() {
		return nil
	}
	return func(b []probe.Result) {
		if hd := h.Load(); hd != nil {
			hd.Offer(b)
		}
	}
}

// herdOwnPrefixes are the operator's own and customer prefixes, which
// herd never shares: the inbound prefixes, the flow source's transit
// customers and local networks, and the span source's local networks.
func herdOwnPrefixes(cfg *config.Config) []netip.Prefix {
	var raw []string
	if cfg.Inbound != nil {
		raw = append(raw, cfg.Inbound.Prefixes...)
	}
	for _, sp := range cfg.Sources {
		var c struct {
			Local   []string `yaml:"local"`
			Transit *struct {
				Customers []string `yaml:"customers"`
			} `yaml:"transit"`
			Problems *struct {
				Local []string `yaml:"local"`
			} `yaml:"problems"`
		}
		if sp.Type != "flow" && sp.Type != "span" || sp.Config.Decode(&c) != nil {
			continue
		}
		raw = append(raw, c.Local...)
		if c.Transit != nil {
			raw = append(raw, c.Transit.Customers...)
		}
		if c.Problems != nil {
			raw = append(raw, c.Problems.Local...)
		}
	}
	var out []netip.Prefix
	for _, s := range raw {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

// newHerd builds herd when it is enabled and nothing else: it opens no
// socket. A store that cannot keep herd records is an error, so a node
// never claims to share while it stores nothing. Herd never announces and
// never feeds a decision.
func newHerd(cfg *config.Config, plugins *pluginhost.Set, view herd.RIB, audit *auth.Auditor, emit func(plugin.Event), active func() bool, log *slog.Logger) (*herd.Herd, error) {
	if !cfg.HerdOn() {
		return nil, nil
	}
	var store plugin.HerdStore
	if plugins.Storage != nil {
		store, _ = plugins.Storage.Plugin.(plugin.HerdStore)
	}
	if store == nil {
		return nil, errors.New("herd.enabled needs a storage plugin that keeps herd records (type sqlite)")
	}
	methods, first := map[string]string{}, ""
	for _, p := range plugins.Probers {
		switch p.Type {
		case "icmp", "tcp", "udp":
			methods[p.Name] = p.Type
			if first == "" {
				first = p.Type
			}
		}
	}
	types := map[string]string{}
	for _, s := range plugins.Sources {
		types[s.Name] = s.Type
	}
	return herd.New(herd.Options{
		Cfg: cfg.Herd, ASN: cfg.ASN, Store: store, RIB: view,
		Rules:   herd.NewRules(cfg.Herd, herdOwnPrefixes(cfg)),
		Methods: methods, FirstMethod: first, SourceTypes: types, Log: log,
		Event: func(msg string) {
			emit(plugin.NewEvent(plugin.EventHerdRestarted, time.Now(), msg, nil))
		},
		Audit: func(a herd.Audit) {
			audit.Record(context.Background(), plugin.AuditRecord{
				Actor: a.Puller, Method: auth.MethodSystem, Remote: a.Remote,
				Action: "herd.serve", Target: a.Query, Detail: strconv.Itoa(a.Records) + " records",
			})
		},
		Active: active,
	})
}

// startHerd builds herd and opens its pull API. Herd needs the RIB view
// to know which routes were learned, so it is refused without one.
func startHerd(ctx context.Context, cfg *config.Config, plugins *pluginhost.Set, view *rib.View, audit *auth.Auditor, emit func(plugin.Event), active func() bool, log *slog.Logger) (*herd.Herd, error) {
	if !cfg.HerdOn() {
		return nil, nil
	}
	if view == nil {
		return nil, errors.New("herd.enabled needs bgp.neighbors: records are built from learned routes")
	}
	h, err := newHerd(cfg, plugins, view, audit, emit, active, log)
	if err != nil {
		return nil, err
	}
	if err := h.Start(ctx); err != nil {
		return nil, err
	}
	return h, nil
}
