package main

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/netip"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/auth"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/herd"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/plugins/source/herdhints"
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

// herdHints reads the hints of the running herd (#672): none before herd
// is built or when it is off. It never blocks the probe engine, which
// calls it through the herd_hints source.
func herdHints(h *atomic.Pointer[herd.Herd]) func() []herdhints.Hint {
	return func() []herdhints.Hint {
		hd := h.Load()
		if hd == nil {
			return nil
		}
		hs := hd.Hints()
		out := make([]herdhints.Hint, len(hs))
		for i, x := range hs {
			out[i] = herdhints.Hint{Prefix: x.Prefix, Vantages: x.Vantages}
		}
		return out
	}
}

// herdOpinion reads the outage opinions of the running herd (#686): none
// before herd is built. It never blocks.
func herdOpinion(h *atomic.Pointer[herd.Herd]) func(uint32) (herd.Opinion, bool) {
	return func(asn uint32) (herd.Opinion, bool) {
		if hd := h.Load(); hd != nil {
			return hd.Opinion(asn)
		}
		return herd.Opinion{}, false
	}
}

// herdOutageNote annotates an outage.as or outage.circuit event with what
// the other herd members see of the same ASN (#686): herd_asn,
// herd_reporting, and herd_degraded from herd's last refresh. A circuit
// incident's ASN is its provider's asn. Without one, or before herd's first
// refresh, the event goes out as it is. It runs after the outage source
// decided and only adds fields, so it never opens, closes, or changes an
// incident. Nil when herd is off.
func herdOutageNote(cfg *config.Config, opinion func(asn uint32) (herd.Opinion, bool)) func(plugin.Event) plugin.Event {
	if !cfg.HerdOn() {
		return nil
	}
	providerASN := map[string]uint32{}
	for _, p := range cfg.Providers {
		if a := cmp.Or(p.ASN, p.PeerASN); a != 0 {
			providerASN[p.Name] = a
		}
	}
	return func(ev plugin.Event) plugin.Event {
		var asn uint32
		switch ev.Kind {
		case plugin.EventOutageAS:
			if n, err := strconv.ParseUint(ev.Fields["asn"], 10, 32); err == nil {
				asn = uint32(n)
			}
		case plugin.EventOutageCircuit:
			asn = providerASN[ev.Fields["provider"]]
		}
		if asn == 0 {
			return ev
		}
		op, ok := opinion(asn)
		if !ok {
			return ev
		}
		fields := maps.Clone(ev.Fields)
		if fields == nil {
			fields = map[string]string{}
		}
		fields["herd_asn"] = strconv.FormatUint(uint64(asn), 10)
		fields["herd_reporting"] = strconv.Itoa(op.Reporting)
		fields["herd_degraded"] = strconv.Itoa(op.Degraded)
		ev.Fields = fields
		return ev
	}
}

// wireHerdHints gives every herd_hints source the hint reader.
func wireHerdHints(plugins *pluginhost.Set, hints func() []herdhints.Hint) {
	if plugins == nil {
		return
	}
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(*herdhints.Source); ok {
			s.SetHints(hints)
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
