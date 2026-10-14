package main

import (
	"context"
	"net/netip"
	"sync"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// wireExchanges gives the ops API the exchange statistics (#27). The next
// hop counts walk every learned path, so they are rebuilt only when the
// RIB generation changes. It also starts the member availability history
// (#156), which stops with ctx, and the offload report (#152).
func wireExchanges(ctx context.Context, cfg *config.Config, col *httpapi.Collector, srv *httpapi.Server, view *rib.View, plugins *pluginhost.Set, decider *policy.Engine) {
	if len(cfg.Exchanges) == 0 || view == nil {
		return
	}
	var exs []exchange.Exchange
	for _, ex := range cfg.Exchanges {
		e := exchange.Exchange{Name: ex.Name, LANs: ex.ExchangeLANs()}
		for _, p := range ex.Peers {
			nh, err := netip.ParseAddr(p.NextHop)
			if err != nil {
				continue
			}
			e.Peers = append(e.Peers, exchange.Peer{Name: p.Name, ASN: p.ASN, NextHop: nh})
		}
		exs = append(exs, e)
	}
	lans := exchange.LANs(exs)
	var mu sync.Mutex
	var gen uint64
	var cached []rib.NextHopCount
	built := false
	hops := func() []rib.NextHopCount {
		g := view.Generation()
		mu.Lock()
		defer mu.Unlock()
		if !built || g != gen {
			cached, gen, built = view.NextHops(lans), g, true
		}
		return cached
	}
	col.SetExchanges(exs, hops)

	// Member counts over time (#156): in memory, read-only.
	hist := exchange.NewHistory()
	stats := func() []exchange.Stats { return exchange.Build(exs, hops(), nil, nil, nil) }
	srv.SetExchangeMembers(httpapi.ExchangeMembers{
		History: hist, Prefixes: view.MemberPrefixes, Offload: offloadReport(cfg, plugins, view, decider),
		PotentialPeers: potentialPeersReport(cfg.ASN, plugins, view, lans, stats),
	})
	go hist.Run(ctx, exchange.SampleEvery, stats)
}

// wireSuggestions gives the settings form next hops seen on iBGP or BMP
// that are not configured providers (#102). Counts walk every learned
// path, so they are rebuilt only when the RIB generation changes. The
// callback only reads. Accepting a suggestion is a draft row in the
// form; nothing here writes a provider, probes, or announces. Exchange
// LAN hops stay on /api/exchanges until the operator adds them as peers.
func wireSuggestions(cfg *config.Config, srv *httpapi.Server, view *rib.View) {
	if srv == nil {
		return
	}
	if view == nil {
		srv.SetSuggestions(func() []httpapi.Suggestion { return nil })
		return
	}
	var mu sync.Mutex
	var gen uint64
	var cached []httpapi.Suggestion
	built := false
	srv.SetSuggestions(func() []httpapi.Suggestion {
		g := view.Generation()
		mu.Lock()
		defer mu.Unlock()
		if !built || g != gen {
			cached = providerSuggestions(cfg, view)
			gen = g
			built = true
		}
		out := make([]httpapi.Suggestion, len(cached))
		copy(out, cached)
		return out
	})
}

const maxProviderSuggestions = 64

func providerSuggestions(cfg *config.Config, view *rib.View) []httpapi.Suggestion {
	if cfg == nil || view == nil {
		return nil
	}
	var configured []netip.Addr
	for _, p := range cfg.Providers {
		if a, err := netip.ParseAddr(p.NextHop); err == nil {
			configured = append(configured, a.Unmap())
		}
	}
	var lans []netip.Prefix
	for _, ex := range cfg.Exchanges {
		lans = append(lans, ex.ExchangeLANs()...)
	}
	hops := view.SuggestNextHops(configured, lans)
	if len(hops) > maxProviderSuggestions {
		hops = hops[:maxProviderSuggestions]
	}
	out := make([]httpapi.Suggestion, 0, len(hops))
	for _, h := range hops {
		out = append(out, httpapi.Suggestion{NextHop: h.NextHop.String(), ASN: h.ASN, Prefixes: h.Prefixes})
	}
	return out
}
