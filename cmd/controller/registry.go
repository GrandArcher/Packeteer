package main

import (
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/netpfx"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/registry"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/rpki"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newRegistry builds registry hygiene (#289). It is nil when the block is
// off. The scan reads the learned RIB, the irr sources, the rpki set, and
// the registry plugins; it announces nothing.
func newRegistry(cfg *config.Config, plugins *pluginhost.Set, view *rib.View, rpkiSet *rpki.Set, log *slog.Logger) *registry.Service {
	if !cfg.RegistryOn() || plugins == nil {
		return nil
	}
	r := cfg.Registry
	deps := registry.Deps{Observe: registryObserver(cfg, view), Log: log}
	for _, s := range plugins.IRRSources {
		deps.IRR = append(deps.IRR, registry.IRRSource{Name: s.Name, Plugin: s.Plugin})
	}
	if rpkiSet.Enabled() {
		deps.RPKI = rpkiSet
	}
	for _, c := range plugins.RegistryCheckers {
		deps.Checkers = append(deps.Checkers, registry.Checker{Name: c.Name, Type: c.Type, Plugin: c.Plugin})
	}
	return registry.New(registry.Config{
		ASNs: r.ASNs, ASSet: r.ASSet, Interval: r.Interval, Headroom: r.HeadroomPercent,
		IRRSource: r.IRR.Source, PushDB: r.PushDatabase(), MntBy: r.IRR.MntBy, PushEnabled: r.PushEnabled,
	}, deps)
}

// registryObserver reads what the network announces from the selected
// routes of the learned RIB.
func registryObserver(cfg *config.Config, view *rib.View) func() registry.Observed {
	own := map[uint32]bool{}
	for _, a := range cfg.Registry.ASNs {
		own[a] = true
	}
	var customers map[string]bool
	noCone := ""
	if own[cfg.ASN] {
		customers, noCone = customerProviders(cfg)
	}
	sessions := registrySessions(cfg)
	return func() registry.Observed {
		obs := registry.Observed{Ready: view.Ready(), Announced: map[netip.Prefix]uint32{}, Origins: map[netip.Prefix]map[uint32]bool{}, Downstream: map[uint32]bool{}, NoCone: noCone, Sessions: sessions}
		if obs.Ready {
			observeRIB(view, cfg.ASN, own, customers, &obs)
		}
		return obs
	}
}

// customerProviders names the providers of type customer. The edge's own
// ASN is not on the paths it learns, so only a path through one of them
// says the AS behind it is a customer: route-server members and peers or
// transits Packeteer does not list arrive the same way.
func customerProviders(cfg *config.Config) (map[string]bool, string) {
	out := map[string]bool{}
	for _, p := range cfg.Providers {
		if p.Type == "customer" {
			out[p.Name] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Sprintf("AS%d is in registry.asns and no provider has type customer, so the routes of its customers cannot be told apart", cfg.ASN)
	}
	return out, ""
}

// observeRIB fills obs from the view: the selected routes decide Announced,
// and every learned path counts for Origins and Downstream. A route with an
// empty AS path is one the edge originates, so its origin is localASN. A
// path through one of customers (localASN is one of own) is all
// downstream.
func observeRIB(view *rib.View, localASN uint32, own map[uint32]bool, customers map[string]bool, obs *registry.Observed) {
	path := func(prefix netip.Prefix, provider string, asPath []uint32, selected bool) {
		origin := netpfx.LastAS(asPath)
		if len(asPath) == 0 {
			origin = localASN
		}
		if own[origin] {
			if selected {
				obs.Announced[prefix] = origin
			}
			if obs.Origins[prefix] == nil {
				obs.Origins[prefix] = map[uint32]bool{}
			}
			obs.Origins[prefix][origin] = true
		}
		from := len(asPath)
		if customers[provider] {
			from = 0
		}
		for i, a := range asPath {
			if own[a] {
				from = min(from, i+1)
			}
		}
		for _, d := range asPath[min(from, len(asPath)):] {
			if !own[d] {
				obs.Downstream[d] = true
			}
		}
	}
	routes, alts := view.RouteSnapshot()
	for _, r := range routes {
		path(r.Prefix, r.Provider, r.ASPath, true)
	}
	for _, a := range alts {
		path(a.Prefix, a.Provider, a.ASPath, false)
	}
}

// registrySessions describes each configured exchange attachment: this
// network's own LAN addresses (local_lan_addrs), the port speed, and the
// PeeringDB ix id from the lookup block when it names the exchange.
func registrySessions(cfg *config.Config) []plugin.RegistrySession {
	ixIDs := map[string]int{}
	if cfg.Lookup != nil && cfg.Lookup.Type == "peeringdb" {
		var l struct {
			Exchanges []struct {
				Name string `yaml:"name"`
				IXID int    `yaml:"ix_id"`
			} `yaml:"exchanges"`
		}
		if cfg.Lookup.Config.Decode(&l) == nil {
			for _, e := range l.Exchanges {
				ixIDs[e.Name] = e.IXID
			}
		}
	}
	var out []plugin.RegistrySession
	for _, ex := range cfg.Exchanges {
		s := plugin.RegistrySession{Exchange: ex.Name, IXID: ixIDs[ex.Name]}
		if ex.Port != nil {
			s.SpeedMbps = int(ex.Port.CapacityMbps)
		}
		for _, a := range ex.LocalLANAddrs {
			if a, err := netip.ParseAddr(a); err == nil {
				s.Addrs = append(s.Addrs, a)
			}
		}
		out = append(out, s)
	}
	return out
}

// wireRegistry gives the API the report and the push.
func wireRegistry(svc *registry.Service, httpSrv *httpapi.Server) {
	if svc == nil || httpSrv == nil {
		return
	}
	httpSrv.SetRegistry(svc)
}
