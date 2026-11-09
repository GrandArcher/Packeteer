package main

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/federation"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// wireIXPMembers connects the IX-F import (#161) before plugins start.
// The sink is set first so the expiry check in Start can emit. The HTTP
// callback reads the plugin view; it does not fetch and it does not announce.
func wireIXPMembers(plugins *pluginhost.Set, httpSrv *httpapi.Server, emit func(plugin.Event)) {
	if plugins == nil || plugins.IXPMembers == nil {
		return
	}
	src := plugins.IXPMembers.Plugin
	if emit != nil {
		src.SetEventSink(emit)
	}
	if httpSrv != nil {
		httpSrv.SetIXPMembers(src.View)
	}
}

// wireIXPFabric connects the fabric prober (#162) before plugins start.
// It reads the member view and the configured vantages. It does not fetch
// and it does not announce.
func wireIXPFabric(cfg *config.Config, plugins *pluginhost.Set, httpSrv *httpapi.Server) {
	if plugins == nil || plugins.IXPFabric == nil || cfg == nil || cfg.IXP == nil {
		return
	}
	p := plugins.IXPFabric.Plugin
	if plugins.IXPMembers != nil {
		p.SetMembers(plugins.IXPMembers.Plugin.View)
	}
	p.SetVantages(fabricVantages(cfg.IXP.Vantages))
	if httpSrv != nil {
		httpSrv.SetIXPFabric(p.View)
	}
}

// wireIXPRouteServers connects the Birdseye watch (#164) before plugins
// start. It reads the member view for ASNs, names, and max_prefix. It
// polls with GET only and does not announce.
func wireIXPRouteServers(plugins *pluginhost.Set, httpSrv *httpapi.Server, emit func(plugin.Event)) {
	if plugins == nil || plugins.IXPRouteServers == nil {
		return
	}
	w := plugins.IXPRouteServers.Plugin
	if plugins.IXPMembers != nil {
		w.SetMembers(plugins.IXPMembers.Plugin.View)
	}
	if emit != nil {
		w.SetEventSink(emit)
	}
	if httpSrv != nil {
		httpSrv.SetIXPRouteServers(w.View, w.History)
	}
}

// wireIXPCorrelate connects the fabric incident correlator (#163) before
// plugins start. It reads the fabric prober's view. It does not probe and
// it does not announce.
func wireIXPCorrelate(plugins *pluginhost.Set, httpSrv *httpapi.Server, emit func(plugin.Event)) {
	if plugins == nil || plugins.IXPCorrelate == nil || plugins.IXPFabric == nil {
		return
	}
	c := plugins.IXPCorrelate.Plugin
	c.SetFabric(plugins.IXPFabric.Plugin.View)
	if emit != nil {
		c.SetEventSink(emit)
	}
	if httpSrv != nil {
		httpSrv.SetIXPCorrelation(c.View)
	}
}

// wireIXPSites connects the core prober and the multi-site view (#167)
// before plugins start. The snapshot published to the federation peers
// carries this site's fabric health; the view reads the peers' last
// snapshots. Both read views only and announce nothing.
func wireIXPSites(cfg *config.Config, plugins *pluginhost.Set, fed *fedState, httpSrv *httpapi.Server) {
	if cfg == nil || cfg.IXP == nil || fed == nil {
		return
	}
	if plugins.IXPCore != nil {
		plugins.IXPCore.Plugin.SetLinks(coreLinks(cfg.IXP.CoreLinks))
	}
	fed.setIXP(func() *plugin.FederatedIXP {
		var in federation.IXPInput
		if plugins.IXPFabric != nil {
			in.Fabric = plugins.IXPFabric.Plugin.View()
		}
		if plugins.IXPCorrelate != nil {
			in.Correlation = plugins.IXPCorrelate.Plugin.View()
		}
		if plugins.IXPRouteServers != nil {
			in.RouteServer = plugins.IXPRouteServers.Plugin.View()
		}
		if plugins.IXPCore != nil {
			in.Core = plugins.IXPCore.Plugin.View()
		}
		return federation.IXPSnapshot(in)
	})
	if httpSrv != nil {
		httpSrv.SetIXPSites(fed.ixpSites)
	}
}

func coreLinks(in []config.CoreLink) []plugin.CoreLink {
	out := make([]plugin.CoreLink, 0, len(in))
	for _, l := range in {
		addr, err := netip.ParseAddr(l.Address)
		if err != nil {
			continue
		}
		src, _ := netip.ParseAddr(l.Source)
		out = append(out, plugin.CoreLink{Name: l.Name, Peer: l.Peer, Source: src, Address: addr, MaxLossPct: l.MaxLossPct, MaxRTT: l.MaxRTT})
	}
	return out
}

func fabricVantages(in []config.Vantage) []plugin.FabricVantage {
	out := make([]plugin.FabricVantage, 0, len(in))
	for _, v := range in {
		addr, err := netip.ParseAddr(v.Address)
		if err != nil {
			continue
		}
		out = append(out, plugin.FabricVantage{Name: v.Name, IXPID: v.IXPID, VLANID: v.VLANID, Address: addr})
	}
	return out
}
