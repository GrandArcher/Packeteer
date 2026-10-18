package main

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/config"
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
