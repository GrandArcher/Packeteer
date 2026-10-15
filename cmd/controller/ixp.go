package main

import (
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
