package main

import (
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
)

// wireLookup connects the PeeringDB / IX-F directory (#153). The HTTP
// callback reads the cached view; it does not fetch and it does not announce.
func wireLookup(plugins *pluginhost.Set, httpSrv *httpapi.Server) {
	if plugins == nil || plugins.Lookup == nil || httpSrv == nil {
		return
	}
	httpSrv.SetLookup(plugins.Lookup.Plugin.View)
}
