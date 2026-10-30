package all

import (
	"slices"
	"testing"

	"github.com/GrandArcher/Packeteer/internal/plugins/oop"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// The out-of-process types exist for prober, source, and notifier only.
// Every other registry (announcers above all, but also detectors,
// electors, federation, and the RIB and leak sources) stays in-process.
func TestProgramTypesAreOnlyProbersSourcesNotifiers(t *testing.T) {
	allowed := map[string]bool{"probers": true, "sources": true, "notifiers": true}
	registries := map[string][]string{
		"probers":               plugin.Probers.Types(),
		"sources":               plugin.Sources.Types(),
		"notifiers":             plugin.Notifiers.Types(),
		"scorers":               plugin.Scorers.Types(),
		"announcers":            plugin.Announcers.Types(),
		"inbound announcers":    plugin.InboundAnnouncers.Types(),
		"mitigation announcers": plugin.MitigationAnnouncers.Types(),
		"telemetry":             plugin.Telemetries.Types(),
		"policies":              plugin.Policies.Types(),
		"storage":               plugin.Storages.Types(),
		"whois":                 plugin.Whoises.Types(),
		"exporters":             plugin.Exporters.Types(),
		"detectors":             plugin.Detectors.Types(),
		"electors":              plugin.Electors.Types(),
		"federations":           plugin.Federations.Types(),
		"rib sources":           plugin.RIBSources.Types(),
		"leak sources":          plugin.LeakSources.Types(),
		"sso":                   plugin.SSOs.Types(),
		"irr":                   plugin.IRRs.Types(),
		"rpki":                  plugin.RPKIs.Types(),
		"lookup":                plugin.Lookups.Types(),
		"inventory":             plugin.Inventories.Types(),
		"registry":              plugin.RegistryCheckers.Types(),
		"ixp members":           plugin.MemberSources.Types(),
		"ixp fabric":            plugin.FabricProbes.Types(),
		"ixp route servers":     plugin.RouteServerWatches.Types(),
		"ixp correlators":       plugin.FabricCorrelators.Types(),
		"ixp core":              plugin.CoreProbes.Types(),
	}
	for name, types := range registries {
		for _, typ := range []string{oop.ExecType, oop.GRPCType} {
			has := slices.Contains(types, typ)
			if want := allowed[name]; has != want {
				t.Errorf("%s: type %s registered = %v, want %v", name, typ, has, want)
			}
		}
	}
}
