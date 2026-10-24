package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/irr"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
)

// Keys under which results are kept for the System page (#184). History
// and the event log write to the same storage plugin under separate keys,
// so a failed history write is not overwritten by a later event write.
const (
	historyKey = "storage/history"
	eventsKey  = "storage/events"
)

func notifierKey(name string) string { return "notifier/" + name }

// storageOutcome is the storage row's result: a failed write of either
// writer wins over a successful one, and between two of the same kind the
// later one is shown.
func storageOutcome(health *syshealth.Tracker) *syshealth.Outcome {
	var out *syshealth.Outcome
	for _, key := range []string{historyKey, eventsKey} {
		o, ok := health.Get(key)
		if !ok {
			continue
		}
		if out == nil || (!o.OK && out.OK) || (o.OK == out.OK && o.At.After(out.At)) {
			out = &o
		}
	}
	return out
}

// systemFacts reads the configured plugins and their latest results for
// GET /api/system. The engine is created after the HTTP server, so it is
// read through an atomic pointer. Only state is read: the Snapshot of a
// telemetry plugin is the call the dashboard already makes.
func systemFacts(plugins *pluginhost.Set, engine *atomic.Pointer[probe.Engine], health *syshealth.Tracker, registry *irr.Checker) func() httpapi.SystemFacts {
	return func() httpapi.SystemFacts {
		var f httpapi.SystemFacts
		if plugins == nil {
			return f
		}
		for _, p := range plugins.Probers {
			f.Probers = append(f.Probers, httpapi.PluginFact{Name: p.Name, Type: p.Type})
		}
		eng := engine.Load()
		for _, s := range plugins.SourcesSnapshot() {
			fact := httpapi.SourceFact{PluginFact: httpapi.PluginFact{Name: s.Name, Type: s.Type}}
			if eng != nil {
				if st, ok := eng.SourceStatus(s.Name); ok {
					fact.Seen, fact.Targets, fact.Err, fact.Since = true, st.Targets, st.Err, st.Since
				}
			}
			f.Sources = append(f.Sources, fact)
		}
		if plugins.Scorer != nil {
			f.Scorer = &httpapi.PluginFact{Name: plugins.Scorer.Name, Type: plugins.Scorer.Type}
		}
		if plugins.Announcer != nil {
			f.Announcer = &httpapi.PluginFact{Name: plugins.Announcer.Name, Type: plugins.Announcer.Type}
		}
		if plugins.Storage != nil {
			fact := httpapi.StorageFact{PluginFact: httpapi.PluginFact{Name: plugins.Storage.Name, Type: plugins.Storage.Type}}
			fact.Last = storageOutcome(health)
			f.Storage = &fact
		}
		for _, n := range plugins.Notifiers {
			fact := httpapi.NotifierFact{PluginFact: httpapi.PluginFact{Name: n.Name, Type: n.Type}}
			if o, ok := health.Get(notifierKey(n.Name)); ok {
				fact.Last = &o
			}
			f.Notifiers = append(f.Notifiers, fact)
		}
		for _, r := range plugins.RIBSources {
			f.RIBSources = append(f.RIBSources, httpapi.RIBSourceFact{
				PluginFact: httpapi.PluginFact{Name: r.Name, Type: r.Type},
				Routers:    health.Under(ribRouterPrefix(r.Name)),
			})
		}
		for _, r := range plugins.RPKISources {
			st := r.Plugin.Status()
			f.RPKI = append(f.RPKI, httpapi.RPKIFact{
				PluginFact: httpapi.PluginFact{Name: r.Name, Type: r.Type},
				Up:         st.Up, Stale: st.Stale, VRPs: st.VRPs, Updated: st.Updated, Err: st.Error,
			})
		}
		for _, st := range registry.Statuses() {
			f.IRR = append(f.IRR, httpapi.IRRFact{
				PluginFact: httpapi.PluginFact{Name: st.Source, Type: st.Type},
				Up:         st.Up, Updated: st.Updated, Err: st.Error,
			})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, t := range plugins.Telemetry {
			fact := httpapi.TelemetryFact{PluginFact: httpapi.PluginFact{Name: t.Name, Type: t.Type}}
			rows, err := t.Plugin.Snapshot(ctx)
			if err != nil {
				fact.Err = err.Error()
			}
			fact.Bindings = len(rows)
			for _, u := range rows {
				if u.Polled.After(fact.Polled) {
					fact.Polled = u.Polled
				}
				if fact.Err == "" && u.Error != "" {
					fact.Err = u.Provider + ": " + u.Error
				}
			}
			f.Telemetry = append(f.Telemetry, fact)
		}
		return f
	}
}
