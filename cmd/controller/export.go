package main

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/export"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Exporters (#207) push events, decision changes, and flow records tagged
// with the chosen provider to external pipelines. They are off unless
// `exporters` is set, they only read, and a slow sink drops its own records
// without delaying a decision or a withdraw.

// newExporter builds the export dispatcher; with no exporters it is inert.
func newExporter(plugins *pluginhost.Set, opt export.Options) *export.Dispatcher {
	var targets []export.Target
	if plugins != nil {
		for _, x := range plugins.Exporters {
			targets = append(targets, export.Target{Name: x.Name, Exporter: x.Plugin})
		}
	}
	return export.New(targets, opt)
}

// eventTee keeps every emitted event for the Events page and also hands it
// to the exporters, so the event stream is exactly what the notifiers see
// before their filters.
type eventTee struct {
	notify.Recorder
	out *export.Dispatcher
}

func (t eventTee) Record(e plugin.Event) {
	t.Recorder.Record(e)
	t.out.Event(e)
}

// exportDecisions sends one record per decision change. A retire carries the
// ID its improve had.
func exportDecisions(out *export.Dispatcher, now time.Time, mode string, changes []policy.Change) {
	if !out.Wants(plugin.StreamDecisions) {
		return
	}
	for _, c := range changes {
		imp := c.New
		if c.Action == policy.ActionRetire {
			imp = c.Old
		}
		r := plugin.DecisionRecord{
			Time: now, ID: imp.ID(), Action: c.Action, Mode: mode,
			Prefix: imp.Prefix.String(), Provider: imp.Provider, Native: imp.Native,
			Cause: imp.Cause, Reason: imp.Reason, Since: imp.Since,
		}
		if c.Action == policy.ActionSwitch {
			r.Previous, r.PreviousID = c.Old.Provider, c.Old.ID()
		}
		out.Decision(r)
	}
}

// nativeProvider reads the provider the learned RIB uses for dst. It is
// empty while the view is not ready or when no provider owns the next hop.
func nativeProvider(view *rib.View) func(netip.Addr) string {
	if view == nil {
		return nil
	}
	return func(dst netip.Addr) string {
		if !view.Ready() {
			return ""
		}
		rt, _ := view.Lookup(dst)
		return rt.Provider
	}
}

// improvementTag is what a flow toward a steered prefix is tagged with.
type improvementTag struct{ provider, id string }

// exportTags is the steered improvements by prefix, replaced after each
// decision round. The flow tap reads it without a lock.
type exportTags struct {
	m atomic.Pointer[map[netip.Prefix]improvementTag]
}

// set takes the improvements of the round. Only inject mode moves traffic;
// in observe and suggest an improvement is a recommendation, so flows keep
// their native provider and no improvement ID.
func (t *exportTags) set(mode string, imps []policy.Improvement) {
	m := make(map[netip.Prefix]improvementTag, len(imps))
	if mode == config.ModeInject {
		for _, imp := range imps {
			m[imp.Prefix] = improvementTag{imp.Provider, imp.ID()}
		}
	}
	t.m.Store(&m)
}

// flowTapper is implemented by target sources that can hand each flow
// observation for a learned prefix to a callback (the flow source).
type flowTapper interface {
	SetFlowTap(func(plugin.FlowObservation))
}

// wireFlowExport installs the flow tap when an exporter takes flows. The
// provider tag is the improvement's provider when the prefix is steered by
// an injected route and the RIB's native provider otherwise; the improvement
// ID is set only for a steered prefix.
func wireFlowExport(plugins *pluginhost.Set, out *export.Dispatcher, native func(netip.Addr) string, tags *exportTags) {
	if plugins == nil || !out.Wants(plugin.StreamFlows) {
		return
	}
	tap := func(o plugin.FlowObservation) {
		rec := plugin.FlowRecord{Time: o.At, Src: o.Src, Dst: o.Dst, Proto: o.Proto, Bytes: o.Bytes, Prefix: o.Prefix.String()}
		if m := tags.m.Load(); m != nil {
			if t, ok := (*m)[o.Prefix]; ok {
				rec.Provider, rec.ImprovementID = t.provider, t.id
			}
		}
		if rec.Provider == "" && native != nil {
			rec.Provider = native(o.Dst)
		}
		out.Flow(rec)
	}
	for _, src := range plugins.SourcesSnapshot() {
		if s, ok := src.Plugin.(flowTapper); ok {
			s.SetFlowTap(tap)
		}
	}
}

// exportStats is the /metrics read of the exporters, nil when none is set.
func exportStats(out *export.Dispatcher) func() []export.Stat {
	if len(out.Stats()) == 0 {
		return nil
	}
	return out.Stats
}
