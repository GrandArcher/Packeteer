package main

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/anomaly"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// newAnomaly returns nil when anomaly detection (#33) is not configured.
// It picks the flow source, and checks each rule's action against the
// mitigation announcer's catalog so a rule that could never be added is
// refused at startup rather than on the first attack.
func newAnomaly(cfg *config.Config, plugins *pluginhost.Set, mit *mitigation.Controller, poke func(), log *slog.Logger) (*anomaly.Controller, error) {
	a := cfg.Anomaly
	if a == nil {
		return nil, nil
	}
	if plugins.Detector == nil {
		return nil, errors.New("anomaly: detector is required")
	}
	src, name, err := anomalySource(a, plugins)
	if err != nil {
		return nil, err
	}
	var rules []anomaly.Rule
	for i, r := range a.Rules {
		if err := checkAnomalyAction(r, mit); err != nil {
			return nil, fmt.Errorf("anomaly.rules[%d] (%s): %w", i, r.Name, err)
		}
		rules = append(rules, anomaly.Rule{Name: r.Name, Prefixes: r.RulePrefixes(), Protocols: r.Protocols, MinMbps: r.MinMbps,
			Action: r.Action, Target: r.Target, RateMbps: r.RateMbps, TTL: r.TTL})
	}
	var m anomaly.Mitigator
	if mit != nil {
		m = mit
	}
	return anomaly.New(anomaly.Config{
		Interval:          a.Interval,
		MaxActionsPerHour: a.MaxActionsPerHour,
		MaxActive:         a.MaxActive,
		Rules:             rules,
		Detector:          plugins.Detector.Type,
		Source:            name,
		Leader:            haLeader(plugins),
		Poke:              poke,
	}, src, plugins.Detector.Plugin, m, log.With("component", "anomaly"))
}

// anomalySource is the named source, or the only one that supplies flow
// counters.
func anomalySource(a *config.Anomaly, plugins *pluginhost.Set) (plugin.FlowCounterSource, string, error) {
	var found []string
	var src plugin.FlowCounterSource
	for _, s := range plugins.Sources {
		fc, ok := s.Plugin.(plugin.FlowCounterSource)
		if a.Source != "" {
			if s.Name != a.Source {
				continue
			}
			if !ok {
				return nil, "", fmt.Errorf("anomaly.source %q (type %s) does not supply flow counters (use a flow source)", s.Name, s.Type)
			}
			return fc, s.Name, nil
		}
		if ok {
			found = append(found, s.Name)
			src = fc
		}
	}
	switch {
	case a.Source != "":
		return nil, "", fmt.Errorf("anomaly.source %q is not a configured source", a.Source)
	case len(found) == 0:
		return nil, "", errors.New("anomaly needs a flow source (sources: - type: flow) for its traffic baselines")
	case len(found) > 1:
		return nil, "", fmt.Errorf("anomaly: several flow sources (%v); set anomaly.source", found)
	}
	return src, found[0], nil
}

// checkAnomalyAction refuses a rule the mitigation announcer cannot carry.
// Without an announcer (observe) every rule is a dry run and the targets
// cannot be checked.
func checkAnomalyAction(r config.AnomalyRule, mit *mitigation.Controller) error {
	if mit == nil {
		return errors.New("anomaly rules need mitigation")
	}
	cat, fs := mit.Catalog(), mit.FlowSpecCatalog()
	if len(cat.BlackholeNextHops) == 0 && len(cat.Targets) == 0 && !fs.Enabled {
		return nil // no announcer
	}
	switch r.Action {
	case plugin.MitigationBlackhole:
		if !cat.Blackhole {
			return errors.New("blackhole is not configured on the mitigation announcer")
		}
	case plugin.MitigationRedirect:
		if _, ok := cat.Target(r.Target); !ok {
			return fmt.Errorf("unknown redirect target %q", r.Target)
		}
	case plugin.MitigationFlowSpecRedirect:
		if _, ok := fs.Target(r.Target); !ok {
			return fmt.Errorf("unknown flowspec redirect target %q", r.Target)
		}
	}
	if plugin.IsFlowSpec(r.Action) && !fs.Enabled {
		return errors.New("flowspec is not configured on the mitigation announcer")
	}
	return nil
}

// setAnomalyRIB gives the detector the RIB view once it exists.
func setAnomalyRIB(an *anomaly.Controller, view *rib.View) {
	if an == nil || view == nil {
		return
	}
	an.SetRIB(ribGate{view})
}

// anomalyRecorder is where anomaly history goes (*history.Recorder).
type anomalyRecorder interface {
	Anomaly(plugin.AnomalyRecord)
}

// recordAnomalies writes each change's anomaly state to history.
func recordAnomalies(rec anomalyRecorder, changes []anomaly.Change) {
	for _, c := range changes {
		rec.Anomaly(anomaly.Record(c))
	}
}

// anomaly reports anomaly changes (#33) as notifier events.
func (w *eventWatch) anomaly(changes []anomaly.Change) {
	if w == nil {
		return
	}
	for _, c := range changes {
		a := c.Anomaly
		proto := a.Protocol.String()
		if a.Protocol == 0 {
			proto = "any"
		}
		fields := map[string]string{
			"anomaly": a.ID, "prefix": a.Prefix.String(), "protocol": proto,
			"mbps":          strconv.FormatFloat(a.Mbps, 'f', 2, 64),
			"peak_mbps":     strconv.FormatFloat(a.PeakMbps, 'f', 2, 64),
			"baseline_mbps": strconv.FormatFloat(a.BaselineMbps, 'f', 2, 64),
			"since":         a.Since.UTC().Format(time.RFC3339),
		}
		for k, v := range map[string]string{"rule": a.Rule, "mitigation": a.Mitigation, "action": a.Action, "reason": a.Reason, "detail": c.Detail} {
			if v != "" {
				fields[k] = v
			}
		}
		what := a.Prefix.String() + " " + proto
		var kind, msg string
		switch c.Kind {
		case anomaly.ChangeDetected:
			kind, msg = plugin.EventAnomalyDetected, "traffic anomaly on "+what+": "+a.Reason
		case anomaly.ChangeMitigated:
			kind, msg = plugin.EventAnomalyMitigated, "traffic anomaly on "+what+" mitigated: "+c.Detail
		case anomaly.ChangeHeld, anomaly.ChangeEnded:
			kind, msg = plugin.EventAnomalyHeld, "traffic anomaly on "+what+": "+c.Detail
		case anomaly.ChangeCleared:
			kind, msg = plugin.EventAnomalyCleared, "traffic anomaly on "+what+" cleared: "+c.Detail
		default:
			continue
		}
		w.emit(c.Time, kind, msg, fields)
	}
}
