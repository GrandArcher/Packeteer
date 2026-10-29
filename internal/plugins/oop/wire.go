package oop

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// ProbeParams is the "probe" call parameter object.
type ProbeParams struct {
	Provider  string `json:"provider"`
	Source    string `json:"source"`
	Target    string `json:"target"`
	Count     int    `json:"count"`
	TimeoutMs int64  `json:"timeout_ms"`
	// Mark and DSCP are set only for a provider that shares its source
	// (#157); the plugin must tag its packets or fail the probe.
	Mark uint32 `json:"mark,omitempty"`
	DSCP uint8  `json:"dscp,omitempty"`
}

// NewProbeParams maps a probe request to its wire form.
func NewProbeParams(req plugin.ProbeRequest) ProbeParams {
	return ProbeParams{Provider: req.Provider, Source: req.Source.String(), Target: req.Target.String(),
		Count: req.Count, TimeoutMs: req.Timeout.Milliseconds(), Mark: req.Mark, DSCP: req.DSCP}
}

// Request parses the wire form back into a probe request.
func (p ProbeParams) Request() (plugin.ProbeRequest, error) {
	src, err := netip.ParseAddr(p.Source)
	if err != nil {
		return plugin.ProbeRequest{}, fmt.Errorf("probe: bad source %q", p.Source)
	}
	dst, err := netip.ParseAddr(p.Target)
	if err != nil {
		return plugin.ProbeRequest{}, fmt.Errorf("probe: bad target %q", p.Target)
	}
	return plugin.ProbeRequest{Provider: p.Provider, Source: src, Target: dst, Count: p.Count,
		Timeout: time.Duration(p.TimeoutMs) * time.Millisecond, Mark: p.Mark, DSCP: p.DSCP}, nil
}

// ProbeResult is the "probe" call result object.
type ProbeResult struct {
	Sent   int       `json:"sent"`
	RTTsMs []float64 `json:"rtts_ms"`
}

// NewProbeResult maps a probe result to its wire form.
func NewProbeResult(r plugin.ProbeResult) ProbeResult {
	out := ProbeResult{Sent: r.Sent, RTTsMs: make([]float64, 0, len(r.RTTs))}
	for _, rtt := range r.RTTs {
		out.RTTsMs = append(out.RTTsMs, float64(rtt)/float64(time.Millisecond))
	}
	return out
}

// Result checks the wire form and maps it to a probe result.
func (r ProbeResult) Result() (plugin.ProbeResult, error) {
	if r.Sent < 0 || len(r.RTTsMs) > r.Sent {
		return plugin.ProbeResult{}, fmt.Errorf("probe: inconsistent result: sent=%d replies=%d", r.Sent, len(r.RTTsMs))
	}
	out := plugin.ProbeResult{Sent: r.Sent}
	for _, ms := range r.RTTsMs {
		if ms < 0 {
			return plugin.ProbeResult{}, fmt.Errorf("probe: negative rtt %v", ms)
		}
		out.RTTs = append(out.RTTs, time.Duration(ms*float64(time.Millisecond)))
	}
	return out, nil
}

// TargetsResult is the "targets" call result object.
type TargetsResult struct {
	Targets []TargetEntry `json:"targets"`
}

// TargetEntry is one target of a TargetsResult.
type TargetEntry struct {
	Prefix string  `json:"prefix"`
	Host   string  `json:"host,omitempty"`
	Weight float64 `json:"weight,omitempty"`
}

// NewTargetsResult maps targets to their wire form.
func NewTargetsResult(ts []plugin.Target) TargetsResult {
	out := TargetsResult{Targets: make([]TargetEntry, 0, len(ts))}
	for _, t := range ts {
		e := TargetEntry{Prefix: t.Prefix.String(), Weight: t.Weight}
		if t.Host.IsValid() {
			e.Host = t.Host.String()
		}
		out.Targets = append(out.Targets, e)
	}
	return out
}

// Parse checks the wire form and maps it to targets. A host must lie
// inside its prefix.
func (r TargetsResult) Parse() ([]plugin.Target, error) {
	out := make([]plugin.Target, 0, len(r.Targets))
	for i, t := range r.Targets {
		p, err := netip.ParsePrefix(t.Prefix)
		if err != nil {
			return nil, fmt.Errorf("targets[%d]: bad prefix %q", i, t.Prefix)
		}
		tg := plugin.Target{Prefix: p.Masked(), Weight: t.Weight}
		if t.Host != "" {
			h, err := netip.ParseAddr(t.Host)
			if err != nil || !p.Contains(h) {
				return nil, fmt.Errorf("targets[%d]: host %q is not an address inside %s", i, t.Host, p)
			}
			tg.Host = h
		}
		out = append(out, tg)
	}
	return out, nil
}
