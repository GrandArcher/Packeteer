package main

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/announce"
	"github.com/GrandArcher/Packeteer/internal/blast"
	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/rib"
)

// blastSource is the blast-radius preview (#227). It decides the latest
// round again with Engine.WhatIf, under inject, on a copy of the live
// state, so the decision engine and the announcer are not touched.
type blastSource struct {
	live    *liveConfig
	decider *policy.Engine
	ctl     *announce.Controller
	view    *rib.View
	plugins *pluginhost.Set
	// check parses and validates a candidate like a start does.
	check func([]byte) (*config.Config, error)
	// held and reserved are the announcer's refusals: the leak watch holds
	// a prefix out, inbound steering or a mitigation rule reserves it.
	held, reserved func(netip.Prefix) bool
}

// Preview previews the running config under inject when candidate is nil,
// else the candidate under its own mode.
func (b blastSource) Preview(candidate []byte) (blast.Report, error) {
	run := b.live.snapshot()
	if run == nil {
		return blast.Report{}, errors.New("no running config")
	}
	if candidate == nil {
		inject := *run
		inject.Mode = config.ModeInject
		return b.report(&inject, nil)
	}
	next, err := b.check(candidate)
	if err != nil {
		return blast.Report{}, err
	}
	_, online := classify(run, next)
	return b.report(next, online)
}

// PreviewConfig previews a reload's config under its own mode.
func (b blastSource) PreviewConfig(next *config.Config, online []string) (blast.Report, error) {
	return b.report(next, online)
}

func (b blastSource) report(cfg *config.Config, changed []string) (blast.Report, error) {
	pc, err := policyConfig(cfg)
	if err != nil {
		return blast.Report{}, err
	}
	now := time.Now()
	what, ok := b.decider.WhatIf(pc, now)
	if !ok {
		return blast.Report{}, blast.ErrNoRound
	}
	var onWire []policy.Improvement
	for _, im := range what.Before {
		if b.ctl.Injected(im.Prefix) {
			onWire = append(onWire, im)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return blast.Build(blast.Params{
		Now: now, Cfg: pc, OnWire: onWire, What: what, Changed: changed,
		Refuse:  b.refusal,
		Volumes: collectVolumes(ctx, b.plugins),
		Usage:   collectTelemetry(ctx, b.plugins),
	}), nil
}

// refusal is why the announcer would not put a decided route on the wire.
// A route already on the wire is not checked against the RIB: the router
// prefers it, so the native path it replaced may no longer be learned.
func (b blastSource) refusal(p netip.Prefix) string {
	switch {
	case b.held != nil && b.held(p):
		return "held out by the leak watch"
	case b.reserved != nil && b.reserved(p):
		return "reserved for inbound steering or threat mitigation"
	case !b.ctl.Injected(p) && !(ribGate{b.view}).Contains(p):
		return "not in the learned RIB"
	}
	return ""
}
