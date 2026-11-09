package main

import (
	"net/netip"

	"github.com/GrandArcher/Packeteer/internal/atlas"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
)

// atlasAfterMoves queues one RIPE Atlas measurement (#213) for each prefix
// whose route Packeteer just put on the wire or moved to another provider.
// observe and suggest never move a route, so they queue nothing, and a
// prefix the announcer refused (not injected) is skipped. The measurement
// is evidence for the operator; nothing reads it back into a decision.
func atlasAfterMoves(a *atlas.Client, injected func(netip.Prefix) bool, changes []policy.Change, results []probe.Result) {
	if !a.Active() {
		return
	}
	for _, ch := range changes {
		if ch.Action != policy.ActionImprove && ch.Action != policy.ActionSwitch {
			continue
		}
		p := ch.New.Prefix
		if !injected(p) {
			continue
		}
		if addr, ok := moveTestAddr(results, p, ch.New.Provider); ok {
			a.AfterMove(p, addr, ch.New.Provider)
		}
	}
}

// moveTestAddr is the address Packeteer measured for the prefix, taken
// from the provider traffic moved to when it measured one.
func moveTestAddr(results []probe.Result, p netip.Prefix, provider string) (netip.Addr, bool) {
	var rows []atlas.LocalRow
	for _, r := range results {
		if r.Prefix == p {
			rows = append(rows, atlas.LocalRow{Provider: r.Provider, Target: r.Target, Answered: r.Stats.Received > 0})
		}
	}
	return atlas.TestAddr(rows, provider)
}
