package main

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/portload"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/verify"
)

// steerVerifier ties the verify tracker (#305) to the two controllers whose
// steers it checks. It reads telemetry and probe results and, only for a
// steer that moved no traffic in a direction named by verify.backout,
// retires it through the controller that made it. It announces nothing.
type steerVerifier struct {
	tr      *verify.Tracker
	decider *policy.Engine
	inb     *inbound.Controller
	plugins *pluginhost.Set
	log     *slog.Logger
	// awaiting holds the providers of inbound steers that are decided but
	// not on the wire: the RIB was not ready or the announce failed, and
	// Sync retries each round, as it does after a RIB flap. Their window
	// starts when a route steering away from them goes out.
	awaiting map[string]struct{}
}

// newSteerVerifier returns nil when verify is off.
func newSteerVerifier(cfg *config.Config, decider *policy.Engine, inb *inbound.Controller, plugins *pluginhost.Set, log *slog.Logger) *steerVerifier {
	if !cfg.Verify.Enabled {
		return nil
	}
	v := &steerVerifier{decider: decider, inb: inb, plugins: plugins, log: log.With("component", "verify"), awaiting: map[string]struct{}{}}
	v.tr = verify.New(cfg.Verify, v.degraded)
	return v
}

// degraded is the decision engine's own rule read backwards: the path
// before beats the path after by the performance thresholds.
func (v *steerVerifier) degraded(before, after verify.Path) bool {
	th := v.decider.Thresholds()
	b, a := pathCandidate(before), pathCandidate(after)
	return th.LossWins(b, a) || th.RTTWins(b, a)
}

func pathCandidate(p verify.Path) policy.Candidate {
	return policy.Candidate{LossPct: p.LossPct, RTTAvg: time.Duration(p.RTTMs * float64(time.Millisecond))}
}

// rates is each provider's latest interface rate from rows that are fresh.
func (v *steerVerifier) rates(ctx context.Context, now time.Time) map[string]verify.Rate {
	out := map[string]verify.Rate{}
	for _, u := range collectTelemetry(ctx, v.plugins) {
		if u.Provider == "" || u.Error != "" || u.Samples <= 0 || u.Updated.IsZero() || !portload.Fresh(u.Updated, now, portload.DefaultMaxAge) {
			continue
		}
		out[u.Provider] = verify.Rate{InMbps: u.InMbps, OutMbps: u.OutMbps, Updated: u.Updated}
	}
	return out
}

func resultPath(results []probe.Result, p netip.Prefix, provider string) (verify.Path, bool) {
	for _, r := range results {
		if r.Prefix == p && r.Provider == provider && r.OK() && r.Stats.Sent > 0 {
			return verify.Path{LossPct: r.Stats.LossPct, RTTMs: float64(r.Stats.RTTAvg) / float64(time.Millisecond)}, true
		}
	}
	return verify.Path{}, false
}

// onWire reports whether a steer is still announced: an outbound route the
// announcer holds, or an inbound steer that is injected and not moderated
// whose route on the wire steers away from that provider.
func (v *steerVerifier) onWire(injected func(netip.Prefix) bool, kind verify.Kind, key string) bool {
	if kind == verify.Outbound {
		p, err := netip.ParsePrefix(key)
		return err == nil && injected(p)
	}
	st := v.inb.Status()
	return st.Mode == config.ModeInject && steeredAway(st, key) &&
		slices.ContainsFunc(st.Announced, func(r inbound.Route) bool { return slices.Contains(r.Away, key) })
}

// steeredAway reports an unmoderated steer away from provider.
func steeredAway(st inbound.Status, provider string) bool {
	return slices.ContainsFunc(st.Steers, func(s inbound.Steer) bool { return s.Provider == provider && !s.Moderated })
}

// check judges the steers whose window has passed and backs out the ones
// that moved nothing where the config says to. It runs before the round's
// decision, so the withdraw goes out in the same round. The changes are
// the retire and release it made, for events and history. A steer that is
// no longer on the wire is dropped, not judged.
func (v *steerVerifier) check(ctx context.Context, now time.Time, injected func(netip.Prefix) bool, results []probe.Result) (done []verify.Result, pol []policy.Change, in []inbound.Change) {
	if v == nil {
		return nil, nil, nil
	}
	v.tr.Keep(func(kind verify.Kind, key string) bool {
		if v.onWire(injected, kind, key) {
			return true
		}
		// A steer the controller still holds is announced again when the
		// RIB is back, with no new change: verify it from then.
		if kind == verify.Inbound && steeredAway(v.inb.Status(), key) {
			v.awaiting[key] = struct{}{}
		}
		return false
	})
	done = v.tr.Observe(now, verify.Observation{
		Rates: v.rates(ctx, now),
		Path:  func(p netip.Prefix, provider string) (verify.Path, bool) { return resultPath(results, p, provider) },
	})
	for _, r := range done {
		v.log.Info("steer verification", "kind", r.Kind, "target", r.Target(), "provider", r.Provider, "status", r.Status,
			"expected_mbps", r.ExpectedMbps, "moved_mbps", r.MovedMbps, "path_degraded", r.PathDegraded, "backed_out", r.BackedOut, "detail", r.Detail)
		if !r.BackedOut {
			continue
		}
		reason := "verification: " + r.Detail
		switch r.Kind {
		case verify.Outbound:
			if ch, ok := v.decider.Backout(r.Prefix, now.Add(r.Backoff), reason); ok {
				pol = append(pol, ch)
				v.log.Info("steer backed out", "kind", r.Kind, "target", r.Target(), "backoff", r.Backoff)
			}
		case verify.Inbound:
			if ch, ok := v.inb.Revert(now, r.Provider, reason, r.Backoff); ok {
				in = append(in, ch)
				v.log.Info("steer backed out", "kind", r.Kind, "target", r.Target(), "backoff", r.Backoff)
			}
		}
	}
	return done, pol, in
}

// begin starts verifying the steers this round put on the wire and drops
// the ones it ended. A prefix the announcer refused (not injected), and an
// inbound steer that is moderated or not injected, announced nothing and
// is not verified. An inbound steer whose route is not out yet is verified
// from the round it goes out.
func (v *steerVerifier) begin(ctx context.Context, now time.Time, injected func(netip.Prefix) bool, inboundMode string, changes []policy.Change, inChanges []inbound.Change, results []probe.Result) {
	if v == nil {
		return
	}
	rates := v.rates(ctx, now)
	var volumes map[netip.Prefix]float64
	for _, ch := range changes {
		switch ch.Action {
		case policy.ActionRetire:
			v.tr.Cancel(verify.Outbound, ch.Old.Prefix.String())
		case policy.ActionImprove, policy.ActionSwitch:
			p := ch.New.Prefix
			if !injected(p) {
				v.tr.Cancel(verify.Outbound, p.String())
				continue
			}
			from := ch.New.Native
			if ch.Action == policy.ActionSwitch {
				from = ch.Old.Provider
			}
			// The improvement carries a volume only under a scorer that
			// plans by it; the flow or static volume is read otherwise.
			expected := ch.New.VolumeMbps
			if expected == 0 {
				if volumes == nil {
					volumes = collectVolumes(ctx, v.plugins)
				}
				expected = volumes[p]
			}
			c := verify.Claim{Kind: verify.Outbound, Prefix: p, Provider: ch.New.Provider, From: from, Expected: expected, Rates: rates}
			if path, ok := resultPath(results, p, ch.New.Provider); ok {
				c.Path = &path
			}
			v.tr.Begin(now, c)
		}
	}
	for _, ch := range inChanges {
		switch {
		case ch.Action == inbound.ActionRelease:
			delete(v.awaiting, ch.Steer.Provider)
			v.tr.Cancel(verify.Inbound, ch.Steer.Provider)
		case ch.Action == inbound.ActionSteer && inboundMode == config.ModeInject && !ch.Steer.Moderated:
			v.awaiting[ch.Steer.Provider] = struct{}{}
		}
	}
	for provider := range v.awaiting {
		if v.onWire(injected, verify.Inbound, provider) {
			delete(v.awaiting, provider)
			v.tr.Begin(now, verify.Claim{Kind: verify.Inbound, Provider: provider, Rates: rates})
		}
	}
}

// reset forgets open verifications when this instance steps down (#31).
func (v *steerVerifier) reset() {
	if v != nil {
		v.tr.Reset()
		clear(v.awaiting)
	}
}

// results is the read-only view for GET /api/verification.
func (v *steerVerifier) results() []verify.Result {
	if v == nil {
		return nil
	}
	return v.tr.List()
}
