package probe

import (
	"context"
	"math"
	"net/netip"
	"time"

	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// SubrangeResult is one sub-range's measurement inside a prefix (#121).
// Measurement only: the sub-range is never a route.
type SubrangeResult struct {
	Prefix netip.Prefix `json:"prefix"`
	Target netip.Addr   `json:"target"`
	Weight float64      `json:"weight"`
	Prober string       `json:"prober,omitempty"`
	Stats  Stats        `json:"stats"`
	Err    string       `json:"error,omitempty"`
	Time   time.Time    `json:"time"`
}

// OK reports whether the sub-range holds a measurement.
func (r SubrangeResult) OK() bool { return r.Err == "" }

// cleanSubranges keeps the sub-ranges the engine may measure for prefix:
// strictly more specific than prefix and inside it, a host inside the
// sub-range, a finite positive weight, no duplicate sub-range or host, at
// most plugin.MaxSubranges in source order. Fewer than two left is none:
// one sub-range is what the host candidates already measure.
func cleanSubranges(prefix netip.Prefix, in []plugin.Subrange) []plugin.Subrange {
	if len(in) < 2 || !prefix.IsValid() {
		return nil
	}
	prefix = prefix.Masked()
	out := make([]plugin.Subrange, 0, min(len(in), plugin.MaxSubranges))
	seenP := map[netip.Prefix]bool{}
	seenH := map[netip.Addr]bool{}
	for _, s := range in {
		if len(out) == plugin.MaxSubranges {
			break
		}
		p := s.Prefix.Masked()
		h := s.Host
		if !p.IsValid() || p.Bits() <= prefix.Bits() || !prefix.Contains(p.Addr()) {
			continue
		}
		if !h.IsValid() || !p.Contains(h) || seenP[p] || seenH[h] {
			continue
		}
		if math.IsNaN(s.Weight) || math.IsInf(s.Weight, 0) || s.Weight <= 0 {
			continue
		}
		seenP[p], seenH[h] = true, true
		out = append(out, plugin.Subrange{Prefix: p, Host: h, Weight: s.Weight})
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

// jobSubranges is the sub-range list for one provider: none for a pin,
// and none whose host sits on a peering LAN. Fewer than two left is none.
func jobSubranges(t plugin.Target, lans []netip.Prefix) []plugin.Subrange {
	if t.Pinned || len(t.Subranges) < 2 {
		return nil
	}
	out := make([]plugin.Subrange, 0, len(t.Subranges))
	for _, s := range t.Subranges {
		if len(lans) > 0 && exchange.ContainsAddr(lans, s.Host) {
			continue
		}
		out = append(out, s)
	}
	if len(out) < 2 {
		return nil
	}
	return out
}

// probeSubranges measures each sub-range's host for one provider and
// returns the prefix result built from them. ok is false when no
// sub-range produced a measurement; the caller then probes the prefix
// hosts as usual. A dead probe source fails closed. Every packet waits on
// the global rate limit inside probeOne, including a loss or dispersion
// retry.
func (e *Engine) probeSubranges(ctx context.Context, j job) (res Result, down, ok bool) {
	subs := make([]SubrangeResult, 0, len(j.subs))
	for _, s := range j.subs {
		one, dn := e.probeOne(ctx, j.provider, j.target.Prefix, s.Host, e.packets())
		if dn || ctx.Err() != nil {
			return one, dn, true
		}
		if one.OK() && e.retryPackets() > 0 &&
			((e.retryLoss() > 0 && one.Stats.LossPct >= e.retryLoss()) || e.inconsistent(one.Stats)) {
			again, dn := e.probeOne(ctx, j.provider, j.target.Prefix, s.Host, e.retryPackets())
			if dn || ctx.Err() != nil {
				return again, dn, true
			}
			if again.OK() {
				one = again
			}
		}
		subs = append(subs, SubrangeResult{Prefix: s.Prefix, Target: s.Host, Weight: s.Weight,
			Prober: one.Prober, Stats: one.Stats, Err: one.Err, Time: one.Time})
	}
	res, ok = combineSubranges(j.provider.Name, j.target.Prefix, subs)
	return res, false, ok
}

// combineSubranges builds the prefix result from its sub-ranges. Loss,
// RTT, and jitter are traffic-weighted means. Loss is over every
// sub-range: one whose probe errored counts as full loss, so every
// provider is scored on the same sub-ranges and one that fails where the
// traffic goes cannot look better by leaving that sub-range out. RTT and
// jitter are over those that answered. Sent and Received are sums.
// Targets are the measured sub-range hosts, and Target is the busiest of
// them. ok is false when no sub-range was measured.
func combineSubranges(provider string, prefix netip.Prefix, subs []SubrangeResult) (Result, bool) {
	res := Result{Provider: provider, Prefix: prefix, Subranges: subs}
	var lossW, rttW, loss, rtt, jit float64
	busiest := -1
	seenRTT := false
	for i, s := range subs {
		lossW += s.Weight
		if !s.OK() || s.Stats.Sent == 0 {
			loss += s.Weight * 100
			continue
		}
		res.Targets = append(res.Targets, s.Target)
		if busiest < 0 || s.Weight > subs[busiest].Weight {
			busiest = i
		}
		if s.Time.After(res.Time) {
			res.Time = s.Time
		}
		res.Stats.Sent += s.Stats.Sent
		res.Stats.Received += s.Stats.Received
		loss += s.Weight * s.Stats.LossPct
		if s.Stats.Received == 0 {
			continue
		}
		rttW += s.Weight
		rtt += s.Weight * float64(s.Stats.RTTAvg)
		jit += s.Weight * float64(s.Stats.Jitter)
		if !seenRTT || s.Stats.RTTMin < res.Stats.RTTMin {
			res.Stats.RTTMin = s.Stats.RTTMin
		}
		if s.Stats.RTTMax > res.Stats.RTTMax {
			res.Stats.RTTMax = s.Stats.RTTMax
		}
		seenRTT = true
	}
	if busiest < 0 {
		return res, false
	}
	res.Target = subs[busiest].Target
	res.Prober = subs[busiest].Prober
	res.Stats.LossPct = loss / lossW
	if rttW > 0 {
		res.Stats.RTTAvg = time.Duration(rtt / rttW)
		res.Stats.Jitter = time.Duration(jit / rttW)
	}
	return res, true
}
