package main

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// emitter is where catalog events go. *notify.Dispatcher implements it.
type emitter interface {
	Emit(plugin.Event)
}

func newDispatcher(plugins *pluginhost.Set, opt notify.Options) *notify.Dispatcher {
	var targets []notify.Target
	if plugins != nil {
		for _, n := range plugins.Notifiers {
			targets = append(targets, notify.Target{Name: n.Name, Notifier: n.Plugin})
		}
	}
	return notify.New(targets, opt)
}

// eventWatch turns controller state into catalog events. It keeps the last
// state it saw and emits only on transitions, so a provider that stays
// down is reported once. Observe, suggest, and inject all emit; in observe
// and suggest an improvement event says the route was not announced. It
// never announces or withdraws anything.
type eventWatch struct {
	out  emitter
	mode string

	mu             sync.Mutex
	providers      map[string]bool
	peers          map[netip.Addr]bool
	overCommit     map[string]bool
	commitChecked  time.Time
	announceFailed bool
}

// commitCheckInterval spaces commit checks. A telemetry snapshot sorts the
// billing window, and RIB churn can run decisions far more often.
const commitCheckInterval = time.Minute

// commitDue reports whether a commit check should run now.
func (w *eventWatch) commitDue(now time.Time) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.commitChecked.IsZero() && now.Sub(w.commitChecked) < commitCheckInterval && !now.Before(w.commitChecked) {
		return false
	}
	w.commitChecked = now
	return true
}

func newEventWatch(out emitter, mode string) *eventWatch {
	return &eventWatch{out: out, mode: mode, providers: map[string]bool{}, peers: map[netip.Addr]bool{}, overCommit: map[string]bool{}}
}

// SetMode records the mode a reload applied. Improvement events say
// whether the route was announced.
func (w *eventWatch) SetMode(mode string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.mode = mode
	w.mu.Unlock()
}

func (w *eventWatch) currentMode() string {
	if w == nil {
		return ""
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.mode
}

func (w *eventWatch) emit(now time.Time, kind, msg string, fields map[string]string) {
	if w == nil || w.out == nil {
		return
	}
	w.out.Emit(plugin.NewEvent(kind, now, msg, fields))
}

// improvements reports decision changes.
func (w *eventWatch) improvements(now time.Time, changes []policy.Change) {
	if w == nil {
		return
	}
	mode := w.currentMode()
	suffix := ""
	if mode != "inject" {
		suffix = " (" + mode + ": not announced)"
	}
	for _, c := range changes {
		imp, kind, verb := c.New, "", ""
		switch c.Action {
		case policy.ActionImprove:
			kind, verb = plugin.EventImprovementAdded, "steered to"
		case policy.ActionSwitch:
			kind, verb = plugin.EventImprovementSwitch, "switched to"
		case policy.ActionRetire:
			imp, kind, verb = c.Old, plugin.EventImprovementRemoved, "returned from"
		default:
			continue
		}
		fields := map[string]string{
			"prefix": imp.Prefix.String(), "provider": imp.Provider, "native": imp.Native,
			"mode": mode, "reason": imp.Reason,
		}
		if imp.Cause != "" {
			fields["cause"] = imp.Cause
		}
		if c.Action == policy.ActionSwitch && c.Old.Provider != "" {
			fields["previous"] = c.Old.Provider
		}
		msg := fmt.Sprintf("%s %s %s%s", imp.Prefix, verb, imp.Provider, suffix)
		if c.Action == policy.ActionRetire {
			msg = fmt.Sprintf("%s returned to native routing (%s)%s", imp.Prefix, imp.Reason, suffix)
		}
		w.emit(now, kind, msg, fields)
	}
}

// providers reports probe-source transitions. A provider first seen down
// is reported; one first seen up is not.
func (w *eventWatch) providerStatus(now time.Time, st []probe.ProviderStatus) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range st {
		prev, seen := w.providers[p.Name]
		w.providers[p.Name] = p.Up
		if seen && prev == p.Up || !seen && p.Up {
			continue
		}
		fields := map[string]string{"provider": p.Name, "source": p.Source.String()}
		if p.Up {
			w.emit(now, plugin.EventProviderUp, "probe source for "+p.Name+" recovered", fields)
			continue
		}
		fields["reason"] = p.Reason
		w.emit(now, plugin.EventProviderDown, "probe source for "+p.Name+" is down; its improvements are withdrawn", fields)
	}
}

// peerStatus reports iBGP sessions reaching or leaving Established. A
// session that never came up is not reported as down.
func (w *eventWatch) peerStatus(now time.Time, peers []rib.PeerState) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range peers {
		prev := w.peers[p.Address]
		w.peers[p.Address] = p.Established
		if prev == p.Established {
			continue
		}
		fields := map[string]string{"neighbor": p.Address.String(), "state": p.State}
		if p.Description != "" {
			fields["description"] = p.Description
		}
		if p.Established {
			w.emit(now, plugin.EventBGPSessionUp, "iBGP session to "+p.Address.String()+" established", fields)
		} else {
			w.emit(now, plugin.EventBGPSessionDown, "iBGP session to "+p.Address.String()+" is down ("+p.State+")", fields)
		}
	}
}

// billable is the figure a provider is charged on.
func billable(u plugin.Usage) float64 {
	if u.Single {
		return u.UsageMbps
	}
	return math.Max(u.InMbps95, u.OutMbps95)
}

// commit reports providers whose billable 95th crosses the commit.
func (w *eventWatch) commit(now time.Time, usage []plugin.Usage) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, u := range usage {
		if u.Provider == "" || u.CommitMbps <= 0 || u.Samples == 0 {
			continue
		}
		v := billable(u)
		over := v > u.CommitMbps
		if over == w.overCommit[u.Provider] {
			continue
		}
		w.overCommit[u.Provider] = over
		fields := map[string]string{
			"provider":    u.Provider,
			"usage_mbps":  strconv.FormatFloat(v, 'f', 1, 64),
			"commit_mbps": strconv.FormatFloat(u.CommitMbps, 'f', 1, 64),
			"percentile":  string(u.Mode),
		}
		if over {
			w.emit(now, plugin.EventCommitExceeded, fmt.Sprintf("%s 95th percentile %.1f Mbps is above its %.1f Mbps commit", u.Provider, v, u.CommitMbps), fields)
		} else {
			w.emit(now, plugin.EventCommitCleared, fmt.Sprintf("%s 95th percentile %.1f Mbps is within its %.1f Mbps commit", u.Provider, v, u.CommitMbps), fields)
		}
	}
}

// inbound reports inbound steers and releases. In observe and suggest, and
// for moderated triggers, the message says nothing was announced.
func (w *eventWatch) inbound(now time.Time, mode string, changes []inbound.Change) {
	if w == nil {
		return
	}
	for _, c := range changes {
		s := c.Steer
		suffix := ""
		switch {
		case mode != "inject":
			suffix = " (" + mode + ": not announced)"
		case s.Moderated:
			suffix = " (moderated: not announced)"
		}
		fields := map[string]string{
			"provider": s.Provider, "mode": mode, "reason": c.Reason, "trigger": s.Trigger,
			"moderated": strconv.FormatBool(s.Moderated), "flaps": strconv.Itoa(s.Flaps),
			"in_mbps_95":  strconv.FormatFloat(s.InMbps95, 'f', 1, 64),
			"commit_mbps": strconv.FormatFloat(s.CommitMbps, 'f', 1, 64),
		}
		if c.Action == inbound.ActionSteer {
			fields["hold"] = s.Hold.String()
		}
		if c.Action == inbound.ActionRelease {
			w.emit(now, plugin.EventInboundReleased, "inbound steer away from "+s.Provider+" released ("+c.Reason+")"+suffix, fields)
			continue
		}
		if s.Action.Name != "" {
			fields["action"] = s.Action.Name
		}
		fields["prepend"] = strconv.Itoa(s.Action.Prepend)
		if s.Action.Withhold {
			fields["withhold"] = "true"
		}
		fields["communities"] = strings.Join(s.Action.Communities, " ")
		w.emit(now, plugin.EventInboundSteered, "steering inbound traffic away from "+s.Provider+" ("+c.Reason+")"+suffix, fields)
	}
}

// announce reports the first failed sync and the first success after it.
func (w *eventWatch) announce(now time.Time, err error) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	failed := err != nil
	if failed == w.announceFailed {
		return
	}
	w.announceFailed = failed
	if failed {
		w.emit(now, plugin.EventAnnounceFailed, "announcer sync failed: "+err.Error(), map[string]string{"mode": w.mode})
		return
	}
	w.emit(now, plugin.EventAnnounceRecovered, "announcer sync recovered", map[string]string{"mode": w.mode})
}

// sendTestEvent delivers one notifier.test event to each notifier directly
// and reports the result. It sends no probes and opens no BGP session. A
// notifier whose filter drops the test kind is reported, not failed.
func sendTestEvent(ctx context.Context, plugins *pluginhost.Set, stdout io.Writer) int {
	if plugins == nil || len(plugins.Notifiers) == 0 {
		fmt.Fprintln(stdout, "notify-test: no notifiers configured")
		return 1
	}
	ev := plugin.NewEvent(plugin.EventTest, time.Now(), "Packeteer notifier test", map[string]string{"version": version})
	code := 0
	for _, n := range plugins.Notifiers {
		if g, ok := n.Plugin.(plugin.Gated); ok && !g.EventGate().Match(ev) {
			fmt.Fprintf(stdout, "notify-test: %s: filtered by events/min_severity (not sent)\n", n.Name)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := n.Plugin.Notify(cctx, ev)
		cancel()
		if err != nil {
			fmt.Fprintf(stdout, "notify-test: %s: FAILED: %v\n", n.Name, err)
			code = 1
			continue
		}
		fmt.Fprintf(stdout, "notify-test: %s: sent\n", n.Name)
	}
	return code
}

// mitigation reports threat mitigation changes (#28): the feed as
// notifier events.
func (w *eventWatch) mitigation(changes []mitigation.Change) {
	if w == nil {
		return
	}
	for _, c := range changes {
		r := c.Rule
		fields := map[string]string{
			"rule": r.ID, "prefix": r.Prefix.String(), "action": r.Action, "mode": c.Mode,
			"routes": strconv.Itoa(r.Routes), "expires": r.Expires.UTC().Format(time.RFC3339),
		}
		for k, v := range map[string]string{"target": r.Target, "match": r.MatchText(), "source_countries": strings.Join(r.Countries, ","),
			"reason": r.Reason, "detail": c.Detail} {
			if v != "" {
				fields[k] = v
			}
		}
		if r.RateMbps != 0 {
			fields["rate_mbps"] = strconv.FormatFloat(r.RateMbps, 'f', -1, 64)
		}
		what := r.Action + " for " + r.Prefix.String()
		if m := r.MatchText(); m != "" {
			what += " (" + m + ")"
		}
		if len(r.Countries) > 0 {
			what += " from " + strings.Join(r.Countries, ",")
		}
		var kind, msg string
		switch c.Kind {
		case mitigation.ChangeAdded:
			kind, msg = plugin.EventMitigationAdded, "mitigation rule added: "+what
			if c.Mode != "inject" {
				msg += " (" + c.Mode + ": dry run, not announced)"
			}
		case mitigation.ChangeAnnounced:
			kind, msg = plugin.EventMitigationOn, "mitigation announced: "+what
		case mitigation.ChangeWithdrawn:
			kind, msg = plugin.EventMitigationOff, "mitigation withdrawn while the rule is held: "+what
		case mitigation.ChangeExpired, mitigation.ChangeRemoved, mitigation.ChangeReplaced:
			fields["end"] = c.Kind
			kind, msg = plugin.EventMitigationEnded, "mitigation rule "+c.Kind+": "+what
		default:
			continue
		}
		w.emit(c.Time, kind, msg, fields)
	}
}
