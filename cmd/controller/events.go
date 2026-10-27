package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/internal/eventlog"
	"github.com/GrandArcher/Packeteer/internal/httpapi"
	"github.com/GrandArcher/Packeteer/internal/inbound"
	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/internal/notify"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	"github.com/GrandArcher/Packeteer/internal/policy"
	"github.com/GrandArcher/Packeteer/internal/probe"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/internal/verify"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// emitter is where catalog events go. *notify.Dispatcher implements it.
type emitter interface {
	Emit(plugin.Event)
}

// newEventLog keeps recent events for the Events page: in the storage
// plugin when it keeps them, otherwise in memory since start.
func newEventLog(plugins *pluginhost.Set, log *slog.Logger, health *syshealth.Tracker) *eventlog.Log {
	var store plugin.EventStore
	if plugins != nil && plugins.Storage != nil {
		store, _ = plugins.Storage.Plugin.(plugin.EventStore)
	}
	return eventlog.New(store, log, func(err error) { health.Record(eventsKey, err) })
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
	providers      map[string]string
	peers          map[netip.Addr]bool
	waiting        map[netip.Addr]time.Time
	stuck          map[netip.Addr]bool
	overCommit     map[string]bool
	overloaded     map[string]bool
	refused        map[string]bool
	rpkiUsable     map[string]bool
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
	return &eventWatch{out: out, mode: mode, providers: map[string]string{}, peers: map[netip.Addr]bool{},
		waiting: map[netip.Addr]time.Time{}, stuck: map[netip.Addr]bool{}, overCommit: map[string]bool{},
		overloaded: map[string]bool{}, refused: map[string]bool{}, rpkiUsable: map[string]bool{}}
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
	inject := mode == "inject"
	for _, c := range changes {
		imp, kind := c.New, ""
		switch c.Action {
		case policy.ActionImprove:
			kind = plugin.EventImprovementAdded
		case policy.ActionSwitch:
			kind = plugin.EventImprovementSwitch
		case policy.ActionRetire:
			imp, kind = c.Old, plugin.EventImprovementRemoved
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
		msg := improvementMessage(inject, mode, c, imp)
		w.emit(now, kind, msg, fields)
		if o := imp.MEDOverride; o != nil && c.Action != policy.ActionRetire {
			w.emit(now, plugin.EventMEDOverridden, imp.Prefix.String()+" "+o.String(), map[string]string{
				"prefix": imp.Prefix.String(), "asn": strconv.FormatUint(uint64(o.ASN), 10), "provider": o.Chosen,
				"med": strconv.FormatUint(uint64(o.ChosenMED), 10), "preferred": o.Preferred,
				"preferred_med": strconv.FormatUint(uint64(o.PreferredMED), 10), "score_gap": strconv.FormatFloat(o.ScoreGap, 'f', 1, 64), "mode": mode,
			})
		}
	}
}

// improvementMessage words a decision change. Outside inject the router's
// path never moved, so the text says Packeteer recommends and never says
// traffic was steered (#346).
func improvementMessage(inject bool, mode string, c policy.Change, imp policy.Improvement) string {
	if inject {
		switch c.Action {
		case policy.ActionRetire:
			return fmt.Sprintf("%s returned to native routing (%s)", imp.Prefix, imp.Reason)
		case policy.ActionSwitch:
			return fmt.Sprintf("%s switched to %s", imp.Prefix, imp.Provider)
		}
		return fmt.Sprintf("%s steered to %s", imp.Prefix, imp.Provider)
	}
	tail := " (not announced, " + mode + " mode)"
	if c.Action == policy.ActionRetire {
		return fmt.Sprintf("No longer recommends moving %s from %s to %s (%s)%s", imp.Prefix, imp.Native, imp.Provider, imp.Reason, tail)
	}
	return fmt.Sprintf("Recommends moving %s from %s to %s%s", imp.Prefix, imp.Native, imp.Provider, tail)
}

// quarantines reports flap quarantines starting and ending (#228).
func (w *eventWatch) quarantines(now time.Time, changes []policy.QuarantineChange) {
	if w == nil || w.out == nil {
		return
	}
	for _, c := range changes {
		w.out.Emit(quarantineEvent(now, c))
	}
}

// providerStatus reports provider health transitions: the probe source
// failing, and measured loss reaching probe.degraded_loss_pct or
// probe.down_loss_pct (#347), judged as the Overview does (#343). A
// provider first seen down or degraded is reported; one first seen up is
// not. A provider with nothing measured yet keeps its last state.
func (w *eventWatch) providerStatus(now time.Time, st []probe.ProviderStatus, results []probe.Result, degradedAt, downAt float64) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, h := range httpapi.MeasureProviders(st, results, degradedAt, downAt) {
		if h.State == httpapi.HealthUnknown {
			continue
		}
		prev, seen := w.providers[h.Name]
		w.providers[h.Name] = h.State
		if prev == h.State || !seen && h.State == httpapi.HealthUp {
			continue
		}
		fields := map[string]string{"provider": h.Name, "source": st[i].Source.String(), "state": h.State}
		switch {
		case h.State == httpapi.HealthUp:
			w.emit(now, plugin.EventProviderUp, "Provider "+h.Name+" is healthy again", fields)
		case !st[i].Up:
			fields["reason"] = st[i].Reason
			w.emit(now, plugin.EventProviderDown, "Provider "+h.Name+" is down: its probe source failed ("+st[i].Reason+"); improvements onto it are withdrawn", fields)
		case h.State == httpapi.HealthDown:
			fields["reason"], fields["loss_pct"] = h.Detail, strconv.FormatFloat(h.LossPct, 'f', 1, 64)
			w.emit(now, plugin.EventProviderDown, "Provider "+h.Name+" is down: "+h.Detail+" on its probes", fields)
		default:
			fields["reason"], fields["loss_pct"] = h.Detail, strconv.FormatFloat(h.LossPct, 'f', 1, 64)
			w.emit(now, plugin.EventProviderDegraded, "Provider "+h.Name+" is degraded: "+h.Detail+" on its probes", fields)
		}
	}
}

// peerStatus reports iBGP sessions reaching or leaving Established, and a
// session that has not reached Established within notEstablishedAfter of
// the first time it was seen (#347). A session that comes up and later
// drops is reported by bgp.session_down, not by the timer.
func (w *eventWatch) peerStatus(now time.Time, peers []rib.PeerState, notEstablishedAfter time.Duration) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range peers {
		prev, known := w.peers[p.Address]
		w.peers[p.Address] = p.Established
		fields := map[string]string{"neighbor": p.Address.String(), "state": p.State}
		if p.Description != "" {
			fields["description"] = p.Description
		}
		name := p.Address.String()
		if p.Description != "" {
			name = p.Description + " (" + name + ")"
		}
		switch {
		case p.Established:
			delete(w.waiting, p.Address)
			delete(w.stuck, p.Address)
			if !prev {
				w.emit(now, plugin.EventBGPSessionUp, "iBGP session to "+name+" is established", fields)
			}
		case prev:
			w.emit(now, plugin.EventBGPSessionDown, "iBGP session to "+name+" is down ("+p.State+"): Packeteer can't see its routes, so it makes no recommendations for them", fields)
		default:
			if !known {
				w.waiting[p.Address] = now
			}
			since, waiting := w.waiting[p.Address]
			if !waiting || w.stuck[p.Address] || notEstablishedAfter <= 0 || now.Sub(since) < notEstablishedAfter {
				continue
			}
			w.stuck[p.Address] = true
			fields["after"] = notEstablishedAfter.String()
			w.emit(now, plugin.EventBGPSessionStuck, "iBGP session to "+name+" is still "+p.State+" after "+notEstablishedAfter.String()+": Packeteer can't see its routes, so it makes no recommendations for them", fields)
		}
	}
}

// rpki reports an RPKI source whose cache stopped answering lookups
// (stale or empty, as rpki.Set skips it) and its recovery (#200). A source
// is tracked only once it has been usable, so one still loading at boot
// raises neither event and rpki.fresh always follows an rpki.stale; the
// System page shows it down meanwhile. Its lookups are unknown while it is
// unusable, which fails open: decisions continue and no withdraw waits on it.
func (w *eventWatch) rpki(now time.Time, sources []plugin.RPKIStatus) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, st := range sources {
		usable := !st.Stale && st.VRPs > 0
		prev, known := w.rpkiUsable[st.Source]
		if !usable && !known {
			continue
		}
		w.rpkiUsable[st.Source] = usable
		fields := map[string]string{"source": st.Source, "vrps": strconv.Itoa(st.VRPs)}
		if !st.Updated.IsZero() {
			fields["updated"] = st.Updated.UTC().Format(time.RFC3339)
		}
		switch {
		case usable && known && !prev:
			w.emit(now, plugin.EventRPKIFresh, "RPKI source "+st.Source+" has fresh data again", fields)
		case !usable && prev:
			msg := "RPKI source " + st.Source + " has no fresh data: its lookups are unknown until it recovers or the next source answers"
			if st.Error != "" {
				fields["error"] = st.Error
				msg += " (" + st.Error + ")"
			}
			w.emit(now, plugin.EventRPKIStale, msg, fields)
		}
	}
}

// stopping reports shutdown after the withdraw. When no mode announces,
// nothing was announced and nothing was withdrawn, so a routine restart is
// info and says so instead of warning that routes were withdrawn (#347).
func (w *eventWatch) stopping(now time.Time, mode string, announces bool, withdrawErr error) {
	fields := map[string]string{"mode": mode, "withdrawn": "true"}
	if withdrawErr != nil {
		fields["withdrawn"] = "false"
		fields["error"] = withdrawErr.Error()
	}
	ev := plugin.NewEvent(plugin.EventControllerStopping, now, "Packeteer is shutting down; Packeteer routes withdrawn", fields)
	if !announces && withdrawErr == nil {
		ev.Severity = plugin.SeverityInfo
		ev.Message = "Packeteer is shutting down (" + mode + " mode: it announced no routes)"
	}
	if w != nil && w.out != nil {
		w.out.Emit(ev)
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
		if s.Action.MED != 0 {
			fields["med"] = strconv.FormatUint(uint64(s.Action.MED), 10)
		}
		fields["communities"] = strings.Join(s.Action.Communities, " ")
		w.emit(now, plugin.EventInboundSteered, "steering inbound traffic away from "+s.Provider+" ("+c.Reason+")"+suffix, fields)
	}
}

// verification reports the steers that were checked (#305). Verified
// resolves an earlier steer.unverified for the same target; partial and
// not moved are the routing anomaly. Unknown is only logged: no data is
// not a finding.
func (w *eventWatch) verification(now time.Time, results []verify.Result) {
	if w == nil {
		return
	}
	for _, r := range results {
		target := r.Target()
		fields := map[string]string{
			"kind": string(r.Kind), "target": target, "provider": r.Provider, "status": string(r.Status),
			"expected_mbps": strconv.FormatFloat(r.ExpectedMbps, 'f', 1, 64),
			"moved_mbps":    strconv.FormatFloat(r.MovedMbps, 'f', 1, 64),
			"moved_pct":     strconv.FormatFloat(r.MovedPct, 'f', 0, 64),
			"backed_out":    strconv.FormatBool(r.BackedOut),
			"detail":        r.Detail,
		}
		if r.Kind == verify.Outbound {
			fields["prefix"] = r.Prefix.String()
			fields["path_degraded"] = strconv.FormatBool(r.PathDegraded)
		}
		switch {
		case r.Status == verify.Verified:
			w.emit(now, plugin.EventSteerVerified, fmt.Sprintf("%s steer of %s verified: %s", r.Kind, target, r.Detail), fields)
		case r.Status.Unverified():
			w.emit(now, plugin.EventSteerUnverified, fmt.Sprintf("%s steer of %s is %s: %s", r.Kind, target, strings.ReplaceAll(string(r.Status), "_", " "), r.Detail), fields)
		}
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
