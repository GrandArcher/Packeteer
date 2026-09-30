package httpapi

import (
	"sort"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/mitigation"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// Canonical BGP FSM states from the GoBGP session enum. A state outside
// this list is emitted as well so a future name is still visible.
var bgpFSM = []string{"UNKNOWN", "IDLE", "CONNECT", "ACTIVE", "OPENSENT", "OPENCONFIRM", "ESTABLISHED"}

// Decision actions the policy engine records. Unknown actions are added
// when a snapshot contains one.
var decisionActions = []string{"none", "improve", "keep", "switch", "retire", "capped"}

// HAMetrics renders the active/standby role (#31).
func HAMetrics(st plugin.ElectorStatus) []byte {
	var b strings.Builder
	writeGauge(&b, "packeteer_ha_active", "1 while this instance is the active one of its HA pair and may announce.",
		sample{labels: []lbl{{"id", st.ID}}, value: boolFloat(st.Role == plugin.RoleActive)})
	writeGauge(&b, "packeteer_ha_eligible", "1 while this instance may lead (its RIB view is ready).",
		sample{labels: []lbl{{"id", st.ID}}, value: boolFloat(st.Eligible)})
	writeGauge(&b, "packeteer_ha_takeovers", "Times this instance became active since it started.",
		sample{labels: []lbl{{"id", st.ID}}, value: float64(st.Takeovers)})
	return []byte(b.String())
}

// Metrics renders s in Prometheus text exposition format.
func Metrics(s Snapshot) []byte {
	var b strings.Builder
	b.Grow(2048)

	writeGauge(&b, "packeteer_up", "1 while the HTTP server is serving.",
		sample{value: 1})
	writeGauge(&b, "packeteer_ready", "1 after startup when the RIB is ready if BGP is configured.",
		sample{value: boolFloat(s.Ready())})
	writeGauge(&b, "packeteer_build_info", "Process version and operating mode. The value is always 1.",
		sample{labels: []lbl{{"version", s.Version}, {"mode", s.Mode}}, value: 1})

	var prov []sample
	for _, p := range s.Providers {
		prov = append(prov, sample{
			labels: []lbl{{"provider", p.Name}, {"exclude", boolText(p.Exclude)}},
			value:  boolFloat(p.Up),
		})
	}
	writeGauge(&b, "packeteer_provider_up", "1 if the provider probe source is up.", prov...)

	var rtt, rttMin, rttMax, loss, jitter, success []sample
	for _, p := range s.Probes {
		base := []lbl{{"provider", p.Provider}, {"prefix", p.Prefix}}
		success = append(success, sample{labels: base, value: boolFloat(p.OK)})
		if !p.OK {
			continue
		}
		rtt = append(rtt, sample{labels: base, value: p.RTTAvgMs / 1000})
		rttMin = append(rttMin, sample{labels: base, value: p.RTTMinMs / 1000})
		rttMax = append(rttMax, sample{labels: base, value: p.RTTMaxMs / 1000})
		loss = append(loss, sample{labels: base, value: clamp01(p.LossPct / 100)})
		jitter = append(jitter, sample{labels: base, value: p.JitterMs / 1000})
	}
	writeGauge(&b, "packeteer_probe_success", "1 if the latest probe returned a measurement.", success...)
	writeGauge(&b, "packeteer_probe_rtt_seconds", "Average round-trip time of the latest successful probe.", rtt...)
	writeGauge(&b, "packeteer_probe_rtt_min_seconds", "Minimum RTT of the latest successful probe.", rttMin...)
	writeGauge(&b, "packeteer_probe_rtt_max_seconds", "Maximum RTT of the latest successful probe.", rttMax...)
	writeGauge(&b, "packeteer_probe_loss_ratio", "Packet loss ratio of the latest successful probe, from 0 to 1.", loss...)
	writeGauge(&b, "packeteer_probe_jitter_seconds", "Mean absolute inter-packet RTT difference of the latest successful probe.", jitter...)

	counts := map[string]float64{}
	actions := append([]string(nil), decisionActions...)
	for _, d := range s.Decisions {
		counts[d.Action]++
		if !contains(actions, d.Action) && d.Action != "" {
			actions = append(actions, d.Action)
		}
	}
	var byAction []sample
	for _, a := range actions {
		byAction = append(byAction, sample{labels: []lbl{{"action", a}}, value: counts[a]})
	}
	writeGauge(&b, "packeteer_decisions", "Prefixes in the latest decision, by action.", byAction...)

	var perPrefix []sample
	for _, d := range s.Decisions {
		perPrefix = append(perPrefix, sample{
			labels: []lbl{
				{"prefix", d.Prefix},
				{"action", d.Action},
				{"native", d.Native},
				{"current", d.Current},
				{"recommended", d.Recommended},
			},
			value: 1,
		})
	}
	writeGauge(&b, "packeteer_decision", "Latest decision for one prefix. The value is always 1.", perPrefix...)

	writeGauge(&b, "packeteer_improvements_active", "Number of active improvements.",
		sample{value: float64(len(s.Improvements))})
	var imps []sample
	savings := 0.0
	for _, im := range s.Improvements {
		imps = append(imps, sample{
			labels: []lbl{{"prefix", im.Prefix}, {"provider", im.Provider}, {"native", im.Native}, {"cause", im.Cause}},
			value:  1,
		})
		savings += im.EstSavings
	}
	writeGauge(&b, "packeteer_improvement", "Active improvement. cause is performance, commit, or cost. The value is always 1.", imps...)
	writeGauge(&b, "packeteer_estimated_savings", "Sum of est_savings over active improvements: native cost per Mbps minus steered cost per Mbps, times prefix volume. Negative is extra spend.",
		sample{value: savings})

	bgpReady := 1.0
	if s.BGPConfigured && !s.RIBReady {
		bgpReady = 0
	}
	writeGauge(&b, "packeteer_bgp_configured", "1 if bgp.neighbors is set.",
		sample{value: boolFloat(s.BGPConfigured)})
	writeGauge(&b, "packeteer_bgp_ready", "1 if BGP is not configured or at least one iBGP session is established.",
		sample{value: bgpReady})

	var telUp, telIn, telOut, telIn95, telOut95, telUsage, telCommit, telSamples []sample
	for _, u := range s.Telemetry {
		base := []lbl{{"provider", u.Provider}, {"interface", u.Interface}, {"percentile", u.Percentile}}
		up := u.Error == "" && u.Polled != nil
		telUp = append(telUp, sample{labels: base, value: boolFloat(up)})
		telIn = append(telIn, sample{labels: base, value: u.InMbps * 1e6})
		telOut = append(telOut, sample{labels: base, value: u.OutMbps * 1e6})
		telIn95 = append(telIn95, sample{labels: base, value: u.InMbps95 * 1e6})
		telOut95 = append(telOut95, sample{labels: base, value: u.OutMbps95 * 1e6})
		if u.UsageMbps != nil {
			telUsage = append(telUsage, sample{labels: base, value: *u.UsageMbps * 1e6})
		}
		telCommit = append(telCommit, sample{labels: base, value: u.CommitMbps * 1e6})
		telSamples = append(telSamples, sample{labels: base, value: float64(u.Samples)})
	}
	writeGauge(&b, "packeteer_telemetry_up", "1 if the last SNMP poll of this provider succeeded.", telUp...)
	writeGauge(&b, "packeteer_telemetry_in_bps", "Latest inbound interface rate, bits per second.", telIn...)
	writeGauge(&b, "packeteer_telemetry_out_bps", "Latest outbound interface rate, bits per second.", telOut...)
	writeGauge(&b, "packeteer_telemetry_in_95th_bps", "95th percentile inbound rate for the open billing period, bits per second.", telIn95...)
	writeGauge(&b, "packeteer_telemetry_out_95th_bps", "95th percentile outbound rate for the open billing period, bits per second.", telOut95...)
	writeGauge(&b, "packeteer_telemetry_usage_bps", "Billable 95th percentile for modes that collapse to one figure, bits per second.", telUsage...)
	writeGauge(&b, "packeteer_telemetry_commit_bps", "Configured commit rate, bits per second.", telCommit...)
	writeGauge(&b, "packeteer_telemetry_samples", "Rate samples stored in the open billing period.", telSamples...)
	if s.BGPConfigured {
		var sessionUp, sessionState []sample
		for _, p := range s.Peers {
			sessionUp = append(sessionUp, sample{labels: []lbl{{"peer", p.Address}}, value: boolFloat(p.Established)})
			cur := strings.ToUpper(strings.TrimSpace(p.State))
			if cur == "" {
				cur = "UNKNOWN"
			}
			states := append([]string(nil), bgpFSM...)
			if !contains(states, cur) {
				states = append(states, cur)
			}
			for _, st := range states {
				v := 0.0
				if st == cur {
					v = 1
				}
				sessionState = append(sessionState, sample{labels: []lbl{{"peer", p.Address}, {"state", st}}, value: v})
			}
		}
		writeGauge(&b, "packeteer_bgp_session_up", "1 if the iBGP session is established.", sessionUp...)
		writeGauge(&b, "packeteer_bgp_session", "1 if the iBGP session is currently in this FSM state.", sessionState...)
	}

	var ixPrefixes, ixImps, ixDiscovered []sample
	for _, ex := range s.Exchanges {
		for _, p := range ex.Peers {
			l := []lbl{{"exchange", ex.Name}, {"peer", p.Name}}
			ixPrefixes = append(ixPrefixes, sample{labels: l, value: float64(p.Prefixes)})
			ixImps = append(ixImps, sample{labels: l, value: float64(p.Improvements)})
		}
		ixDiscovered = append(ixDiscovered, sample{labels: []lbl{{"exchange", ex.Name}}, value: float64(len(ex.Discovered))})
	}
	writeGauge(&b, "packeteer_exchange_peer_prefixes", "Prefixes the router shows through the exchange peer's next hop.", ixPrefixes...)
	writeGauge(&b, "packeteer_exchange_peer_improvements", "Active improvements onto the exchange peer.", ixImps...)
	writeGauge(&b, "packeteer_exchange_discovered_peers", "Next hops on the peering LAN that are not configured peers.", ixDiscovered...)

	return []byte(b.String())
}

// MitigationMetrics renders threat mitigation (#28) gauges: rules by
// action and state, routes held and announced, and the cap.
func MitigationMetrics(st mitigation.Status) []byte {
	var b strings.Builder
	type key struct{ action, state string }
	counts := map[key]float64{}
	for _, a := range []string{plugin.MitigationBlackhole, plugin.MitigationRedirect, plugin.MitigationFlowSpecDrop,
		plugin.MitigationFlowSpecRateLimit, plugin.MitigationFlowSpecRedirect} {
		counts[key{a, "announced"}] = 0
		counts[key{a, "pending"}] = 0
	}
	for _, r := range st.Rules {
		state := "pending"
		if r.Announced {
			state = "announced"
		}
		counts[key{r.Action, state}]++
	}
	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].action != keys[j].action {
			return keys[i].action < keys[j].action
		}
		return keys[i].state < keys[j].state
	})
	var rules []sample
	for _, k := range keys {
		rules = append(rules, sample{labels: []lbl{{"action", k.action}, {"state", k.state}}, value: counts[k]})
	}
	writeGauge(&b, "packeteer_mitigation_rules", "Threat mitigation rules held, by action and state (announced, or pending: waiting, or a dry run in observe).", rules...)
	writeGauge(&b, "packeteer_mitigation_routes_held", "Routes the held mitigation rules stand for (a FlowSpec country rule counts once per source network).",
		sample{value: float64(st.Routes)})
	writeGauge(&b, "packeteer_mitigation_routes_announced", "Mitigation routes on the wire (RTBH, redirect, and FlowSpec).",
		sample{value: float64(st.OnWire)})
	writeGauge(&b, "packeteer_mitigation_max_rules", "The mitigation.max_rules cap, in routes.",
		sample{labels: []lbl{{"mode", st.Mode}}, value: float64(st.MaxRules)})
	return []byte(b.String())
}

type lbl struct{ k, v string }

type sample struct {
	labels []lbl
	value  float64
}

func writeGauge(b *strings.Builder, name, help string, samples ...sample) {
	if len(samples) == 0 {
		return
	}
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" gauge\n")
	for _, s := range samples {
		b.WriteString(name)
		if len(s.labels) > 0 {
			b.WriteByte('{')
			for i, l := range s.labels {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(l.k)
				b.WriteString(`="`)
				b.WriteString(promEscape(l.v))
				b.WriteByte('"')
			}
			b.WriteByte('}')
		}
		b.WriteByte(' ')
		b.WriteString(strconv.FormatFloat(s.value, 'g', -1, 64))
		b.WriteByte('\n')
	}
}

func promEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func boolFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
