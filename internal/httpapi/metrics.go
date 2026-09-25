package httpapi

import (
	"strconv"
	"strings"
)

// Canonical BGP FSM states from the GoBGP session enum. A state outside
// this list is emitted as well so a future name is still visible.
var bgpFSM = []string{"UNKNOWN", "IDLE", "CONNECT", "ACTIVE", "OPENSENT", "OPENCONFIRM", "ESTABLISHED"}

// Decision actions the policy engine records. Unknown actions are added
// when a snapshot contains one.
var decisionActions = []string{"none", "improve", "keep", "switch", "retire", "capped"}

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
	for _, im := range s.Improvements {
		imps = append(imps, sample{
			labels: []lbl{{"prefix", im.Prefix}, {"provider", im.Provider}, {"native", im.Native}},
			value:  1,
		})
	}
	writeGauge(&b, "packeteer_improvement", "Active improvement. The value is always 1.", imps...)

	bgpReady := 1.0
	if s.BGPConfigured && !s.RIBReady {
		bgpReady = 0
	}
	writeGauge(&b, "packeteer_bgp_configured", "1 if bgp.neighbors is set.",
		sample{value: boolFloat(s.BGPConfigured)})
	writeGauge(&b, "packeteer_bgp_ready", "1 if BGP is not configured or at least one iBGP session is established.",
		sample{value: bgpReady})
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
