package configedit

import (
	"fmt"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
)

// herdLimitText is the label and help of each herd.limits key. The default
// and the range come from the loader (config.HerdLimitSpecs), and a test
// fails when a key has no text here or a text has no key.
var herdLimitText = map[string][2]string{
	"rate_per_identity":     {"Requests per member", "Pull requests a verified member may make in a minute. Above it the answer is 429."},
	"rate_global":           {"Requests, all callers", "Pull requests in a minute from everyone together."},
	"rate_per_address":      {"Requests per address", "Pull requests in a minute from one address (an IPv6 /64 counts as one)."},
	"max_conns":             {"Connections", "Open pull connections at once."},
	"max_conns_per_peer":    {"Connections per member", "Open pull connections at once from one member."},
	"max_handshakes":        {"Handshakes", "TLS handshakes in progress at once."},
	"max_requests_per_conn": {"Requests per connection", "Requests served on one connection before it is closed."},
	"max_request_bytes":     {"Request size", "Largest request accepted, in bytes."},
	"page_records":          {"Records per page", "Most records in one answer page."},
	"response_bytes":        {"Response size", "Largest answer, in bytes."},
	"timeout":               {"Serving timeout", "Bounds reading a request and writing the answer."},
	"idle_timeout":          {"Idle timeout", "An idle connection is closed after this."},
	"pull_interval":         {"Pull interval", "How often each peer is pulled."},
	"pull_timeout":          {"Pull timeout", "Bounds one pull request."},
	"max_pulls":             {"Concurrent pulls", "Peers pulled at the same time."},
	"pull_requests":         {"Pull requests per interval", "Requests to all peers in one pull interval."},
	"peer_requests":         {"Requests per peer", "Requests to one peer in one pull interval."},
	"pull_bytes":            {"Pull response size", "Largest response read from a peer, in bytes."},
	"pull_records":          {"Records per pull response", "Most records taken from one response."},
	"peer_records_per_pull": {"Records per peer and pull", "Most records taken from one peer in one pull."},
	"peer_records_total":    {"Records per peer, stored", "Most pulled records kept for one peer."},
	"backoff_max":           {"Longest back-off", "Longest wait after a failed or refused pull."},
	"queue":                 {"Queue", "Probe rounds waiting for the herd goroutine. A full queue drops the round and counts it."},
	"local_bytes":           {"Local record disk budget", "Bytes of this node's own stored records."},
	"pulled_bytes":          {"Pulled record disk budget", "Bytes of records pulled from peers. The oldest are deleted first."},
}

// herdLimitFields are the limit keys as advanced fields of the herd block.
// An empty field writes nothing and the loader's default applies.
func herdLimitFields() []Field {
	var out []Field
	for _, s := range config.HerdLimitSpecs() {
		text := herdLimitText[s.Key]
		key := "limits." + s.Key
		if s.Duration {
			out = append(out, field(key, text[0], text[1]+" "+fmt.Sprintf("%s to %s.", durText(s.Min), durText(s.Max)), KindDuration).
				rng(time.Duration(s.Min).Seconds(), time.Duration(s.Max).Seconds()).dflt(durText(s.Default)).adv())
			continue
		}
		out = append(out, field(key, text[0], text[1], KindInt).rng(float64(s.Min), float64(s.Max)).dflt(strconv.FormatInt(s.Default, 10)).adv())
	}
	return out
}

// durText writes a duration the way an operator types one: 5m, not 5m0s.
func durText(ns int64) string {
	d := time.Duration(ns)
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

// checkHerdOutside gives the Atlas settings the loader's checks with the
// field named: ids and a refresh need the switch, and the switch needs an id.
func checkHerdOutside(v Values) error {
	on, _ := v["outside.atlas.enabled"].(bool)
	meas, _ := v["outside.atlas.measurements"].([]string)
	probes, _ := v["outside.atlas.probes"].([]string)
	refresh, _ := v["outside.atlas.refresh"].(string)
	if !on {
		if len(meas)+len(probes) > 0 || refresh != "" {
			return fieldErr("herd.outside.atlas.enabled", "turn Atlas on to use measurements, probes, or a refresh")
		}
		return nil
	}
	if len(meas)+len(probes) == 0 {
		return fieldErr("herd.outside.atlas.measurements", "name at least one measurement or probe")
	}
	if len(meas) > config.MaxHerdAtlasIDs {
		return fieldErr("herd.outside.atlas.measurements", "at most %d", config.MaxHerdAtlasIDs)
	}
	if len(probes) > config.MaxHerdAtlasIDs {
		return fieldErr("herd.outside.atlas.probes", "at most %d", config.MaxHerdAtlasIDs)
	}
	return nil
}
