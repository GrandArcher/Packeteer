package configedit

import "strings"

// envPrefixes are the variable name prefixes the editor accepts in a *_env
// key, per place: "<list>/<plugin type>" for a plugin's config, or the
// yaml path of a block with a typed *_env field. A plugin sends the value
// of that variable to the host it is configured with, so a free name would
// let an admin send PACKETEER_ADMIN_PASSWORD or the OIDC client secret to a
// host they chose (#504). A place not listed takes only the names the
// running config already uses there. The mounted file is not checked.
var envPrefixes = map[string][]string{
	"telemetry/snmp":          {"PACKETEER_SNMP_"},
	"exporters/snmpagent":     {"PACKETEER_SNMP_"},
	"notifiers/snmptrap":      {"PACKETEER_SNMP_", "PACKETEER_TRAP_"},
	"notifiers/smtp":          {"PACKETEER_SMTP_"},
	"notifiers/webhook":       {"PACKETEER_WEBHOOK_", "PAGERDUTY_"},
	"exporters/influxdb":      {"PACKETEER_INFLUX_", "INFLUX_"},
	"exporters/kafka":         {"PACKETEER_KAFKA_"},
	"exporters/nats":          {"PACKETEER_NATS_"},
	"auth.sso/oidc":           {"PACKETEER_OIDC_"},
	"threat_feeds.feeds/http": {"PACKETEER_FEED_"},
	"external_policy":         {"PACKETEER_POLICY_"},
	"nonbgp.steerer/mikrotik": {"PACKETEER_ROUTER_"},
}

// EnvNameAllowed reports whether the editor may set a *_env key at place
// to name.
func EnvNameAllowed(place, name string) bool {
	for _, p := range envPrefixes[place] {
		if len(name) > len(p) && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// EnvPrefixes lists the prefixes EnvNameAllowed accepts at place, for an
// error message. It is empty for a place with no allowlist.
func EnvPrefixes(place string) []string {
	return envPrefixes[place]
}
