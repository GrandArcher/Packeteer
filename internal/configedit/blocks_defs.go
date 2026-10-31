package configedit

import (
	"fmt"
	"slices"
	"time"

	"gopkg.in/yaml.v3"
)

// The blocks of the settings page (#330). Defaults named here are the
// loader's; the page shows them greyed and an empty field writes nothing.

var (
	mbpsMax = 100000000.0
	week    = (7 * 24 * time.Hour).Seconds()
	day     = (24 * time.Hour).Seconds()
	u32Max  = 4294967295.0
)

func field(key, label, help string, kind Kind) Field {
	return Field{Key: key, Label: label, Help: help, Kind: kind}
}

func (f Field) rng(min, max float64) Field {
	f.Min, f.Max = num(min), num(max)
	return f
}

func (f Field) atLeast(min float64) Field {
	f.Min = num(min)
	return f
}

func (f Field) dflt(d string) Field {
	f.Default = d
	return f
}

func (f Field) adv() Field {
	f.Advanced = true
	return f
}

func (f Field) req() Field {
	f.Required = true
	return f
}

func (f Field) check(name string) Field {
	f.Check = name
	return f
}

func (f Field) opts(o ...string) Field {
	f.Options = o
	return f
}

func (f Field) only(scorers ...string) Field {
	f.For = scorers
	return f
}

func (f Field) dtrue() Field {
	f.DefaultTrue = true
	return f
}

func (f Field) noInject() Field {
	f.NoInject = true
	return f
}

func (f Field) unique(key string) Field {
	f.RowKey = key
	return f
}

func (f Field) with(sub ...Field) Field {
	f.Fields = sub
	return f
}

// flowExtras are the optional blocks of a flow source (problems, transit,
// subranges), under its config.
var flowExtras = []Field{
	field("problems", "Passive problem detection", "Counts TCP timeouts and resets in unsampled flow records, and inbound resets in sampled and sFlow records, and probes the prefixes that fail. Measures only.", KindGroup).with(
		field("local", "Your networks", "Local source networks, one per row. Required when this is on.", KindCIDRs).req(),
		field("failure_pct", "Failure share", "A prefix is a problem when this share of its flows fail (of its sampled records, when sampled).", KindFloat).rng(0, 100).dflt("20"),
		field("min_flows", "Minimum flows", "Flows needed in the window before a prefix can be a problem.", KindInt).atLeast(0).dflt("10"),
		field("max_targets", "Most problem prefixes", "Cap on listed problem prefixes.", KindInt).rng(1, 100000).dflt("100"),
	),
	field("transit", "Transit traffic", "Classifies traffic from your customers' networks as transit so a rules policy can treat it separately.", KindGroup).with(
		field("customers", "Customer networks", "Source networks whose traffic transits your edge, one per row.", KindCIDRs).req(),
		field("share_pct", "Transit share", "A prefix is transit when at least this share of its bytes comes from the customer networks.", KindFloat).rng(0, 100).dflt("50"),
	),
	field("subranges", "Sub-ranges", "Measures parts of a wide prefix on their own. Measure only: nothing is announced for a sub-range.", KindGroup).with(
		field("bits_v4", "IPv4 length", "Sub-range length for IPv4.", KindInt).rng(1, 32).dflt("24"),
		field("bits_v6", "IPv6 length", "Sub-range length for IPv6.", KindInt).rng(1, 128).dflt("48"),
		field("max_subranges", "Per prefix", "Busiest sub-ranges measured per prefix.", KindInt).rng(2, 16).dflt("4"),
		field("max_total", "In total", "Sub-ranges across the whole target list.", KindInt).rng(2, 10000).dflt("1000"),
	),
}

var blockDefs = []Block{
	{
		ID: "inject", Title: "Inject settings",
		Help: "Needed before the mode can be inject: the tag on every injected route, the local preference, and the announcer. Choosing inject in Mode asks for the checklist and a confirmation.",
		YAML: "",
		Fields: []Field{
			field("packeteer_community", "Route community", "Tags every injected route, as asn:value or a large community global:data1:data2. The edge's export policy matches only this.", KindString).check("community"),
			field("local_pref", "Local preference", "On an injected route. Set it above the edge's native local preference. Inject needs a value above 0.", KindInt).rng(0, u32Max),
			field("announcer", "Announcer", "The in-process BGP announcer. It publishes on the iBGP session; nothing is announced while the mode is observe.", KindGroup).with(
				field("type", "Type", "The only announcer is gobgp.", KindEnum).opts("gobgp").req(),
			),
		},
	},
	{
		ID: "scorer", Title: "Scorer knobs", YAML: "scorer.config",
		Help: "How a path is scored. Switch the scorer type above; these knobs belong to the type shown. An empty field uses the default.",
		path: []string{"scorer", "config"},
		fix:  scorerNeedsType,
		Fields: []Field{
			field("loss_weight", "Loss weight", "Score added per point of loss.", KindFloat).atLeast(0).dflt("100"),
			field("rtt_weight", "Latency weight", "Score added per millisecond of round-trip time.", KindFloat).atLeast(0).dflt("1"),
			field("jitter_weight", "Jitter weight", "Score added per millisecond of jitter.", KindFloat).atLeast(0).dflt("0.5"),
			field("loss_override", "Move onto higher loss", "Lets a commit move land on a path with more loss.", KindBool).only("commit").adv(),
			field("balance_slack", "Balance slack", "Imbalance inside a group that does not move traffic, 0 to 1.", KindFloat).rng(0, 1).dflt("0.10").only("commit").adv(),
			field("max_age", "Telemetry max age", "Telemetry older than this is ignored.", KindDuration).atLeast(0).dflt("15m").only("commit").adv(),
			field("min_mbps", "Smallest prefix", "Prefixes below this volume are not moved for commit.", KindFloat).rng(0, mbpsMax).dflt("0").only("commit").adv(),
		},
	},
	{
		ID: "bgp", Title: "BGP sessions", YAML: "bgp", path: []string{"bgp"},
		Help: "The iBGP sessions Packeteer learns routes on. Neighbors are your edge routers in your own AS. Adding one opens a session after Save; the session only learns unless the mode is inject.",
		Fields: []Field{
			field("listen_port", "Listen port", "0 connects out to each neighbor. 1 to 65535 accepts sessions.", KindInt).rng(0, 65535).dflt("0").adv(),
			field("listen_addresses", "Listen addresses", "Local addresses to bind when listening, one per row.", KindList).check("ip").adv(),
			field("as_path", "AS path on injected routes", "empty adds none, native copies the learned path, provider copies the chosen provider's.", KindEnum).opts("", "empty", "native", "provider").dflt("empty").adv(),
			field("not_established_after", "Session warning after", "A neighbor that has not come up this long raises an event.", KindDuration).atLeast(0).dflt("5m").adv(),
			field("neighbors", "Neighbors", "Each is an edge router in your AS.", KindRows).unique("address").with(
				field("address", "Address", "The router's IP address.", KindString).check("ip").req(),
				field("description", "Label", "Shown in logs.", KindString),
				field("add_path", "Add-path", "Ask the router for every path (BGP add-path, receive only). The router must be set to send them.", KindBool),
				field("port", "Remote port", "TCP port on the router.", KindInt).rng(0, 65535).dflt("179").adv(),
				field("local_address", "Source address", "Source address of the TCP session.", KindString).check("ip").adv(),
				field("passive", "Wait for the router", "The router connects in. Needs a listen port.", KindBool).adv(),
				field("providers", "Providers it forwards to", "Provider names this router reaches itself, one per row. Empty means every provider.", KindList).check("name").adv(),
			),
		},
	},
	{
		ID: "bmp", Title: "BMP station", YAML: "rib_sources[bmp].config", Optional: true,
		Help: "Routers send their per-peer routes to this station. Learn only: it never sends BGP and never announces. Then set a provider's BMP use to prefer or only.",
		list: "rib_sources", typ: "bmp", path: []string{"config"},
		Fields: []Field{
			field("listen", "Listen", "host:port the routers connect to. With --network host this is a host port: allow it only from the routers.", KindString).check("ipport").dflt(":11019"),
			field("routers", "Routers", "Router addresses allowed to connect, one per row.", KindList).check("ip").req(),
			field("loc_rib", "Read Loc-RIB", "Read the router's selected routes when it sends them.", KindBool).dtrue().adv(),
			field("idle_timeout", "Idle timeout", "Drop a router that sends nothing for this long. 0 is off, otherwise at least 10s.", KindDuration).rng(0, day).dflt("0s").adv(),
		},
	},
	{
		ID: "maintenance", Title: "Maintenance windows", YAML: "policies[maintenance].config", Optional: true,
		Help: "While a window is open its providers are excluded: improvements on them are retired and no move lands on them. Nothing is announced.",
		list: "policies", typ: "maintenance", path: []string{"config"},
		Fields: []Field{
			field("timezone", "Time zone", "IANA zone for the schedules, for example Europe/Berlin.", KindString).dflt("UTC").adv(),
			field("max_api_duration", "Longest on-demand window", "Longest window opened from the API.", KindDuration).rng(60, week).dflt("24h").adv(),
			field("windows", "Windows", "A recurring window has a schedule and a duration. A one-off window has a start and an end.", KindRows).with(
				field("name", "Name", "Optional label; the window ID is schedule-<name>.", KindString).check("name"),
				field("providers", "Providers", "Providers taken out while the window is open, one per row.", KindList).check("name").req(),
				field("schedule", "Schedule", "Cron start time: minute hour day-of-month month day-of-week, for example 0 2 * * 0 for Sundays at 02:00.", KindString),
				field("duration", "Duration", "How long each scheduled window stays open, 1m to 7d.", KindDuration).rng(60, week),
				field("start", "Start", "One-off window start (your browser's time, saved as UTC).", KindTime),
				field("end", "End", "One-off window end.", KindTime),
				field("reason", "Reason", "Shown in the API.", KindString),
			),
		},
		check: checkMaintenance,
	},
	{
		ID: "inbound_announcer", Title: "Inbound announcer", YAML: "inbound.announcer", Optional: true,
		Help: "Publishes inbound steer routes on the iBGP speaker. In observe and suggest it only supplies the catalog. Needs the inbound block above to be on.",
		path: []string{"inbound", "announcer"},
		Fields: []Field{
			field("type", "Type", "The only inbound announcer is gobgp.", KindEnum).opts("gobgp").req(),
			field("config.marker", "Marker community", "Tags steer routes so the edge can tell them from outbound improvements. Must differ from the route community.", KindString).check("community").req(),
			field("config.providers", "Provider actions", "One row per provider that may be steered away from. A provider without a row is never steered away from.", KindRows).unique("provider").with(
				field("provider", "Provider", "A configured provider name.", KindString).check("name").req(),
				field("name", "Label", "Optional label.", KindString),
				field("communities", "Communities", "Signal communities the edge maps to the action, one per row (1 to 16).", KindList).check("community").req(),
				field("prepend", "Prepends", "How many times the edge prepends toward this provider, 0 to 10. Informational.", KindInt).rng(0, 10).adv(),
				field("withhold", "Withhold", "The edge does not send the prefix to this provider at all. Exclusive with prepends.", KindBool).adv(),
			),
		},
	},
	{
		ID: "anomaly", Title: "Anomaly detector", YAML: "anomaly", Optional: true, path: []string{"anomaly"},
		Help: "Baselines flow volumes and reports anomalies. It adds a mitigation rule only through a rule below and the mitigation block (its mode, allowlist, and caps). Turning this off removes the block, rules included.",
		Fields: []Field{
			field("detector.type", "Detector", "The built-in detector is baseline.", KindEnum).opts("baseline").req(),
			field("source", "Flow source", "The flow source that supplies counters. Needed when there are several.", KindString).check("name"),
			field("interval", "Round", "How often rates are checked, 1s to 5m.", KindDuration).rng(1, 300).dflt("10s"),
			field("max_actions_per_hour", "Rules per hour", "Mitigation rules the detector may add in any rolling hour.", KindInt).rng(1, 1000).dflt("6"),
			field("max_active", "Rules held at once", "At most the mitigation rule cap.", KindInt).rng(1, 1000).dflt("4"),
			field("detector.config.sensitivity", "Sensitivity", "Standard deviations above the mean. Lower is more sensitive.", KindFloat).rng(0, 100).dflt("3"),
			field("detector.config.min_mbps", "Smallest anomaly", "Smallest rate that can be an anomaly, Mbit/s.", KindFloat).atLeast(0).dflt("10"),
			field("detector.config.min_ratio", "Times the mean", "The rate must reach this many times the mean.", KindFloat).rng(1, 1000).dflt("3").adv(),
			field("detector.config.max_mbps", "Static ceiling", "A rate at or above this is an anomaly whatever the baseline. 0 is off.", KindFloat).atLeast(0).dflt("0").adv(),
			field("detector.config.alpha", "Learning weight", "Weight of each new round in the baseline, above 0 and at most 1.", KindFloat).rng(0, 1).dflt("0.05").adv(),
			field("detector.config.warmup", "Warm-up rounds", "Rounds a key learns before the baseline test applies.", KindInt).rng(1, 100000).dflt("30").adv(),
			field("detector.config.trigger_rounds", "Rounds to open", "Anomalous rounds in a row before an anomaly opens.", KindInt).rng(1, 1000).dflt("2").adv(),
			field("detector.config.clear_rounds", "Rounds to clear", "Normal rounds in a row before it clears.", KindInt).rng(1, 1000).dflt("3").adv(),
			field("detector.config.max_keys", "Tracked keys", "Keys tracked; new ones past it are not tracked.", KindInt).rng(1, 1000000).dflt("10000").adv(),
		},
	},
	{
		ID: "mitigation", Title: "Mitigation", YAML: "mitigation", Optional: true, path: []string{"mitigation"},
		Help: "RTBH, redirect, and FlowSpec rules for exact learned prefixes. Observe lists rules as a dry run. The announcer, redirect targets, and inject stay with the inject checklist in the raw YAML.",
		Fields: []Field{
			field("mode", "Mode", "Observe is a dry run. Inject is turned on in the raw YAML after the checklist, or kept if it is already set.", KindEnum).opts("", "observe", "inject").dflt("observe").noInject(),
			field("allowlist", "Allowlist", "A rule's prefix must be inside one of these, one per row. Separate from the main allowlist.", KindCIDRs).req(),
			field("max_rules", "Rule cap", "Mitigation routes held at once, announced or waiting.", KindInt).rng(1, 1000).dflt("10"),
			field("default_ttl", "Default lifetime", "Lifetime of a rule that names none.", KindDuration).rng(1, week).dflt("1h").adv(),
			field("max_ttl", "Longest lifetime", "Longest lifetime a request may ask for.", KindDuration).rng(1, week).dflt("24h").adv(),
			field("local_pref", "Local preference", "On mitigation routes. Empty uses the main one.", KindInt).rng(0, u32Max).adv(),
			field("geoip_db", "GeoIP database", "Absolute path of a country database mounted in the container, for source-country rules.", KindString).check("abspath").adv(),
		},
	},
	{
		ID: "http", Title: "HTTP server", YAML: "http", path: []string{"http"},
		Help: "The dashboard, API, and this page. A change to these needs a restart. Mind lock-out: a listen address or allowed range that excludes you, or the editor off, ends this page.",
		Fields: []Field{
			field("listen", "Listen", "host:port, for example localhost:8080. Empty uses the default 127.0.0.1:8080. Wrap IPv6 in brackets.", KindString).check("hostport").dflt("127.0.0.1:8080"),
			field("config_editor", "Config editor", "Lets an admin edit this file here. It also needs sign-in. Turning it off removes this page at the next start.", KindBool),
			field("allow_from", "Allowed clients", "Client ranges that may connect, one per row. Empty allows any. Others get 403 on every path.", KindCIDRs),
		},
	},
}

// scorerNeedsType gives a scorer block made from knobs alone the default
// type, because the loader wants a type with every scorer entry.
func scorerNeedsType(root *yaml.Node) {
	if scorer, ok := mappingChild(root, "scorer"); ok && scalar(scorer, "type") == "" {
		scorer.Content = append([]*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "type"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "weighted"},
		}, scorer.Content...)
	}
}

func checkMaintenance(v Values) error {
	rows, _ := v["windows"].([]Values)
	for i, w := range rows {
		at := fmt.Sprintf("policies[maintenance].config.windows[%d]", i)
		sched, _ := w["schedule"].(string)
		dur, _ := w["duration"].(string)
		start, _ := w["start"].(string)
		end, _ := w["end"].(string)
		switch {
		case sched != "" && (start != "" || end != ""):
			return fieldErr(at+".schedule", "use a schedule with a duration, or a start with an end, not both")
		case sched != "":
			if dur == "" {
				return fieldErr(at+".duration", "a schedule needs a duration")
			}
		case start == "" || end == "":
			return fieldErr(at+".start", "give a schedule with a duration, or both a start and an end")
		case dur != "":
			return fieldErr(at+".duration", "a duration is only for a schedule; a start and an end set the window")
		default:
			s, _ := time.Parse(time.RFC3339, start)
			e, _ := time.Parse(time.RFC3339, end)
			if !e.After(s) {
				return fieldErr(at+".end", "must be after the start")
			}
		}
	}
	return nil
}

// Blocks returns the form blocks in page order.
func Blocks() []Block {
	out := make([]Block, len(blockDefs))
	copy(out, blockDefs)
	return out
}

func blockByID(id string) (Block, bool) {
	for _, b := range blockDefs {
		if b.ID == id {
			return b, true
		}
	}
	return Block{}, false
}

// FlowExtras returns the optional blocks of a flow source, for the page.
func FlowExtras() []Field { return slices.Clone(flowExtras) }
