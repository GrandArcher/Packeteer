package configedit

import (
	"fmt"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/internal/linkout"
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

func (f Field) startOn() Field {
	f.StartOn = true
	return f
}

func (f Field) defaultList(items []string) Field {
	f.DefaultList = items
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
			field("listen", "Listen", "host:port the routers connect to. With --network host this is a host port: allow it only from the routers.", KindString).check("ipport").dflt("127.0.0.1:11019"),
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
			field("hide_window", "Hide window", "How long a route on the wire stays while its prefix is missing from the learned RIB.", KindDuration).rng(60, week).dflt("5m").adv(),
			field("local_pref", "Local preference", "On mitigation routes. Empty uses the main one.", KindInt).rng(0, u32Max).adv(),
			field("geoip_db", "GeoIP database", "Absolute path of a country database mounted in the container, for source-country rules.", KindString).check("abspath").adv(),
		},
	},
	{
		ID: "federation", Title: "Federation (multi-POP)", YAML: "",
		Help: "Joins this instance to the other POPs over mutual TLS. Peers share a read-only view; nothing here announces or decides. A peer may push thresholds and policies to this instance only when it is listed under Accept settings from. Mode, the allowlist, and the announcer are never pushed. A change needs a restart.",
		Fields: []Field{
			field("domain", "Routing domain", "This instance's routing domain. Federation needs it.", KindString).check("name"),
			field("instance", "Instance name", "How peers see this instance. Empty uses the domain.", KindString).check("name").adv(),
			field("federation", "Federation", "Off runs this instance on its own.", KindGroup).with(
				field("type", "Type", "The only federation transport is mtls.", KindEnum).opts("mtls").req(),
				field("config.listen", "Listen", "host:port that serves this instance's snapshot to peers. Empty only polls. With --network host this is a host port: allow it only from the peers.", KindString).check("hostport"),
				field("config.cert_file", "Certificate file", "Absolute path of this instance's certificate in the container.", KindString).check("abspath").req(),
				field("config.key_file", "Key file", "Absolute path of its private key in the container. Only the path is stored.", KindString).check("abspath").req(),
				field("config.ca_file", "CA file", "Absolute path of the CA that signs every instance's certificate.", KindString).check("abspath").req(),
				field("config.peers", "Peers", "The other instances. Each peer's snapshot must carry its name and its certificate must be valid for it.", KindRows).unique("name").with(
					field("name", "Name", "The peer's instance name.", KindString).check("name").req(),
					field("url", "URL", "https://host:port of the peer.", KindString).check("httpsurl").req(),
					field("server_name", "Certificate name", "Overrides the name checked on the peer's certificate.", KindString).check("name").adv(),
					field("domain", "Pinned domain", "The routing domain this peer may claim. Empty accepts what it claims.", KindString).check("name").adv(),
				),
				field("config.allow_clients", "Allowed readers", "Certificate names that may read this instance's snapshot, one per row. Empty uses the peer names.", KindList).check("name"),
				field("config.accept_settings_from", "Accept settings from", "Certificate names that may push thresholds and policies here, one per row. Empty refuses every push. Needs a listen address and the config editor.", KindList).check("name"),
				field("config.poll_interval", "Poll interval", "How often each peer is read, 100ms to 1m.", KindDuration).rng(0.1, 60).dflt("2s").adv(),
				field("config.timeout", "Read timeout", "Bounds one read. At most the poll interval.", KindDuration).rng(0.001, 60).adv(),
				field("config.max_age", "Peer data max age", "A peer's data older than this is not used. From the poll interval to 10m. Empty is three poll intervals.", KindDuration).rng(0.1, 600).adv(),
				field("config.max_bytes", "Largest snapshot", "Bytes accepted from a peer, 1024 to 1073741824.", KindInt).rng(1024, 1073741824).dflt("16777216").adv(),
			),
		},
	},
	{
		ID: "rpki", Title: "RPKI origin validation", YAML: "rpki", Optional: true, path: []string{"rpki"},
		Help:  "Labels each learned path's origin valid, invalid, not found, or unknown from read-only sources, tried in order. It never announces and never changes the learned RIB. A change needs a restart.",
		check: rowsCheck("rpki", "rpki.sources", "sources"),
		Fields: []Field{
			field("enabled", "Enabled", "Off builds no source.", KindBool).startOn(),
			field("avoid_invalid", "Avoid invalid", "Refuse a new improvement onto a provider whose learned path for the prefix is invalid. Never withdraws a learned prefix.", KindBool),
			field("sources", "Sources", "At least one when enabled. The first with fresh data answers. TLS and SSH settings of an rtr source stay in the raw YAML and are kept.", KindRows).with(
				field("type", "Type", "rtr reads RFC 8210 over TCP; json reads a Routinator /json or rpki-client -j file over http.", KindEnum).opts("rtr", "json").req(),
				field("name", "Name", "Optional label.", KindString).check("name"),
				field("config.address", "Address", "rtr only: host:port of the cache.", KindString).check("hostport"),
				field("config.url", "URL", "json only: http:// or https:// address of the document, no login.", KindString).check("baseurl"),
				field("config.refresh", "Refresh", "How often the cache is read, 1s to 24h.", KindDuration).rng(1, 86400).dflt("5m").adv(),
				field("config.staleness", "Staleness", "Data older than this is not used. At least refresh plus an hour for json.", KindDuration).atLeast(1).dflt("1h").adv(),
				field("config.timeout", "Read timeout", "Bounds one read, 1s to 5m.", KindDuration).rng(1, 300).dflt("30s").adv(),
			),
			field("display_fallback", "Display fallback", "Labels the prefix card only when no source is fresh. It sends each looked-up prefix to RIPE NCC and never reaches a decision.", KindGroup).with(
				field("type", "Type", "The only display fallback is ripestat.", KindEnum).opts("ripestat").req(),
			),
		},
	},
	{
		ID: "rpki_only_invalid", Title: "RPKI-invalid only paths", YAML: "rpki.only_invalid", Optional: true, path: []string{"rpki", "only_invalid"},
		Help:  "Reports prefixes whose every learned route is RPKI-invalid, classed from evidence. Needs the RPKI block above to be on. It never announces and never changes the learned RIB. SLURM exceptions change what an RTR cache serves, so they stay in the raw YAML and are kept.",
		check: rowsCheck("rpki.only_invalid", "rpki.only_invalid.hijack_feeds", "hijack_feeds"),
		Fields: []Field{
			field("enabled", "Enabled", "Off reports nothing.", KindBool).startOn(),
			field("stable_after", "Stable after", "How long a learned path must be in the RIB for its origin to count as stable evidence, 1h to 365d.", KindDuration).rng(3600, 365*day).dflt("720h"),
			field("hijack_feeds", "Hijack feeds", "Files of hijack incidents the detector may read.", KindRows).with(
				field("type", "Type", "The only feed is file.", KindEnum).opts("file").req(),
				field("name", "Name", "Optional label.", KindString).check("name"),
				field("config.path", "Path", "Absolute path of the incident file mounted in the container.", KindString).check("abspath").req(),
			),
		},
	},
	{
		ID: "registry", Title: "Registry hygiene", YAML: "registry", Optional: true, path: []string{"registry"},
		Help:  "A scheduled read-only scan compares the learned RIB with IRR route objects, RPKI, the as-set, and PeeringDB. It announces nothing. Pushing a change to a registry (push_enabled) is off and stays a raw YAML edit. A change needs a restart.",
		check: rowsCheck("registry", "registry.sources", "sources"),
		Fields: []Field{
			field("enabled", "Enabled", "Off builds nothing.", KindBool).startOn(),
			field("asns", "Origin ASNs", "The AS numbers this network announces, one per row. A learned route is yours when its origin is one of them.", KindInts).rng(1, u32Max).req(),
			field("as_set", "As-set", "Your as-set, for example AS-EXAMPLE. Needs the irr block with a source.", KindString),
			field("interval", "Scan interval", "Time between scans, 1h to 7d.", KindDuration).rng(3600, week).dflt("24h"),
			field("headroom_percent", "Headroom", "Added to the announced prefix counts when a PeeringDB max-prefix value is suggested, 1 to 1000.", KindInt).rng(1, 1000).dflt("20").adv(),
			field("irr.source", "IRR database", "The source: of generated route objects, in capitals.", KindString).dflt("RIPE").adv(),
			field("irr.mnt_by", "Maintainer", "The mnt-by: of generated route objects.", KindString).adv(),
			field("sources", "Registry sources", "The registries read for the scan.", KindRows).with(
				field("type", "Type", "peeringdb reads the PeeringDB API; ripe reads the RIPE database over REST. Credentials come from the environment only.", KindEnum).opts("peeringdb", "ripe").req(),
				field("name", "Name", "Optional label.", KindString).check("name"),
				field("config.base_url", "Base URL", "Overrides the registry's address, http:// or https:// with no login.", KindString).check("baseurl").adv(),
				field("config.source", "Database", "ripe only: RIPE or TEST.", KindEnum).opts("", "RIPE", "TEST").adv(),
				field("config.timeout", "Timeout", "Bounds one request.", KindDuration).atLeast(1).adv(),
			),
		},
	},
	{
		ID: "mcp", Title: "MCP endpoint", YAML: "mcp", Optional: true, path: []string{"mcp"},
		Help: "Serves POST /mcp for AI assistants: read tools over the REST API as the signed-in caller, with the same roles and audit log. It announces nothing itself. A token needs the mcp scope. A change needs a restart.",
		Fields: []Field{
			field("enabled", "Enabled", "Off serves no /mcp.", KindBool).startOn(),
			field("write_tools", "Write tools", "Adds the write tools (maintenance windows, pins, pause and resume, alert acknowledgement). A call also needs a token with the mcp:write scope and the role the REST call needs. A pin is announced only in inject mode, under a static rule's rails.", KindBool),
			field("rate_per_minute", "Requests per minute", "Per user, 1 to 6000.", KindInt).rng(1, 6000).dflt("120"),
		},
	},
	{
		ID: "verify", Title: "Steer verification", YAML: "verify", Optional: true, path: []string{"verify"},
		Help: "After an improvement or an inbound steer is announced, the interface counters must show the traffic moved: verified, partial, or not moved. It announces nothing. Which directions are backed out when traffic did not move (backout, default inbound only) stays in the raw YAML and is kept. A change needs a restart.",
		Fields: []Field{
			field("enabled", "Enabled", "Off checks nothing.", KindBool).startOn(),
			field("outbound_window", "Outbound window", "How long after an outbound improvement the traffic has to show on the new provider, 10s to 1h.", KindDuration).rng(10, 3600).dflt("5m"),
			field("inbound_window", "Inbound window", "The same for an inbound steer, whose telemetry lags more, 10s to 1h.", KindDuration).rng(10, 3600).dflt("10m"),
			field("verified_pct", "Verified at", "Share of the expected traffic that must have moved, above 0 and at most 100.", KindFloat).rng(0, 100).dflt("50"),
			field("moved_pct", "Moved at", "Share below which nothing moved. Above 0 and below the verified share.", KindFloat).rng(0, 100).dflt("10"),
			field("min_mbps", "Smallest traffic", "Least traffic worth judging, Mbit/s. With less expected the steer is unknown.", KindFloat).atLeast(0).dflt("1").adv(),
			field("backoff", "Back-off", "How long a backed-out steer is held off. It doubles for each repeat.", KindDuration).atLeast(0).dflt("30m").adv(),
			field("max_backoff", "Longest back-off", "At least the back-off.", KindDuration).atLeast(0).dflt("4h").adv(),
		},
	},
	{
		ID: "herd", Title: "Herd (shared measurements)", YAML: "herd", Optional: true, path: []string{"herd"},
		Help:  "Shares probe measurements, never names, host addresses, or usage, with the peers you pin by key. Advisory only: never read by a decision and never announces. Needs sqlite storage and bgp neighbors. Outside sources and resource limits are below; none of it is herd data or reaches a decision. A change needs a restart.",
		check: checkHerdOutside,
		Fields: slices.Concat([]Field{
			field("enabled", "Enabled", "Off stores, serves, and pulls nothing.", KindBool).startOn(),
			field("preview_only", "Preview only", "Stores and previews records but serves and pulls nothing. Needs no listen address or peers.", KindBool),
			field("share.classes", "What is shared", "measurements, or paths to add the AS path. At least one.", KindList).opts("measurements", "paths").req(),
			field("share.granularity", "Granularity", "origin_asn shares per origin AS; route names exact learned prefixes.", KindEnum).opts("", "origin_asn", "route").dflt("origin_asn"),
			field("share.sources", "Target sources", "Probe target sources whose results may be shared, one per row. Empty is static, vip, outage.", KindList).opts("static", "vip", "outage", "flow", "span"),
			field("share.discovery", "Discovery", "query_only answers a peer's question; listing also publishes the list.", KindEnum).opts("", "query_only", "listing").dflt("query_only"),
			field("share.crowd_k", "Crowd threshold", "Route level: a route only flow or span listed is shared once this many other verified ASNs share it, 1 to 64. Needs Identity.", KindInt).rng(1, 64).dflt("2").adv(),
			field("share.exclude.prefixes", "Never share prefixes", "A prefix excludes every route equal to, inside, or covering it, one per row.", KindCIDRs),
			field("share.exclude.asns", "Never share ASNs", "Excludes every route whose origin is the AS or whose path contains it, one per row.", KindInts).rng(1, u32Max),
			field("vantage.country", "Country", "Where this node measures from, ISO 3166-1 alpha-2 in capitals. Declared, not geolocated.", KindString).check("country").req(),
			field("retention_days", "Retention", "Days records are kept and served, 30 to 365.", KindInt).rng(30, 365).dflt("90"),
			field("listen", "Listen", "host:port of the pull API (mutual TLS, pinned keys), apart from the ops listener. With --network host this is a host port: allow it only from the peers.", KindString).check("hostport"),
			field("key_file", "Key file", "Absolute path of this node's Ed25519 key, created on first start. Only the path is stored.", KindString).check("abspath").dflt("/var/lib/packeteer/herd/node.key").adv(),
			field("peers", "Peers", "Static peers, at most 16: the pull API address and the pinned public key.", KindRows).with(
				field("url", "URL", "https://host:port of the peer's pull API.", KindString).check("herdurl").req(),
				field("key", "Public key", "ed25519: and the base64 of the peer's 32-byte key, from its GET /api/herd.", KindString).check("herdkey").req(),
			),
			field("hub", "Hub", "A public list of herd servers used as seeds. Every entry is verified by this node.", KindGroup).with(
				field("url", "URL", "https address of the list document.", KindString).req(),
				field("refresh", "Refresh", "How often the list is fetched, 10m to 7d.", KindDuration).rng(600, 7*day).dflt("6h"),
				field("max_peers", "Most peers", "Peers taken from the list, 1 to 64.", KindInt).rng(1, 64).dflt("16"),
				field("exchange_peers", "Most exchange peers", "Members learned from the hub peers' peer lists, 1 to 64.", KindInt).rng(1, 64).dflt("16"),
			),
			field("identity", "Identity", "Validated RPKI checklists that bind member keys to ASNs. Only verified members are counted.", KindGroup).with(
				field("url", "URL", "https address of the checklist document.", KindString).req(),
				field("refresh", "Refresh", "How often it is fetched, 10m to 24h.", KindDuration).rng(600, day).dflt("1h"),
			),
			field("outside.atlas.enabled", "RIPE Atlas", "Shows public RIPE Atlas results and the status of your hosted probes on the herd page, read with no API key. Off until ticked.", KindBool),
			field("outside.atlas.measurements", "Atlas measurements", "Public measurement ids, one per row, at most 4. Only ping results are shown.", KindInts).rng(1, 2147483647),
			field("outside.atlas.probes", "Atlas probes", "Your own hosted probe ids, one per row, at most 4.", KindInts).rng(1, 2147483647),
			field("outside.atlas.refresh", "Atlas refresh", "How often Atlas is read again, 15m to 24h.", KindDuration).rng(900, day).dflt("15m"),
			field("outside.ris", "RIS Live routes", "Shows routes of your AS that RIPE RIS Live reported outside it. Needs leak_watch with a rislive source.", KindBool),
			field("outside.rpki", "RPKI validation", "Shows the origin validation of a route from the RPKI block. Needs RPKI on.", KindBool),
			field("outside.links", "Link-outs", "Shows the Link-outs sites for the chosen prefix or ASN. Makes no request.", KindBool),
		}, herdLimitFields()),
	},
	{
		ID: "router_check", Title: "Read-only router check", YAML: "preflight.router_check", Optional: true, path: []string{"preflight", "router_check"},
		Help:  "Reads the router's BGP policy with allowlisted read-only commands and backs the import_filter preflight check with it. Point it only at a lab router or a router you chose. It never writes to the router. The socket path or login comes from the environment, never this file. A change needs a restart.",
		check: checkRouterCheck,
		Fields: []Field{
			field("type", "Type", "frr reads bgpd's vty socket, bird reads birdc's socket, routeros reads the REST API with GET only.", KindEnum).opts("frr", "bird", "routeros").req(),
			field("config.socket_env", "Socket variable", "frr and bird: the environment variable that holds the control socket path, PACKETEER_FRR_... or PACKETEER_BIRD_....", KindString).check("envname"),
			field("config.config_env", "Config variable", "bird only: the environment variable that holds the path of the bird.conf that runs, PACKETEER_BIRD_....", KindString).check("envname"),
			field("config.url", "REST URL", "routeros only: https://host of the router. http only to a loopback host.", KindString).check("baseurl"),
			field("config.username_env", "User variable", "routeros only: the environment variable that holds a read-group user, PACKETEER_ROUTER_READ_....", KindString).check("envname"),
			field("config.password_env", "Password variable", "routeros only: the environment variable that holds its password, PACKETEER_ROUTER_READ_.... Only the name is stored.", KindString).check("envname"),
			field("config.ca_file", "CA file", "routeros only: absolute path of the PEM certificate that signed the router's certificate.", KindString).check("abspath").adv(),
		},
	},
	{
		ID: "linkouts", Title: "Link-outs", YAML: "linkouts", path: []string{"linkouts"},
		Help:  "The Open in links on the prefix, ASN, and exchange-peer pages. Display only: Packeteer requests none of these sites. A change needs a restart.",
		check: checkLinkouts,
		Fields: []Field{
			field("enabled", "Built-in sites", "The sites shown. Not set in the file, the default sites are listed; emptying the list shows no built-in site. nlnog_ring and qrator_radar are off unless listed.", KindList).opts(linkout.SiteIDs()...).defaultList(linkout.DefaultSites()),
			field("custom", "Custom links", "Your own sites, at most 20. The URL is https with one of {prefix} or {asn}, not in the host, and no login.", KindRows).unique("name").with(
				field("name", "Name", "1 to 40 printable characters, unique.", KindString).check("linkname").req(),
				field("url", "URL", "For example https://lg.example.net/route?prefix={prefix}.", KindString).check("linkurl").req(),
			),
			field("hide_internal", "Hide internal", "No link for an RFC 1918, ULA, loopback, or link-local prefix or a private-use AS. Documentation ranges are not internal.", KindBool).dtrue(),
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
