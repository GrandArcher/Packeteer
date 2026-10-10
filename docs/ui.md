# Dashboard, config editor, wizard, dashboards, report subscriptions, and improvement weights

The remaining UI conveniences (#34). All of them work in the stock image with a mounted config file. None of them announces a route, and the default mode stays `observe`. Every key is in [CONFIG.md](CONFIG.md).

| Feature | Where | Who | Config |
|---|---|---|---|
| Before/after graphs (#129) | `/graphs.html`, `/api/reports/timeseries`, the `timeseries` dashboard widget | viewer | `storage: {type: sqlite}` |
| Dashboard overview and setup checklist (#49) | `/`, `/api/overview` | viewer | none |
| Config editor and settings form (#102) | `/settings.html`, `/api/config`, `POST /api/config/form` | admin | `http.config_editor: true` + auth or basic auth |
| Setup wizard (#106, flow step #130) | `/settings.html`, `POST /api/config/wizard` | admin | `http.config_editor: true` + auth or basic auth |
| Custom dashboards | `/dashboards.html`, `/api/dashboards` | every signed-in user, own dashboards | `storage: {type: sqlite}` + auth or basic auth |
| Report subscriptions | `report_subscriptions`, `/api/subscriptions` | viewers see them, operators send now | `storage` + an `smtp` notifier |
| Improvement weights | `scorer.config.improvement_weights`, `/api/decisions` | - | `weighted`, `commit`, or `cost` scorer |

With `auth` on, roles are checked per route like every other endpoint ([auth.md](auth.md)); with basic auth, the one account may do everything; with neither, the editor, the wizard, dashboards, and send-now are refused.

## Shell

Every page has the same chrome (#170). The mode banner is the first thing on the page, above a left navigation and a top bar. A reload of a page URL opens that page. The navigation links are:

| Page | URL | What is on it |
|---|---|---|
| Overview | `/` | Tiles, setup checklist, optional features, and POPs when federation is on |
| Dashboards | `/dashboards.html` | Custom dashboards (the existing page) |
| Improvements | `/improvements.html` | Recommended or active improvements |
| Prefixes & ASNs | `/prefixes.html` | Prefix cards and the ASN map |
| Graphs | `/graphs.html` | Before/after loss and latency charts (#129; [below](#graphs)). Empty state without history |
| Reports | `/reports.html` | History reports and CSV |
| Providers & Exchanges | `/providers.html` | Provider health. The exchange view is empty (#148) |
| Commit & Cost | `/commit.html` | Empty (#174) |
| Policies | `/policies.html` | Points to Settings, where the `rules` policy is edited (#130). It does not list rules yet |
| Protection | `/protection.html` | The threat-mitigation monitor when that feature is on. Otherwise an empty state (#131) |
| Troubleshooting | `/troubleshooting.html` | Looking glass, probe, traceroute, whois |
| Events | `/events.html` | Empty (#173) |
| Settings | `/settings.html` | Wizard, settings form, YAML, report subscriptions. Admin |
| Admin | `/admin.html` | Empty (#175). Admin |

POPs stay on Overview and the threat-mitigation monitor stays on Protection. Both stay hidden when the feature is off, as they did on the single dashboard.

The top bar holds the mode chip, a search slot, an events slot, and the account menu. The search slot does not query (#172). The events slot opens the Events page. The account menu shows who is signed in (`GET /api/me`). With single sign-on it can sign out (`POST /auth/logout`). A local account has no sign-out here (#176).

Settings and Admin are marked admin-only. With role-based auth, a viewer or an operator does not see those two links. Opening Admin directly says "Your account may not read this page." Opening Settings directly keeps the editor's existing not-allowed message; report subscriptions on that page are unchanged. With auth off, or with the one basic-auth account, both links are shown. Nothing in the shell announces, and it does not write config.

## Dashboard and first run

The dashboard (`/`) is built for a first run from the stock image with nothing but a mounted config file (#49):

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

- **Mode banner.** `observe` reads "Observe mode: Packeteer measures and recommends. It announces nothing." `suggest` also says it announces nothing. `inject` says improvements for allowlisted prefixes are announced. A file without `mode` observes. The banner is the first thing on every page, in every mode.
- **Mode chip (#171).** The header chip sets its own text and background. Observe is `#0b3a5b` on `#d4e4f4`, suggest is `#6a3b06` on `#f6e4c4`, inject is white on `#9d1c2a`, and any other mode is `#12263a` on `#e7eef5`. Each pair meets WCAG AA (4.5:1) for this text size. The chip no longer inherits the header's white text.
- **Overview tiles.** Mode, status (ready, not ready, starting), providers up, prefixes measured (and which sources list them), recommended improvements (outside inject) or active improvements (inject) against `max_improvements`, and BGP sessions with the number of probed prefixes in the learned RIB.
- **Setup checklist.** Shown until there is nothing left to do, most urgent first. `todo`: no `sources` (nothing to probe). `warn`: every probe through a provider fails (with the last error), every provider is down, `bgp.neighbors` is set but no session is up, or no probed prefix is in the learned RIB. `info`: still starting, waiting for the first round, no `bgp.neighbors` (the current exit is unknown), report history off. Each line names the doc to read. The checklist only reads state; fix the mounted file and restart.
- **Providers** (`/providers.html`) show `no data yet` until something is measured through them, `no answer` when every probe through them fails, and per-provider probe counts. The exchange view on that page is an empty state (#148).
- **Prefixes** (`/prefixes.html`) have a filter (prefix or provider) and a switch for prefixes whose recommended exit differs from the learned one. A prefix card lists each learned path, including inactive add-path and BMP paths, with its MED (display only) and `via` (route server, bilateral, or unknown; #146). The ASN map is on the same page.
- **Improvements** (`/improvements.html`) are labeled recommended outside inject and active in inject.
- **Reports** (`/reports.html`) and **troubleshooting** (`/troubleshooting.html`) are the same sections as before, on their own URLs.
- **Optional sections** (POPs on Overview, threat mitigation on Protection) are hidden when not configured; the overview lists which optional features are on and off. Protection shows the #131 empty state while the monitor is hidden.
- **Errors.** Every section shows `Loading…` until its first answer and a plain empty state after it. When the controller cannot be reached or answers with an error, a banner says so (sign-in required, not allowed, or unreachable), the last data stays on screen marked stale, and the page keeps retrying every 5 seconds.

`GET /api/overview` (viewer) is the same summary as JSON: `mode`, `ready`, `started`, `sources`, `providers` (`name`, `up`, `ok`, `failed`, `last_error`), `counts`, `bgp`, `features` (`name`, `on`), and `setup` (`id`, `level`, `title`, `detail`, `doc`). It is read-only and announces nothing.

CI runs a UI smoke test in the docker job (`lab/ui-smoke.sh`): headless Chrome loads every shell page from the stock image. The first run mounts `config.example.yaml` unchanged. The banner says observe and that it announces nothing, the header chip is `mode-observe`, the checklist on `/` asks for sources, `/providers.html` shows `no data yet`, `/improvements.html` says Recommended, and the empty pages name their issues. The second run uses a minimal file with no `mode` key and one static target (observe, the prefix measured with an RTT on `/prefixes.html`, no improvement). A third run turns the config editor on with basic auth and sqlite, saves a dashboard of providers and improvements, and loads `/`, `/settings.html`, and `/dashboards.html` through `lab/uiproxy` (headless Chrome does not send URL credentials on later fetches). That run checks the filled provider fields keep their labels, the improvements widget says Recommended, and the provider `since` time is the local format.

The settings forms (#130) have their own smoke step in the same job. The stock image mounts an observe file that has a `flow`, `vip`, and `outage` source and a `rules` policy. The step reads the form through the API, merges an edit, and requires the editor's start checks to accept the result as observe with inject not enabled. It renders a wizard config with the flow step and requires the same. Headless Chrome then loads `/settings.html` through `lab/uiproxy` and checks that each section is filled from the file, that the observe banner is on top, and that the wizard has its optional flow step. `internal/configedit`, `internal/httpapi`, and `cmd/controller` tests round-trip every section through `config.Load` and the start checks.

## Graphs

`/graphs.html` charts the `timeseries` report (#129): two charts, loss (%) and latency (ms), one point per UTC day. A dashed line is **before**, the native provider's path, and a solid line is **after**, the chosen provider's path. Both come from the same daily probe rollups, so they are measurements of the two paths whether or not the improvement was announced; in observe the chosen path is the recommended one. The page needs `storage: {type: sqlite}` and says so when history is off. With history but nothing to compare it shows "No before/after data in this range" and draws no chart. Under the charts, a Data table lists the plotted values. A day with no point breaks the line. Days are the finest history the store keeps, so there is no intra-day resolution.

The Destinations list picks one of four buckets, each a subset of the one before it where noted:

| Bucket (`bucket`) | What is in it |
|---|---|
| All destinations (`all`) | Every prefix with an improvement active on that day, when both its native and its chosen provider were measured that day. |
| Problem prefixes (`problem`) | The `all` prefixes whose improvement was made for performance (the native path broke the loss or latency thresholds), not for commit or cost. A record with no cause counts as performance. |
| 20% or more better (`better_20`) | Prefix-days on which the chosen path's average loss or average RTT was at least 20% lower than the native path's. |
| 50% or more better (`better_50`) | The same with 50%. A subset of `better_20`. |

Each point averages the prefixes in the bucket that day, weighted by measured probes. A prefix is placed per day from that day's rollups, so a prefix can be in `better_20` on one day and not the next. The Days list sets the range (7, 30, 90, or 365) and CSV downloads the same rows.

`GET /api/reports/timeseries` (viewer; `days`, or `from` and `to`, like every report) returns `rows`, one per day and bucket that has data, oldest first: `day`, `bucket`, `prefixes`, `before_loss_pct`, `after_loss_pct`, `before_rtt_ms`, `after_rtt_ms`. `limit` does not apply. A bucket and day with no data has no row.

The **Before/after graphs** dashboard widget (`{"type": "timeseries", "days": 7, "bucket": "all"}`; `days` 0 to 3660 and `bucket` one of the four ids, both optional) draws the same charts for one bucket. The charts are inline SVG drawn by `/charts.js`: no external script, font, or style, and nothing inline, so the CSP (same-origin scripts and styles only) holds. The page and the widget only read; they announce nothing, and the mode banner is on top in every mode.

CI (docker job) loads `/graphs.html` twice in headless Chrome: against the stock example config with empty history (the empty state, no chart), and against a history seeded by `lab/mkhistory` on documentation prefixes (the charts, the data table, and a `timeseries` dashboard widget). `internal/history` tests cover every bucket with synthetic history.

## Config editor

Turn it on in the file itself, and mount the file writable:

```yaml
http:
  listen: "127.0.0.1:8080"
  config_editor: true
```

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PACKETEER_HTTP_USER=ops -e PACKETEER_HTTP_PASSWORD='use-a-long-secret' \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

`/settings.html` loads the file, validates it, and saves it. The API:

- `GET /api/config`: `path`, `yaml`, and `sha256` of the file on disk.
- `POST /api/config/validate {"yaml": "..."}`: runs the checks without writing. Returns `valid`, `errors` (one line each), `mode`, `changed` (keys that differ from the running config), `restart_required`, `reload_online` (every change can apply while running: thresholds, hold time, the cap, policies, sources, probe timing, mode, the allowlist, and `bgp.neighbors`), and `enables_inject`.
- `PUT /api/config {"yaml": "...", "base": "<sha256>", "confirm_inject": false}`: writes the file.

A write is accepted only when:

- `base` is the `sha256` of the file on disk now (otherwise `409`: someone else changed it; reload and edit again);
- it adds or changes no `exec` plugin and keeps `plugin_dir` (see below);
- the new text passes the same checks the controller runs when it starts: `config.Load`'s strict parser and validator (unknown keys are errors), the environment overrides, every plugin's own config, and the cross-checks (auth, telemetry, VIP and outage intervals, anomaly source, report subscriptions). Otherwise `422` with the errors, and the file is not touched;
- a file that turns `mode: inject` on (and was not inject before) carries `confirm_inject: true` (otherwise `428`). The inject rules still apply: allowlist, `local_pref`, community, announcer, thresholds, hold time, and at least one neighbor are required by the validator.

The file is written next to itself and renamed into place when the directory allows it. A single-file bind mount cannot be renamed over, so the file is then rewritten in place (restored if that write fails; if the restore fails too, the old content is kept in a temporary file whose path is in the error). It is then read back and loaded with `config.Load`; the response is sent only after that. The file mode is kept. Comments and formatting are what you typed: the editor writes your text, not a re-rendered config. Files larger than 1 MiB are refused.

When `reload_online` is true, the running controller applies the file on this write (#128). The response adds `applied` (the keys now running) or `apply_error` (the running config was left as it was, or the process is stopping because the BGP speaker changed). A mix of online and restart-only keys is not applied: restart the container. SIGHUP applies the same online keys ([CONFIG.md](CONFIG.md#online-reconfiguration)). A restart withdraws every Packeteer route first, as always. The observe banner stays on the dashboard in every mode.

Every write, accepted or refused, is in the audit log with the old and new hashes (never the content) and is logged as a warning.

## Settings form

`/settings.html` puts a form beside the YAML (#102). The form has a row per provider (name, probe source, next hop, cost, commit), a row per static probe prefix, a row per allowlist prefix, and separate fields for hold time, the improvement cap, the loss and latency thresholds, the RTT percent (`min_rtt_delta_pct`, empty or 0 is off), confirm rounds (`confirm_rounds`, empty means 1), and, when the scorer is `cost`, whether cost or performance wins plus the floor (extra loss, extra delay). Plus adds a row and minus removes one. Each provider field has a visible label above the input, and that label is the field's accessible name, including after the placeholder disappears (#171). Apply copies the form into the YAML in the editor and does not write the file. Save is still `PUT /api/config`: the same checks as a start, the same `confirm_inject` when the text turns inject on, and the same online apply as a SIGHUP when every change can run while the process is up (#128). A cap of 0 is a whole number and retires every improvement on the next decision. MED stays display-only. A next hop seen on the wire is a draft suggestion, not a provider, until it is saved as one.

Fields the form does not show stay in the YAML, including plugin blocks. An unchanged form is not reformatted. Commit is the SNMP telemetry binding's `commit_mbps` for that provider; there is no field for a community or a passphrase. A commit with no binding is refused until the binding is in the YAML. Choosing cost-or-performance, or setting the floor, on a `weighted` scorer (or none) switches `scorer.type` to `cost` and keeps the weights. It does not replace a `commit` scorer.

### Flow, policies, VIP, and outage (#130)

Four more sections sit under the allowlist. Each edits the **first** source or policy of its type; further ones, and every key the form does not show, stay in the YAML.

| Section | Edits | Notes |
|---|---|---|
| Flow collector | the first `flow` source: `listen` (comma separated `host:port`), `window`, `top_n` (the priority tier, probed every round), `max_targets`, `tail_interval`, `min_bytes`, `min_pct`, `exclude` | `problems`, `transit`, `subranges`, `aggregate_v4`, and `aggregate_v6` are kept as they are. Unchecking the box removes the source and those blocks from the YAML. Measurement only |
| Policies (rules) | the first `rules` policy: one row per rule (`name`, `action`, `providers`, `prefixes`, `asns`, `countries`, `traffic`, `max_loss_pct`, `max_rtt`) | Rules keep their order. Removing every rule removes that policy. `geoip_db`, `maintenance`, and any other policy stay in the YAML. A country rule still needs `geoip_db` in the file; the start checks say so on Validate or Save |
| VIP | the first `vip` source: `interval`, `max_targets`, prefixes with an optional pinned host, `asns` | Unchecking removes the source |
| Outage detection | the first `outage` source: `min_prefixes`, `window`, `loss_pct`, `rtt_ms`, `interval`, `max_targets`, `ignore_asns` | Empty fields use the defaults. Unchecking removes the source |

A policy or source only restricts, orders, or measures. The learned-RIB check, the allowlist, `max_improvements`, the community and NO_EXPORT, hold time, and the withdraw rules are unchanged, and nothing here can announce. The form checks each field the way the plugin does (types, bounds, duplicates, a rule's action against its providers and `max_loss_pct`, and that a rule names configured providers) and refuses with the field named. The start checks that need the whole file still run on Validate and Save, for example a flow `tail_interval` that must be longer than `probe.interval`. A section the operator did not change is not checked or rewritten, so a file the form does not fully model still lets the other fields apply.

`vip` ASNs and the `outage` source read the learned RIB: set `bgp.neighbors` before enabling them. A controller with no BGP session currently stops with a nil-pointer panic once either one runs. This change does not alter that.

`POST /api/config/form {"yaml"}` returns `form`, now with `flow`, `policies` (`rules`), `vip`, and `outage` objects (`enabled` on each source). A request that leaves a section out of `form` leaves that part of the file alone, so a client written before #130 cannot remove one. Saving is the same `PUT /api/config` as every other edit: admin role, the same checks as a start, `confirm_inject` when the text turns inject on, and a line in the audit log with the old and new hashes.

`POST /api/config/form {"yaml"}` returns `form`. `POST /api/config/form {"yaml","apply":true,"form":{...}}` returns the merged `yaml` and the form read back. Neither writes.

`GET /api/config/suggestions` lists next hops seen on iBGP (including add-path) or BMP that are not a configured provider and not on an exchange LAN: `next_hop`, `asn` (the most common first AS), and `prefixes`. The busiest 64 are returned. Accepting one in the page adds a draft provider row with the next hop and the AS shown. The probe source, cost, and commit stay empty. Accepting does not call the API, so it does not write a provider, start probing, or announce. Exchange LAN hops stay on `GET /api/exchanges` until the operator adds them as peers. The list is cached against the RIB generation and only reads.

**Secrets.** `GET /api/config` returns the file exactly as it is on disk, to every admin API client; nothing is redacted (a redacted file could not be saved back). With the editor on, keep every secret out of the file: built-in plugins only take secrets by environment variable name (`password_env`, `community_env`, `auth_env`, `client_secret_env`, `routing_key_env`), and webhook `url`/`headers` and exec `env` values should reference `${VAR}` instead of holding a token.

**Exec plugins.** Checking or saving a candidate never runs a program. `exec` plugins in the candidate are validated without running their command (no `init` handshake), and a candidate that adds or changes an `exec` plugin (command, args, env, anything in its block) or changes `plugin_dir` is refused with `422`. Which programs the controller runs is set only by editing the mounted file; removing an `exec` plugin through the editor is allowed.

The file is read-only in many deployments (`:ro`). Then saving fails with a clear error and nothing changes. Leave `config_editor` off if you manage the file with Git or configuration management.

## Setup wizard

`/settings.html` walks four steps, the last optional (#106, #130). `POST /api/config/wizard` renders a config from them and writes nothing. The result opens in the editor for review, and you save it like any other edit.

1. Edge session: ASN, an IPv4 router ID, and the edge address. The session is learn-only iBGP.
2. Providers: one row each (name, probe source, next hop), with plus and minus. Each of those three fields has a visible label, the same way as the settings form (#171). A next hop from `GET /api/config/suggestions` can be added as a row; you still name it and set the probe source. Adding a row does not probe or announce.
3. What to probe: an optional prefix and an optional pinned host inside it. Leave both empty to add targets later in the form. A prefix without a host is probed at a few addresses inside it, including the provider next hop when that address can be used. A host pins that prefix to one address. Report history (sqlite) is a checkbox on this step, not a secret.
4. Flow collector (optional): a checkbox, a listen address (empty means every address), and a UDP port (default 2055). When on, the file gets a `flow` source listening there, with the source's defaults; tune it afterwards in the settings form. The step explains exporter setup: point the router's NetFlow v5/v9, IPFIX, or sFlow export at that host and port. Packeteer does not configure the router. With `--network host` the port is a host UDP port: do not publish it, and allow it only from the router. The generated file carries the same note. `POST /api/config/wizard` takes it as `"flow": {"listen": "192.0.2.10:2055"}`; a bad address or port is refused with the other wizard errors. Leaving the step off renders exactly what the wizard rendered before.

The rendered file is always:

- `mode: observe` (it measures and recommends; it never announces). Any other mode, including inject, is refused. Inject is not a step;
- an empty allowlist and no announcer;
- one `bgp.neighbors` entry, the edge address;
- the `weighted` scorer, `max_improvements: 50`, `hold_time: 15m`, the default thresholds, and `http.listen: 127.0.0.1:8080`;
- a `static` source only when a prefix was given, and a `flow` source only when the flow step was used;
- `packeteer_community` `<asn>:666` when the ASN fits in 16 bits.

There is no field for a password, a community string, or any other secret. Those stay in environment variables. The page checks each step before continuing, and the server checks the whole body again with `config.Parse`. The wizard is part of the editor: it is off (`404`) unless `http.config_editor` is on. Turning inject on afterwards is a separate edit; follow the [inject checklist](CONFIG.md#inject-checklist).

## Custom dashboards

`/dashboards.html` builds dashboards from read-only widgets. Each user has their own (at most 20, with at most 24 widgets each), kept by the storage plugin (`sqlite`, table `dashboards`). Widgets read endpoints the viewer role can already read: readiness, providers, prefixes, improvements, decisions, provider usage, inbound steers, threat mitigation, anomalies, POPs, HA, report subscriptions, and any stored report with a range in days, and the before/after graphs (type `timeseries`, below). A widget can span the full row.

The improvements widget is titled Recommended improvements in observe and suggest, and Active improvements in inject (#171). A title the operator set on that widget is kept. Timestamps in a widget use the same local format as the main dashboard (`toLocaleString`). An unparseable value stays as returned.

API: `GET /api/dashboards` returns `widget_types`, the report list, and your dashboards; `PUT /api/dashboards/<name>` with `{"title": "...", "widgets": [{"type": "providers"}, {"type": "report", "report": "summary", "days": 7, "wide": true}, {"type": "timeseries", "days": 30, "bucket": "better_50"}]}` saves one (unknown widget types, unknown reports, an unknown `bucket`, `report`, `days`, or `bucket` on a widget type that does not take them, and unknown fields are refused); `DELETE /api/dashboards/<name>` removes it. Deleting a user deletes that user's dashboards.

## Report subscriptions

```yaml
storage:
  type: sqlite
notifiers:
  - type: smtp
    name: mail
    config:
      host: smtp.example.net
      from: packeteer@example.net
      to: [noc@example.net]
      username_env: PACKETEER_SMTP_USER
      password_env: PACKETEER_SMTP_PASSWORD
report_subscriptions:
  - name: weekly-summary
    report: summary
    schedule: weekly        # daily, weekly (weekday, default monday), monthly (the 1st)
    at: "06:00"             # UTC
    notifier: mail
  - name: monthly-savings
    report: savings
    schedule: monthly
    days: 31
    notifier: mail
    to: [finance@example.net]
```

Each send is one email from the named `smtp` notifier: a short text body (report, range, row count) and the report as a CSV attachment, the same rows `/api/reports/<report>?format=csv` returns for the range ending at the send time. The notifier's event filters do not apply to reports; a subscription's `to` replaces the notifier's recipients. Recipients come only from the file; the API cannot add one.

At start the controller refuses an unknown report name or a notifier that cannot send reports (webhook, SNMP trap, exec). A failed send is logged, counted, and shown on `/api/subscriptions`, and tried again at the next scheduled time. Sends missed while the controller was down are not replayed. `POST /api/subscriptions/<name>/send` (operator) sends one now for the range ending now, without moving the schedule.

## Improvement weights

When more prefixes want an improvement than `max_improvements` allows, Packeteer admits the biggest score gains first. With `improvement_weights` on the scorer, it admits the highest weight instead:

```yaml
scorer:
  type: weighted
  config:
    improvement_weights:
      performance: 1   # times the score gain (default 1)
      volume: 1        # times the prefix's traffic in Mbps (default 0)
```

`weight = performance × gain + volume × volume_mbps`. The gain is the native path's score minus the chosen path's; with the default `weighted` scores, 1 ms of RTT is 1 point and 1 % of loss is 100 points. The volume comes from a source that reports it: the `flow` window, or `mbps` on a `static` target. A prefix with no volume counts 0.

Weights only order moves inside their lane: static policy pins first, then VIP moves, then other performance moves. Commit and cost moves keep their relief and savings order. Each move's weight is on `/api/decisions` (`weight`).

Weights never relax a rule: a prefix must still be an exact prefix in the learned RIB and, in inject, allowlisted; the thresholds, hold time, and cooldowns apply as before; the cap is never exceeded; an active improvement is never displaced by a heavier newcomer (no churn); every route still carries `packeteer_community` and NO_EXPORT; and routes are withdrawn on shutdown, stale data, and session loss as always.

Lab proof (`lab/e2e-weights.sh`, CI job `e2e`): an FRR edge advertises 198.51.100.0/24 (5 Mbps) and 203.0.113.0/24 (500 Mbps) with the same gain, and `max_improvements: 1`. The heavier 203.0.113.0/24 takes the slot (without weights the other one would: equal gains break by prefix), with next hop, local-pref, community, and NO_EXPORT; 198.51.100.0/24 is capped with its weight on `/api/decisions`; 198.51.100.0/25, the heaviest and allowlisted but never advertised, is never announced; a real RIB leave withdraws the route and hands the slot over; the heavier prefix coming back does not displace it; SIGTERM withdraws; a restart gives the slot to the heavier prefix again; SIGKILL drops the route with the session within the hold timer. Lab-proven only, not on a public edge.

## Rollback

The graphs (#129) are read-only and need no rollback. Delete a `timeseries` widget from a dashboard to hide it; a build from before #129 refuses to save a dashboard that still has one.

The form sections and the wizard's flow step (#130) are UI and API only and add no config key: revert the change to drop them, or delete the `flow`, `vip`, and `outage` sources and the `rules` policy from the YAML (a restart withdraws every Packeteer route first). A file the form wrote is an ordinary config file that an older build loads unchanged. Remove `improvement_weights`, `http.config_editor`, and `report_subscriptions` and restart. The dashboard polish (#49) needs no rollback: it reads the same state, and `/api/overview` is read-only. The file config works exactly as before; the editor only ever wrote a plain YAML file. Stored dashboards stay in the database and are ignored by an older build. The display fixes (#171) are presentation only: revert that change to restore the previous chip, titles, timestamps, and unlabeled provider fields. The shell (#170) is presentation only as well: revert it to put every section back on `/`. No config key changes.
