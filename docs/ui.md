# Dashboard, config editor, wizard, dashboards, report subscriptions, and improvement weights

The remaining IRP GUI conveniences (#34). All of them work in the stock image with a mounted config file. None of them announces a route, and the default mode stays `observe`. Every key is in [CONFIG.md](CONFIG.md).

| Feature | Where | Who | Config |
|---|---|---|---|
| Dashboard overview and setup checklist (#49) | `/`, `/api/overview` | viewer | none |
| Config editor and settings form (#102) | `/settings.html`, `/api/config`, `POST /api/config/form` | admin | `http.config_editor: true` + auth or basic auth |
| Setup wizard (#106) | `/settings.html`, `POST /api/config/wizard` | admin | `http.config_editor: true` + auth or basic auth |
| Custom dashboards | `/dashboards.html`, `/api/dashboards` | every signed-in user, own dashboards | `storage: {type: sqlite}` + auth or basic auth |
| Report subscriptions | `report_subscriptions`, `/api/subscriptions` | viewers see them, operators send now | `storage` + an `smtp` notifier |
| Improvement weights | `scorer.config.improvement_weights`, `/api/decisions` | - | `weighted`, `commit`, or `cost` scorer |

With `auth` on, roles are checked per route like every other endpoint ([auth.md](auth.md)); with basic auth, the one account may do everything; with neither, the editor, the wizard, dashboards, and send-now are refused.

## Dashboard and first run

The dashboard (`/`) is built for a first run from the stock image with nothing but a mounted config file (#49):

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

- **Mode banner.** `observe` and `suggest` say that nothing is announced; `inject` says improvements for allowlisted prefixes are announced. A file without `mode` observes.
- **Overview tiles.** Mode, status (ready, not ready, starting), providers up, prefixes measured (and which sources list them), recommended improvements (outside inject) or active improvements (inject) against `max_improvements`, and BGP sessions with the number of probed prefixes in the learned RIB.
- **Setup checklist.** Shown until there is nothing left to do, most urgent first. `todo`: no `sources` (nothing to probe). `warn`: every probe through a provider fails (with the last error), every provider is down, `bgp.neighbors` is set but no session is up, or no probed prefix is in the learned RIB. `info`: still starting, waiting for the first round, no `bgp.neighbors` (the current exit is unknown), report history off. Each line names the doc to read. The checklist only reads state; fix the mounted file and restart.
- **Providers** show `no data yet` until something is measured through them, `no answer` when every probe through them fails, and per-provider probe counts.
- **Prefixes** have a filter (prefix or provider) and a switch for prefixes whose recommended exit differs from the learned one.
- **Optional sections** (POPs, threat mitigation) are hidden when not configured; the overview lists which optional features are on and off.
- **Errors.** Every section shows `Loading…` until its first answer and a plain empty state after it. When the controller cannot be reached or answers with an error, a banner says so (sign-in required, not allowed, or unreachable), the last data stays on screen marked stale, and the page keeps retrying every 5 seconds.

`GET /api/overview` (viewer) is the same summary as JSON: `mode`, `ready`, `started`, `sources`, `providers` (`name`, `up`, `ok`, `failed`, `last_error`), `counts`, `bgp`, `features` (`name`, `on`), and `setup` (`id`, `level`, `title`, `detail`, `doc`). It is read-only and announces nothing.

CI runs a UI smoke test in the docker job (`lab/ui-smoke.sh`): headless Chrome loads `/`, `/settings.html`, and `/dashboards.html` from the stock image, first with `config.example.yaml` mounted unchanged (the banner says observe, the checklist asks for sources, providers show `no data yet`), then with a minimal file that has no `mode` key and one static target (observe, the prefix measured with an RTT, no improvement).

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
- `POST /api/config/validate {"yaml": "..."}`: runs the checks without writing. Returns `valid`, `errors` (one line each), `mode`, `changed` (keys that differ from the running config), `restart_required`, `reload_online` (only `bgp.neighbors` changed), and `enables_inject`.
- `PUT /api/config {"yaml": "...", "base": "<sha256>", "confirm_inject": false}`: writes the file.

A write is accepted only when:

- `base` is the `sha256` of the file on disk now (otherwise `409`: someone else changed it; reload and edit again);
- it adds or changes no `exec` plugin and keeps `plugin_dir` (see below);
- the new text passes the same checks the controller runs when it starts: `config.Load`'s strict parser and validator (unknown keys are errors), the environment overrides, every plugin's own config, and the cross-checks (auth, telemetry, VIP and outage intervals, anomaly source, report subscriptions). Otherwise `422` with the errors, and the file is not touched;
- a file that turns `mode: inject` on (and was not inject before) carries `confirm_inject: true` (otherwise `428`). The inject rules still apply: allowlist, `local_pref`, community, announcer, thresholds, hold time, and at least one neighbor are required by the validator.

The file is written next to itself and renamed into place when the directory allows it. A single-file bind mount cannot be renamed over, so the file is then rewritten in place (restored if that write fails; if the restore fails too, the old content is kept in a temporary file whose path is in the error). It is then read back and loaded with `config.Load`; the response is sent only after that. The file mode is kept. Comments and formatting are what you typed: the editor writes your text, not a re-rendered config. Files larger than 1 MiB are refused.

The running controller does **not** change. Restart the container to apply the new file, or send SIGHUP when only `bgp.neighbors` changed ([route-reflector.md](route-reflector.md)). A restart withdraws every Packeteer route first, as always.

Every write, accepted or refused, is in the audit log with the old and new hashes (never the content) and is logged as a warning.

## Settings form

`/settings.html` puts a form beside the YAML (#102). The form has a row per provider (name, probe source, next hop, cost, commit), a row per static probe prefix, a row per allowlist prefix, and separate fields for hold time, the improvement cap, the loss and latency thresholds, and, when the scorer is `cost`, whether cost or performance wins plus the floor (extra loss, extra delay). Plus adds a row and minus removes one. Apply copies the form into the YAML in the editor and does not write the file. Save is still `PUT /api/config`: the same checks as a start, the same `confirm_inject` when the text turns inject on, and the running controller still applies the file on restart (or SIGHUP when only `bgp.neighbors` changed).

Fields the form does not show stay in the YAML, including plugin blocks. An unchanged form is not reformatted. Commit is the SNMP telemetry binding's `commit_mbps` for that provider; there is no field for a community or a passphrase. A commit with no binding is refused until the binding is in the YAML. Choosing cost-or-performance, or setting the floor, on a `weighted` scorer (or none) switches `scorer.type` to `cost` and keeps the weights. It does not replace a `commit` scorer.

`POST /api/config/form {"yaml"}` returns `form`. `POST /api/config/form {"yaml","apply":true,"form":{...}}` returns the merged `yaml` and the form read back. Neither writes.

`GET /api/config/suggestions` lists next hops seen on iBGP (including add-path) or BMP that are not a configured provider and not on an exchange LAN: `next_hop`, `asn` (the most common first AS), and `prefixes`. The busiest 64 are returned. Accepting one in the page adds a draft provider row with the next hop and the AS shown. The probe source, cost, and commit stay empty. Accepting does not call the API, so it does not write a provider, start probing, or announce. Exchange LAN hops stay on `GET /api/exchanges` until the operator adds them as peers. The list is cached against the RIB generation and only reads.

**Secrets.** `GET /api/config` returns the file exactly as it is on disk, to every admin API client; nothing is redacted (a redacted file could not be saved back). With the editor on, keep every secret out of the file: built-in plugins only take secrets by environment variable name (`password_env`, `community_env`, `auth_env`, `client_secret_env`, `routing_key_env`), and webhook `url`/`headers` and exec `env` values should reference `${VAR}` instead of holding a token.

**Exec plugins.** Checking or saving a candidate never runs a program. `exec` plugins in the candidate are validated without running their command (no `init` handshake), and a candidate that adds or changes an `exec` plugin (command, args, env, anything in its block) or changes `plugin_dir` is refused with `422`. Which programs the controller runs is set only by editing the mounted file; removing an `exec` plugin through the editor is allowed.

The file is read-only in many deployments (`:ro`). Then saving fails with a clear error and nothing changes. Leave `config_editor` off if you manage the file with Git or configuration management.

## Setup wizard

`/settings.html` walks three steps (#106). `POST /api/config/wizard` renders a config from them and writes nothing. The result opens in the editor for review, and you save it like any other edit.

1. Edge session: ASN, an IPv4 router ID, and the edge address. The session is learn-only iBGP.
2. Providers: one row each (name, probe source, next hop), with plus and minus. A next hop from `GET /api/config/suggestions` can be added as a row; you still name it and set the probe source. Adding a row does not probe or announce.
3. What to probe: an optional prefix and an optional pinned host inside it. Leave both empty to add targets later in the form. A prefix without a host is probed at a few addresses inside it, including the provider next hop when that address can be used. A host pins that prefix to one address. Report history (sqlite) is a checkbox on this step, not a secret.

The rendered file is always:

- `mode: observe` (it measures and recommends; it never announces). Any other mode, including inject, is refused. Inject is not a step;
- an empty allowlist and no announcer;
- one `bgp.neighbors` entry, the edge address;
- the `weighted` scorer, `max_improvements: 50`, `hold_time: 15m`, the default thresholds, and `http.listen: 127.0.0.1:8080`;
- a `static` source only when a prefix was given;
- `packeteer_community` `<asn>:666` when the ASN fits in 16 bits.

There is no field for a password, a community string, or any other secret. Those stay in environment variables. The page checks each step before continuing, and the server checks the whole body again with `config.Parse`. The wizard is part of the editor: it is off (`404`) unless `http.config_editor` is on. Turning inject on afterwards is a separate edit; follow the [inject checklist](CONFIG.md#inject-checklist).

## Custom dashboards

`/dashboards.html` builds dashboards from read-only widgets. Each user has their own (at most 20, with at most 24 widgets each), kept by the storage plugin (`sqlite`, table `dashboards`). Widgets read endpoints the viewer role can already read: readiness, providers, prefixes, improvements, decisions, provider usage, inbound steers, threat mitigation, anomalies, POPs, HA, report subscriptions, and any stored report with a range in days. A widget can span the full row.

API: `GET /api/dashboards` returns `widget_types`, the report list, and your dashboards; `PUT /api/dashboards/<name>` with `{"title": "...", "widgets": [{"type": "providers"}, {"type": "report", "report": "summary", "days": 7, "wide": true}]}` saves one (unknown widget types, unknown reports, and unknown fields are refused); `DELETE /api/dashboards/<name>` removes it. Deleting a user deletes that user's dashboards.

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

Remove `improvement_weights`, `http.config_editor`, and `report_subscriptions` and restart. The dashboard polish (#49) needs no rollback: it reads the same state, and `/api/overview` is read-only. The file config works exactly as before; the editor only ever wrote a plain YAML file. Stored dashboards stay in the database and are ignored by an older build.
