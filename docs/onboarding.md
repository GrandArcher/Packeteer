# Onboarding: install, first run, and preflight checks

This takes a Linux host with Docker to a verified first injection without hand-writing YAML. Everything before the last step runs in `mode: observe` and announces nothing. Lab use first: run it against a lab edge, never a production router you have not read.

## One-command install

`scripts/install.sh` needs Linux, Docker, and curl. It downloads `config.example.yaml` (observe) into `./packeteer`, runs `-check` on it, starts the stock image with host networking and `NET_RAW` and `NET_ADMIN`, waits for `/healthz` and for the first admin to be bootstrapped (HTTP can answer before sign-in is ready, #328), and prints where to sign in.

```
sh scripts/install.sh
PACKETEER_VERSION=0.8.0 PACKETEER_DIR=/srv/packeteer sh scripts/install.sh
```

An existing `config.yaml` is kept. An existing container named `packeteer`, running or stopped, stops the script. Nothing in it turns inject on. `PACKETEER_ADMIN_PASSWORD` sets the first admin password; otherwise the generated one is printed ([auth.md](auth.md#first-run)). The first sign-in opens the setup wizard ([ui.md](ui.md#setup-wizard)).

## Preflight checks

Settings has a Preflight checks panel with a Run checks button. `GET /api/preflight` returns the last result, `POST /api/preflight/run` runs the checks now. A run reads the BGP sessions, the learned RIB, and the leak watch, and sends one TTL-limited probe per provider toward a documentation address. It announces nothing and writes no config. Each result has a status, a detail, and, unless it passed, a fix in plain words.

| Check | Fails when |
|---|---|
| `bgp_session` | no neighbor is configured, a session is not established, or no routes are learned. Fewer than 10 learned prefixes is a warning. |
| `import_filter` | the leak watch holds a prefix. Otherwise it is unverified until an administrator confirms (see below). |
| `probe_egress` | a provider's probe leaves through an address other than its `next_hop`, or gets no answer. A provider that cannot be checked (loopback source, `path_check: false`) is a warning. |
| `timers` | the negotiated hold time is zero or graceful restart is on for the Packeteer session. A hold time over 180 s is a warning. |
| `withdrawal` | no announcer is configured, or a session would keep Packeteer's routes after a crash: hold time zero or over 180 s, or graceful restart on. |

Observe mode announces nothing, so Packeteer cannot test the router's filters itself. `import_filter` therefore asks an administrator to read the router (the import policy from Packeteer accepts only `packeteer_community`, and every eBGP neighbor's outbound policy rejects it) and press Confirm (`POST /api/preflight/confirm {"id":"import_filter"}`, admin, audited). The confirmation is tied to the AS number, the community, and the neighbors, and ends when one of them changes. A leak seen by the leak watch fails the check whatever was confirmed. `withdrawal` checks configuration and the negotiated hold time: a stopped Packeteer withdraws at once, and a crash drops its routes within the hold time. It does not inject a test route, which would announce in observe mode.

Failing and unverified checks block turning inject on through Settings or the API (the guided step and `PUT /api/config`). A warning does not. Editing the mounted file by hand and restarting skips the checks.

## Turning injection on

While any check blocks, the wizard's inject step is hidden, `POST /api/config/inject` answers `412` with code `preflight_required` and the report, and a save through `PUT /api/config` that changes the mode to `inject` is refused the same way. A save that changes the AS number, the community, or the neighbors and turns inject on in the same edit is refused with code `setup_changed`: the checks and the confirmation describe the running setup. Once the checks pass, the step takes a small allowlist (up to 10 prefixes) and an improvement cap (default 5, at most 50), and `POST /api/config/inject` returns the YAML, a diff, and a plain list of what changes. It adds `local_pref` when missing and needs the `announcer` to be in the config already. Nothing is written: the YAML opens in the editor and the save asks for the usual inject confirmation ([CONFIG.md](CONFIG.md#inject-checklist)). A listed prefix that the learned RIB does not hold is flagged and is never announced.

An instance whose config has an `ixp` block has no preflight: IXP mode never announces.

## Blast-radius preview

Settings has a Blast radius panel, and `GET /api/blast` returns the same report. It decides the latest probe round again under `inject` on a copy of the decision state (`Engine.WhatIf`), so it uses the real `Decide` path with your allowlist, cap, hold time, and thresholds. It lists the routes inject would add, move, and withdraw compared with what is on the wire now, the traffic each provider gains and loses (from a flow source when one is configured, otherwise the route is counted as unknown), and warnings: a provider over its interface capacity limit or its commit, `max_improvements` reached, better paths outside the allowlist, an empty allowlist, allowlist prefixes with stale or no measurements, and decided routes the announcer would refuse (leak-watch hold, inbound or mitigation reservation, not in the learned RIB). It announces nothing, changes no state, and works in observe mode. The guided inject step shows it for the inject config before you save.

A change that applies online and can alter announcements (`mode`, `thresholds`, `hold_time`, `improvement_ttl`, `flap_quarantine`, `max_improvements`, `allowlist`, `policies`, `sources`) is previewed first. `PUT /api/config` with `dry_run: true` writes nothing and returns the preview and a `preview_token`; the save needs `dry_run: false` and that token, from the same file revision and YAML, or it answers `428` (`preview_required`). Settings does this for you and shows an Apply button. Other changes skip it. A reload from SIGHUP or a settings push cannot ask, so it logs the add, move, and withdraw counts and warning codes before it applies. The preview keeps the current policy and source results, so a change to `policies` or `sources` shows its effect after the next round (a warning says so). Inbound and mitigation steers are not in the preview. Before the first decision round the preview answers `409` and a gated save cannot be confirmed; to change the file then, edit it and send SIGHUP (the reload logs the counts) or restart. Preview tokens are signed with a key made at start and good for 10 minutes, so a restart or a late Apply needs a new preview. `GET /api/blast` needs the operator role because each call reads the flow and interface sources. Nothing here enables inject.

Rollback: the preview adds no config key and changes no announcement. To drop the confirmation step, revert the `configGate` call in `PUT /api/config` (`internal/httpapi/ui.go`); until then, API clients that save an announcing change must send `dry_run` first. A save that was confirmed is reverted like any config edit.

## Replay history

Observe mode shows what it would do, but not what a different setting would have done. `packeteer whatif` decides stored decision rounds again with the real `Decide`, under the running config and, with `-config`, a second config, and prints what differs:

```
docker exec packeteer packeteer whatif -base /etc/packeteer/config.yaml -config /tmp/new.yaml -from 24h
```

It needs `storage: {type: sqlite, config: {round_retention: 24h}}` ([CONFIG.md](CONFIG.md#storage-sqlite)); rounds from before that was set are not kept. `-from` and `-to` are RFC 3339 times or durations ago (default the last 24 hours up to now); `-json` prints the result as JSON. `-base` defaults to `PACKETEER_CONFIG`.

Each config's report lists the moves it makes (new, switched, retired), the loss and RTT change per move weighted by the prefix volume when a flow source reported one (the mean per move otherwise, and moves without a volume are counted), traffic moved, commit relief (the volume of the moves made for a commit), flaps, flap quarantines, and how many prefixes and rounds `max_improvements` held back. With two configs it also lists each prefix the two steer differently. Replaying the running config over rounds recorded under it reproduces the live decisions when the window starts with no improvements standing, no reload falls inside it, no round was dropped (the log warns when the store is failing), and the leak watch did not change between the decision and the recording of a round. Every probe round and every evaluation that made a change is kept, so `confirm_rounds` counts the same rounds; a RIB change that changed nothing is kept at most twice per `probe.interval`.

Settings has a Replay history panel that sends the YAML in the editor and a window to `POST /api/whatif` (admin, needs auth; one replay runs at a time, at most two minutes). It works from observe-mode history and is read-only: the CLI opens the database read-only, and the replay has no announcer, so nothing is announced, withdrawn, or saved. It is an estimate:

- Every window starts with no improvements standing, so the first `hold_time` is decided without what was standing before it. A restart, a failover, or a reload inside the window is not modelled: the whole window runs under one config.
- Loss and RTT are those the probes measured on the chosen and native paths at the round of the move; the replay does not predict what the path will do after traffic moves.
- Synthesized sub-ranges, inbound steers, and mitigation rules are not replayed, and neither are an operator releasing a flap quarantine or verification backing out a move (#305): the replay decides every round itself.

## Router config

`packeteer -snippet <vendor>` prints the session and filter config for the configured edge and exits. The vendors are `frr`, `bird`, `junos`, `iosxr`, `arista`, and `mikrotik`. The Settings panel shows the same text (`GET /api/snippets?vendor=frr`, admin). The text is generated from the templates in `internal/snippet/templates` and the `asn`, `router_id`, `packeteer_community`, and neighbors in the config; it is never sent to a router. The FRR and BIRD output is loaded by real FRR and BIRD daemons in the `onboarding` CI job.

## Host policy routing

`packeteer -pbr linux` prints the `ip rule` and `ip route` lines for the providers ([policy-routing.md](policy-routing.md)). With `-apply` it compares them with the host and prints the commands that would change; nothing changes until `-yes` is added. After an apply it asks the kernel which way each provider's source leaves and fails if it is not the provider's `next_hop`. A rule is Packeteer's when its priority is 2001 to 2999 and its table is 1001 to 1999; those are removed when their provider is gone; other rules are never touched. In the container this needs `NET_ADMIN`, which the install already grants.

## Metrics

`/metrics` has `packeteer_preflight_ready`, `packeteer_preflight_check{check,status}` (1 on the current status), and `packeteer_preflight_last_run_timestamp_seconds` once the checks have run.

## Not in this release

Reading the router's filters and timers over its own management API (RouterOS, NETCONF, vtysh, birdc) is not built. The checks above read Packeteer's own view and one administrator confirmation.

## Rollback

Replay history (#204) changes no announcement. Set `round_retention` back to `0` and restart to stop storing rounds (stored rounds age out, or are deleted with the database). Revert the change to drop `whatif`, `/api/whatif`, and the Settings panel.

The install script, `-snippet`, `-pbr -apply`, and the preflight add no config key and change no router. Remove the container (`docker stop -t 30 packeteer && docker rm packeteer`) to undo the install. Undo an applied host policy routing with `ip rule del` and `ip route flush table <n>` for the lines `-apply` printed, or remove the provider from the config while another provider stays measured from this instance, and run `-pbr linux -apply -yes` again: it removes the rules and routes of the provider that is gone.
