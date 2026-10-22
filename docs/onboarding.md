# Onboarding: install, first run, and preflight checks

This takes a Linux host with Docker to a verified first injection without hand-writing YAML. Everything before the last step runs in `mode: observe` and announces nothing. Lab use first: run it against a lab edge, never a production router you have not read.

## One-command install

`scripts/install.sh` needs Linux, Docker, and curl. It downloads `config.example.yaml` (observe) into `./packeteer`, runs `-check` on it, starts the stock image with host networking and `NET_RAW` and `NET_ADMIN`, waits for `/healthz`, and prints where to sign in.

```
sh scripts/install.sh
PACKETEER_VERSION=0.8.0 PACKETEER_DIR=/srv/packeteer sh scripts/install.sh
```

An existing `config.yaml` is kept. A running container named `packeteer` stops the script. Nothing in it turns inject on. `PACKETEER_ADMIN_PASSWORD` sets the first admin password; otherwise the generated one is printed ([auth.md](auth.md#first-run)). The first sign-in opens the setup wizard ([ui.md](ui.md#setup-wizard)).

## Preflight checks

Settings has a Preflight checks panel with a Run checks button. `GET /api/preflight` returns the last result, `POST /api/preflight/run` runs the checks now. A run reads the BGP sessions, the learned RIB, and the leak watch, and sends one TTL-limited probe per provider toward a documentation address. It announces nothing and writes no config. Each result has a status, a detail, and, unless it passed, a fix in plain words.

| Check | Fails when |
|---|---|
| `bgp_session` | no neighbor is configured, a session is not established, or no routes are learned. Fewer than 10 learned prefixes is a warning. |
| `import_filter` | the leak watch holds a prefix. Otherwise it is unverified until an administrator confirms (see below). |
| `probe_egress` | a provider's probe leaves through an address other than its `next_hop`, or gets no answer. A provider that cannot be checked (loopback source, `path_check: false`) is a warning. |
| `timers` | the negotiated hold time is zero or graceful restart is on for the Packeteer session. A hold time over 180 s is a warning. |
| `withdrawal` | no announcer is configured, or a session would keep Packeteer's routes after a crash (the `timers` failures). |

Observe mode announces nothing, so Packeteer cannot test the router's filters itself. `import_filter` therefore asks an administrator to read the router (the import policy from Packeteer accepts only `packeteer_community`, and every eBGP neighbor's outbound policy rejects it) and press Confirm (`POST /api/preflight/confirm {"id":"import_filter"}`, admin, audited). The confirmation is tied to the AS number, the community, and the neighbors, and ends when one of them changes. A leak seen by the leak watch fails the check whatever was confirmed. `withdrawal` checks configuration and the negotiated hold time: a stopped Packeteer withdraws at once, and a crash drops its routes within the hold time. It does not inject a test route, which would announce in observe mode.

Failing and unverified checks block injection. A warning does not.

## Turning injection on

While any check blocks, the wizard's inject step is hidden, `POST /api/config/inject` answers `412` with code `preflight_required` and the report, and a save through `PUT /api/config` that changes the mode to `inject` is refused the same way. A save that changes the AS number, the community, or the neighbors and turns inject on in the same edit is refused with code `setup_changed`: the checks and the confirmation describe the running setup. Once the checks pass, the step takes a small allowlist (up to 10 prefixes) and an improvement cap (default 5, at most 50), and `POST /api/config/inject` returns the YAML, a diff, and a plain list of what changes. It adds `local_pref` when missing and needs the `announcer` to be in the config already. Nothing is written: the YAML opens in the editor and the save asks for the usual inject confirmation ([CONFIG.md](CONFIG.md#inject-checklist)). A listed prefix that the learned RIB does not hold is flagged and is never announced.

An instance whose config has an `ixp` block has no preflight: IXP mode never announces.

## Router config

`packeteer -snippet <vendor>` prints the session and filter config for the configured edge and exits. The vendors are `frr`, `bird`, `junos`, `iosxr`, `arista`, and `mikrotik`. The Settings panel shows the same text (`GET /api/snippets?vendor=frr`, admin). The text is generated from the templates in `internal/snippet/templates` and the `asn`, `router_id`, `packeteer_community`, and neighbors in the config; it is never sent to a router. The FRR and BIRD output is loaded by real FRR and BIRD daemons in the `onboarding` CI job.

## Host policy routing

`packeteer -pbr linux` prints the `ip rule` and `ip route` lines for the providers ([policy-routing.md](policy-routing.md)). With `-apply` it compares them with the host and prints the commands that would change; nothing changes until `-yes` is added. After an apply it asks the kernel which way each provider's source leaves and fails if it is not the provider's `next_hop`. A rule is Packeteer's when its priority is 2001 to 2999 and its table is 1001 to 1999; those are removed when their provider is gone; other rules are never touched. In the container this needs `NET_ADMIN`, which the install already grants.

## Metrics

`/metrics` has `packeteer_preflight_ready`, `packeteer_preflight_check{check,status}` (1 on the current status), and `packeteer_preflight_last_run_timestamp_seconds` once the checks have run.

## Not in this release

Reading the router's filters and timers over its own management API (RouterOS, NETCONF, vtysh, birdc) is not built. The checks above read Packeteer's own view and one administrator confirmation.

## Rollback

The install script, `-snippet`, `-pbr -apply`, and the preflight add no config key and change no router. Remove the container (`docker stop -t 30 packeteer && docker rm packeteer`) to undo the install. Undo an applied host policy routing with `ip rule del` and `ip route flush table <n>` for the lines `-apply` printed, or remove the provider from the config while another provider stays measured from this instance, and run `-pbr linux -apply -yes` again: it removes the rules and routes of the provider that is gone.
