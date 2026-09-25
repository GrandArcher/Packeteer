# Architecture

```
flow/SNMP/static prefix list
        |
        v
   prefix picker  --->  probe worker (one source per upstream)
        |                      |
        |                      v
        |               samples: loss, rtt, jitter
        |                      |
        v                      v
   RIB view (iBGP/BMP) --> policy engine (score + hysteresis)
                                   |
                    observe: log only
                    inject:  gobgp announcer on the same iBGP session
```

## Components

- **Probe worker** sources packets out each configured provider (dedicated probe address or policy-routed source). Compares the same destination across providers. Each round has an overall deadline (the same window as stale measurements, about three intervals). A prober or target source that ignores cancellation is abandoned; the previous results stay, and the next round waits until that call returns.
- **Flow source** (`internal/plugins/source/flow`) is an optional target source. It listens for NetFlow v5/v9, IPFIX, and sFlow, keeps per-prefix byte counters for a sliding window (not the raw records), and offers the top prefixes to the probe engine. A destination is counted under its covering RIB prefix when the view is ready and that prefix is not a default route; otherwise it is aggregated to the configured length. The probe engine merges this set with the other sources and de-duplicates by prefix.
- **RIB view** (`internal/rib`) is an embedded GoBGP speaker with iBGP sessions to the edge routers. It records each neighbor's adj-RIB-in (the paths that neighbor advertised) and maps each prefix to its next-hop and provider (via `providers[].next_hop`). A route Packeteer injects can become this speaker's best path; that does not remove the prefix while a neighbor is still advertising it. When several neighbors advertise one prefix, the higher local preference wins. It offers exact, longest-prefix-match, and covering lookups. It is learn-only: the global export policy rejects everything and graceful restart is never enabled. The session proposes a 90s hold time so a dead peer cannot negotiate the timer off; a shorter timer from the router wins. When all sessions are down it reports not-ready and drops the learned routes, so consumers stop acting on stale data. One session going down drops only that neighbor's paths and leaves the view ready. Injection may only steer prefixes still present in this view. Add-path and BMP come later (#26).
- **Decision engine** (`internal/policy`): a pure function `Decide(state, input, config, scorer, now)` that runs after every probe round, on RIB changes, and on a staleness ticker (once per probe interval) so a round that never finishes still withdraws once measurements are older than the max result age. The scorer plugin (default `weighted`) ranks the providers for each prefix. A new improvement needs:
  - a native exit from the RIB (exact prefix)
  - usable, fresh measurements for the native provider and the candidate
  - a gain beyond `thresholds` (loss delta, or equal-or-better loss plus an RTT delta), and a lower score
  - room under `max_improvements` (biggest gains win when the cap binds)
  - no active cooldown
  - in inject mode, an allowlisted prefix

  An improvement is kept for at least `hold_time`. After that it flips back when the native path is better again, and a flip-back starts a `hold_time` cooldown so the prefix cannot flap. It switches to a clearly better alternative, and it retires after `improvement_ttl` so the native path gets re-measured. It is retired immediately, ignoring hold time, when its provider goes down or its data goes stale, when the provider is excluded or the prefix leaves the allowlist or the probe set, or when the RIB is not ready (every BGP session lost). While an improvement is active the router normally stops advertising the native path to Packeteer (iBGP does not send a route back to the peer it was learned from, and it does not send a non-best path), so that disappearance is not a withdraw and the native provider stays the one recorded on the improvement. If the neighbor keeps advertising the prefix for 5s after the improvement is active and then withdraws it, the improvement is retired immediately and a `hold_time` cooldown blocks re-injection. That is the case when the native path stays best (the lab network statement) or the router is configured to keep sending it (`advertise-best-external`). A provider withdraw that happens only after the native path is already hidden is not visible on a single-path session; `improvement_ttl` is the backstop until add-path or BMP (#26).
- **Announcer** (`internal/announce` + the `gobgp` plugin) publishes inject-mode improvements on the RIB view's existing iBGP session. It does not open a second session. Each route uses the chosen provider's next hop, the configured `local_pref`, `packeteer_community`, and NO_EXPORT. The announced prefix is the exact prefix in the learned RIB; Packeteer does not synthesize more-specifics, and a config that sets `more_specific_bits` is rejected. The export policy accepts only local routes that carry the Packeteer community, so learned routes are never reflected. Observe and suggest never call the announcer. A prefix is announced only when it is in the learned RIB. A route already on the wire is kept or moved while the decision engine still wants it, including when the router has hidden the native path; it is withdrawn when the engine retires the improvement (confirmed RIB leave, flip-back, expiry, a dead probe source, stale measurements, RIB session loss) and on shutdown. Graceful restart stays off. Edges must accept only the Packeteer community and must not export it to eBGP ([docs/routers.md](docs/routers.md)).

## Plugins

Every component above sits behind a small interface in `pkg/plugin`, selected by `type` in config: probers, target sources, scorer, announcer (router driver), and notifiers. Built-ins register through `init()` under `internal/plugins/<kind>/<name>`. `internal/pluginhost` builds and validates the configured set at startup and runs its Start/Stop lifecycle. Out-of-process `exec` plugins (JSON over stdin/stdout) and the `webhook` notifier extend the stock container without recompiling. Announcers are in-process only. See [docs/PLUGINS.md](docs/PLUGINS.md).

```
config ──> pluginhost.Build ──> sources ─┐
                                probers ─┼─> core (stats, RIB view, decisions) ─> announcer
                                scorer  ─┘                       └──> notifiers
```

## Modes

- `observe` — probe and score, write decisions to logs/metrics, announce nothing
- `suggest` — same as observe, plus a decision feed (file/API)
- `inject` — announce allowlisted improvements

## Out of scope for M0–M3

Inbound prepends, commit/95th control, IX peer selection, FlowSpec, multi-POP routing domains.
