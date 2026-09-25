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
                    inject:  announce via ExaBGP/GoBGP iBGP
```

## Components

- **Probe worker** sources packets out each configured provider (dedicated probe address or policy-routed source). Compares the same destination across providers.
- **RIB view** (`internal/rib`) is an embedded GoBGP speaker with iBGP sessions to the edge routers. It learns their best paths and maps each prefix to its next-hop and provider (via `providers[].next_hop`). It offers exact, longest-prefix-match, and covering lookups. It is learn-only: the global export policy rejects everything and graceful restart is never enabled. When all sessions are down it reports not-ready and drops the learned routes, so consumers stop acting on stale data. Injection may only steer prefixes already in this view. Add-path and BMP come later (#26).
- **Decision engine** (`internal/policy`): a pure function `Decide(state, input, config, scorer, now)` that runs after every probe round. The scorer plugin (default `weighted`) ranks the providers for each prefix. A new improvement needs:
  - a native exit from the RIB (exact prefix)
  - usable, fresh measurements for the native provider and the candidate
  - a gain beyond `thresholds` (loss delta, or equal-or-better loss plus an RTT delta), and a lower score
  - room under `max_improvements` (biggest gains win when the cap binds)
  - no active cooldown
  - in inject mode, an allowlisted prefix

  An improvement is kept for at least `hold_time`. After that it flips back when the native path is better again, and a flip-back starts a `hold_time` cooldown so the prefix cannot flap. It switches to a clearly better alternative, and it retires after `improvement_ttl` so the native path gets re-measured. It is retired immediately, ignoring hold time, when its provider goes down or its data goes stale, when the provider is excluded or the prefix leaves the allowlist or the probe set, or when the RIB is not ready (BGP session lost). While an improvement is active the router stops advertising the native path to Packeteer (iBGP never reflects a route back to where it came from), so the native provider is taken from the improvement record rather than from the RIB.
- **Announcer** speaks BGP to the edge as an iBGP peer. Injected routes use a higher local-pref (or community the edge maps to local-pref) and a Packeteer community. Edges must not re-advertise those more-specifics to eBGP peers.

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
