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
- **RIB view** learns which prefixes and next-hops already exist. Injection may only steer prefixes already in this view.
- **Policy engine** scores providers per prefix. Flips only after thresholds and hold time. Enforces max improvements and allow/deny lists.
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
