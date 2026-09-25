# Plugins

Packeteer's core is small. The pieces that differ between deployments are **plugins** behind small Go interfaces. You select them by `type` in config. Every key is listed in [CONFIG.md](CONFIG.md).

```yaml
plugin_dir: /etc/packeteer/plugins   # default; env PACKETEER_PLUGIN_DIR overrides it
probers:                             # ordered: later ones are fallbacks
  - type: icmp
  - type: tcp
sources:
  - type: static
    config: { ... }
  - type: exec
    name: cmdb
    config:
      command: cmdb-targets.sh
notifiers:
  - type: webhook
    config:
      url: https://hooks.example.invalid/packeteer
      headers:
        Authorization: "Bearer ${HOOK_TOKEN}"   # read from the container env
      min_severity: warning
announcer:
  type: gobgp
telemetry:                           # optional; does not announce
  - type: snmp
    config:
      hosts:
        - name: edge1
          address: 192.0.2.254
          version: 2c
          community_env: PACKETEER_SNMP_COMMUNITY
      providers:
        - name: transit-a
          host: edge1
          interface: ether1
          commit_mbps: 1000
          billing_day: 1
          percentile: greater_separate
```

Each entry has `type` (required), an optional `name` (defaults to the type and must be unique within its list), and an optional `config` block. The plugin decodes `config` itself, strictly: unknown fields are errors. **All plugins are built and validated at startup.** If a type is unknown or a config is invalid, Packeteer refuses to start and prints an error naming the entry, e.g. `notifiers[0] (nope): unknown notifier type "nope" (available: exec, webhook)`.

## Extension points (`pkg/plugin`)

| Kind | Interface | Built-ins | Out-of-process |
|---|---|---|---|
| `prober` | `Probe(ctx, ProbeRequest) (ProbeResult, error)` | `icmp`, `tcp`, `udp`, `fixed` (labs) | `exec` |
| `source` | `Targets(ctx) ([]Target, error)` | `static`, `flow`, `traceroute`, `vip`, `outage` | `exec` |
| `scorer` | `Score(PathStats) float64` (lower is better). `commit` also plans commit and group moves | `weighted`, `commit` | none |
| `announcer` | `Announce`, `Withdraw`, `WithdrawAll` | `gobgp` | **never** |
| `notifier` | `Notify(ctx, Event) error` | `webhook` | `exec` |
| `telemetry` | `Snapshot(ctx) ([]Usage, error)` | `snmp` | none |

Metrics exporters are planned; for now Prometheus metrics are built into the ops surface (#9). Interface usage from the `snmp` telemetry plugin is on `/api/telemetry` and in `packeteer_telemetry_*` gauges. The `commit` scorer reads that snapshot and per-prefix flow volume. The telemetry plugin does not announce.

Probers return raw results (packets sent plus one RTT per reply). The core computes loss, RTT min/avg/max, and jitter the same way for every prober. A prober that cannot use its source address must return an error, not "100% loss", so the core can fail closed.

Announcers run **in-process only**, so an external process can never inject routes. They must withdraw everything on `Stop` and must not use BGP graceful restart.

## Lifecycle

1. **Factory (Init).** `func(cfg plugin.Config, env plugin.Env) (T, error)`. It decodes and validates config with `cfg.Decode(&myStruct)`. It must do no network I/O. `env` provides the instance name, a scoped `slog` logger, the plugin dir, and `Getenv`.
2. **`Start(ctx)`.** Begins background work in goroutines and must not block. Plugins start in this order: sources, probers, scorer, telemetry, notifiers, announcer. If one fails, the ones already started are stopped.
3. **`Stop(ctx)`.** Releases everything before `ctx` expires. Plugins stop in reverse order, so the announcer stops first and routes are withdrawn early.

Embed `plugin.Base` for no-op `Start`/`Stop`.

### Built-in configuration

- `icmp`: `socket: auto|raw|udp` (default `auto`, which tries raw and then unprivileged datagram), `packet_interval` (default 100ms).
- `tcp`: `port` (default 443), `packet_interval` (default 100ms). A SYN-ACK or a RST both count as a reply. A middlebox RST is not distinguishable from the target's RST, because the kernel only reports `ECONNREFUSED`. A firewall that rejects with `tcp-reset` can look like a healthy path.
- `udp`: `port` (default 33434), `packet_interval` (default 100ms). A UDP reply counts. An ICMP destination-unreachable counts only when the error-queue offender is the target, so a firewall `REJECT` with icmp-port-unreachable is loss rather than a low-latency success. The kernel reports that on the connected socket, so this prober does not need a raw socket. The offender check is Linux-only; the container image is Linux. It is not in the default chain; add it after `tcp` when you want that fallback.
- `fixed`: returns configured results and **sends no packets**. For labs and tests (`lab/`), not for measuring a transit. `paths: [{provider, sent?, rtt_ms?, loss_pct?, source_down?}]`, plus optional top-level `sent` and `rtt_ms`. `source_down: true` fails the probe source closed. `file` is re-read on every probe (same schema, without `file`) so a lab can flip results without a restart.
- `static`: `targets: [{prefix, host?, weight?}]`. `host` must be inside `prefix` and defaults to the first address.
- `traceroute`: discovers the probe host for each configured prefix. `targets` is required (`prefix`, optional `host` inside the prefix, optional `weight`). `max_hops` (default 16, 1–64), `probes` per hop (default 3, 1–10), `min_replies` (default 2, or `probes` when that is smaller; a hop is stable only when one address answers at least this many times and there is no tie), `timeout` per probe (default 500ms, max 5s; zero uses the default), `port` (default 33434), `source` (optional local address; empty uses the default route), `interval` (default 5m, 1s–24h), `budget` (default 10s, at least `timeout`, at most 30s). Discovery runs in the background. `Targets` returns the last cache immediately and never traces, so a slow hop cannot consume the probe round. `budget` caps one pass; each target gets an equal share. The default budget is under the default round deadline (about 110s). When the configured host answers, it stays the probe host. Otherwise the highest stable TTL is used, which is the responsive hop closest to the destination. Three silent hops after a stable one end the trace. Loopback, link-local, multicast, and unspecified answers are ignored unless they are the destination. The prefix on the target does not change, and the discovered address is not announced. If `source` is set and that address cannot be bound before any cache exists, the source fails for the round and the other sources continue. The socket calls are Linux-only; other systems still compile.
- `vip`: prefixes and ASNs probed on their own interval. `interval` is required (at least 1s) and must be shorter than the staleness window or the controller will not start. `max_targets` (default 100, 1–10000) caps configured prefixes plus ASN matches; truncation is logged, and the expansion is cached until the RIB generation changes. At least one of `prefixes` (`prefix`, optional `host` inside it) or `asns` (non-zero, no duplicates) is required. A default route is rejected. Configured prefixes are always returned, and the prefix list itself cannot exceed `max_targets`. ASN entries expand to learned prefixes whose AS path contains a listed ASN, and only while the RIB view is ready. The same prefix from another source keeps that source's host. A later interval wins only when it is shorter; an unset interval means `probe.interval`, so a longer VIP interval does not slow a prefix static or flow already listed. The global probe rate limit applies. This source does not announce.
- `outage`: correlates completed probe rounds by learned AS path and by provider. `min_prefixes` (default 3, minimum 2) and `window` (default 2m) are the pattern. A sample is degraded when the probe failed, loss is at least `loss_pct` (default 20; zero keeps that default), or average RTT is at least `rtt_ms` when that is set (zero disables the RTT check). The newest in-window sample wins. An ASN is sick when enough degraded prefixes contain it and every measured provider for those prefixes is degraded. A prefix that is healthy on another provider counts toward that provider's circuit instead, unless a sick ASN already explains it. With one provider in the window, mixed destinations still open a circuit and a shared ASN is not opened twice. `ignore_asns` skips ASNs that sit on every path. On a new incident the source returns the affected prefixes with `interval` (default 5s) and marks them urgent for one round; the probe loop wakes immediately. An AS incident also includes other learned prefixes whose path contains the ASN, up to `max_targets` (default 100), degraded ones first. A circuit incident then adds other prefixes sampled on that provider and learned prefixes whose native exit is that provider, under the same cap. A default route is never added. Events are `outage.as` and `outage.circuit` (`critical`) and `outage.cleared` (`warning`). The controller delivers them to the configured notifiers without blocking the probe loop. `interval` must be shorter than `probe.interval` and the staleness window. This source is read every round. It does not announce. AS matches wait until the RIB is ready. The global probe rate limit applies.
- `flow`: UDP collector for NetFlow v5, NetFlow v9, IPFIX, and sFlow v5. Off unless the source is listed. `listen` (required, one `host:port` or a list), `window` (default 5m), `top_n` (default 100), `min_bytes` (default 0), `aggregate_v4` / `aggregate_v6` (default 24 and 48), `exclude` (prefixes to ignore). Each destination is summed over the window and mapped to the covering prefix in the RIB view when that view is ready and the match is not a default route; otherwise it is aggregated to `aggregate_v4` or `aggregate_v6`. The probe host is a destination that contributed bytes inside the prefix. `weight` is the byte total. The same window is exposed as a per-prefix rate (bytes × 8 / window, decimal megabits per second) for the `commit` scorer, including prefixes that `top_n` or `min_bytes` left off the probe list. Private, ULA, loopback, link-local, and multicast addresses are dropped. Raw records are not stored. Each time bucket keeps at most 20000 prefixes. NetFlow v9/IPFIX templates are kept in memory per exporter address and observation domain (capped) and are not written out. With `--network host` the listen ports are host ports; do not publish them. Firewall UDP to the exporter. See [mikrotik.md](mikrotik.md) and [routers.md](routers.md).
- `weighted`: `loss_weight`, `rtt_weight`, `jitter_weight`. Lower score is better. This is the default scorer. It does not move traffic for commit.
- `commit`: performance score with the same weights, plus commit control and group balancing. `loss_override` (default false) is the only way a commit move may increase loss. `balance` is `off` (default), `equal`, or `proportional`. `balance_slack` (default 0.10), `max_age` (default 15m), `min_mbps` (default 0). Provider `group`, `precedence`, and `cc_disable` are on the provider, not in this block. Improvements are tagged `performance` or `commit` and share `max_improvements`. The scorer does not announce. See [CONFIG.md](CONFIG.md).
- `exec`: see below.
- `webhook`: `url`, `timeout`, `headers`, `min_severity`.
- `gobgp`: no plugin config block. It publishes on the iBGP speaker the RIB view already opened. `local_pref` and `packeteer_community` are top-level controller settings. Each route is the exact prefix learned from the RIB; a config that sets `more_specific_bits` is rejected. Every route gets the community plus NO_EXPORT. The export policy accepts only Packeteer's own routes that carry the community. `Stop` withdraws them. Graceful restart is never turned on. Required, along with `local_pref`, when `mode: inject`.
- `snmp`: polls `ifHCInOctets` and `ifHCOutOctets` (or the 32-bit octet counters when the 64-bit ones are absent) and tracks 95th-percentile usage for the open UTC billing period. `percentile` is `separate` (inbound and outbound 95ths kept apart), `greater` (95th of max(in, out) per sample), or `greater_separate` (the greater of the two 95ths). The community and v3 passphrases are environment variables named by `community_env`, `auth_env`, and `priv_env`. They are not config values. A failed poll keeps the samples already stored. The plugin does not announce. The `commit` scorer is what spends the snapshot. See [CONFIG.md](CONFIG.md).

## Writing a Go plugin (compiled in)

```go
package myprober

import "github.com/GrandArcher/Packeteer/pkg/plugin"

type Config struct{ Port int `yaml:"port"` }

type Prober struct{ plugin.Base; port int }

func init() {
	plugin.Probers.Register("myprober", func(c plugin.Config, e plugin.Env) (plugin.Prober, error) {
		var cfg Config
		if err := c.Decode(&cfg); err != nil {
			return nil, err
		}
		return &Prober{port: cfg.Port}, nil
	})
}
```

Built-ins live under `internal/plugins/<kind>/<name>` and are linked through `internal/plugins/all`. A third-party build blank-imports its package the same way.

## `exec` plugins (work with the stock image)

An `exec` plugin is any executable in the plugin dir: a static binary, a POSIX `sh` script (the image is alpine), or anything else you ship in a derived image.

```yaml
sources:
  - type: exec
    name: example
    config:
      command: static-targets.sh   # relative = inside plugin_dir; absolute paths allowed
      args: []
      timeout: 30s                 # per call (default 30s)
      env:                         # only PATH and these are passed; ${VAR} expands from Packeteer's env
        API_TOKEN: ${CMDB_TOKEN}
      config:                      # forwarded verbatim to the plugin
        site: lab
```

### Protocol `packeteer-exec/v1`

For **every call**, Packeteer starts the process, writes **one JSON request** to stdin, closes stdin, and reads **one JSON response** from stdout. Stderr is logged at debug level. Output is capped at 1 MiB. The call fails on a non-zero exit, on the timeout, or on `{"error": "..."}`. The process gets `PATH`, `PACKETEER_PLUGIN_KIND`, and the configured `env`, and nothing else from Packeteer's environment.

Request:

```json
{"protocol":"packeteer-exec/v1","kind":"source","method":"targets","name":"example","config":{"site":"lab"},"params":null}
```

Response: `{"result": ...}` or `{"error": "message"}`.

| kind | method | params | result |
|---|---|---|---|
| any | `init` | none | `{}`, or an error if the config is unacceptable. Called once at startup. |
| `prober` | `probe` | `{"provider","source","target","count","timeout_ms"}` | `{"sent": 10, "rtts_ms": [12.1, 11.8]}`, one RTT per reply, in send order |
| `source` | `targets` | none | `{"targets":[{"prefix":"198.51.100.0/24","host":"198.51.100.1","weight":1}]}` (`host` must be inside `prefix`; `host` and `weight` are optional) |
| `notifier` | `notify` | an event: `{"time","kind","severity","message","fields"}` | `{}` |

A minimal working example is in [examples/plugins/static-targets.sh](../examples/plugins/static-targets.sh).

Mount a plugin directory into the container:

```sh
docker run ... -v "$PWD/plugins:/etc/packeteer/plugins:ro" ghcr.io/grandarcher/packeteer:edge
```

### Security

- Relative commands cannot leave the plugin dir (`../` is rejected).
- Mount the plugin dir read-only. Treat plugins like any code you run as root in the container.
- Secrets reach plugins only through the explicit `env` mapping.

## Roadmap

- Long-running out-of-process plugins over gRPC ([hashicorp/go-plugin](https://github.com/hashicorp/go-plugin)), for probers that keep state or run at high rates.
- Exporter plugins (InfluxDB, OTLP).
- More notifiers: email, Slack, PagerDuty (a webhook already covers most of these).
