# Plugins

Packeteer's core is small. The pieces that differ between deployments are **plugins** behind small Go interfaces. You select them by `type` in config:

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
```

Each entry has `type` (required), an optional `name` (defaults to the type and must be unique within its list), and an optional `config` block. The plugin decodes `config` itself, strictly: unknown fields are errors. **All plugins are built and validated at startup.** If a type is unknown or a config is invalid, Packeteer refuses to start and prints an error naming the entry, e.g. `notifiers[0] (nope): unknown notifier type "nope" (available: exec, webhook)`.

## Extension points (`pkg/plugin`)

| Kind | Interface | Built-ins (v0.1) | Out-of-process |
|---|---|---|---|
| `prober` | `Probe(ctx, ProbeRequest) (ProbeResult, error)` | `icmp`, `tcp`, `fixed` (labs) | `exec` |
| `source` | `Targets(ctx) ([]Target, error)` | `static`, flow (#5) | `exec` |
| `scorer` | `Score(PathStats) float64` (lower is better) | weighted (#7) | none |
| `announcer` | `Announce`, `Withdraw`, `WithdrawAll` | `gobgp` | **never** |
| `notifier` | `Notify(ctx, Event) error` | `webhook` | `exec` |

Metrics exporters are planned; for now Prometheus metrics are built into the ops surface (#9).

Probers return raw results (packets sent plus one RTT per reply). The core computes loss, RTT min/avg/max, and jitter the same way for every prober. A prober that cannot use its source address must return an error, not "100% loss", so the core can fail closed.

Announcers run **in-process only**, so an external process can never inject routes. They must withdraw everything on `Stop` and must not use BGP graceful restart.

## Lifecycle

1. **Factory (Init).** `func(cfg plugin.Config, env plugin.Env) (T, error)`. It decodes and validates config with `cfg.Decode(&myStruct)`. It must do no network I/O. `env` provides the instance name, a scoped `slog` logger, the plugin dir, and `Getenv`.
2. **`Start(ctx)`.** Begins background work in goroutines and must not block. Plugins start in this order: sources, probers, scorer, notifiers, announcer. If one fails, the ones already started are stopped.
3. **`Stop(ctx)`.** Releases everything before `ctx` expires. Plugins stop in reverse order, so the announcer stops first and routes are withdrawn early.

Embed `plugin.Base` for no-op `Start`/`Stop`.

### Built-in configuration

- `icmp`: `socket: auto|raw|udp` (default `auto`, which tries raw and then unprivileged datagram), `packet_interval` (default 100ms).
- `tcp`: `port` (default 443), `packet_interval` (default 100ms). A SYN-ACK or a RST both count as a reply.
- `fixed`: returns configured results and **sends no packets**. For labs and tests (`lab/`), not for measuring a transit. `paths: [{provider, sent?, rtt_ms?, loss_pct?, source_down?}]`, plus optional top-level `sent` and `rtt_ms`. `source_down: true` fails the probe source closed. `file` is re-read on every probe (same schema, without `file`) so a lab can flip results without a restart.
- `static`: `targets: [{prefix, host?, weight?}]`. `host` must be inside `prefix` and defaults to the first address.
- `exec`: see below.
- `webhook`: `url`, `timeout`, `headers`, `min_severity`.
- `gobgp`: no plugin config block. It publishes on the iBGP speaker the RIB view already opened. `local_pref`, `packeteer_community`, and `more_specific_bits` are top-level controller settings. Every route gets the community plus NO_EXPORT. The export policy accepts only Packeteer's own routes that carry the community. `Stop` withdraws them. Graceful restart is never turned on. Required, along with `local_pref`, when `mode: inject`.

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
