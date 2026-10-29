# Writing a plugin

How to write a Packeteer plugin and where to share it. [PLUGINS.md](PLUGINS.md) is the reference for every kind, config key, and wire message; this page is the path through it. Finished plugins by other people are listed in [COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md).

## Pick a delivery

| | `exec` | `grpc` | compiled in |
|---|---|---|---|
| Kinds | prober, source, notifier | prober, source, notifier | every kind in [PLUGINS.md](PLUGINS.md#extension-points-pkgplugin) |
| Language | anything that reads stdin and writes stdout, including POSIX `sh` | Go helper in `pkg/plugin/rpc`; the contract is [plugin.proto](../pkg/plugin/rpc/plugin.proto) | Go |
| Process | started for every call | started once, health-checked, restarted | inside the controller |
| State between calls | none | kept in the process | kept in the object |
| Stock image | yes: mount the file or binary into the plugin dir | yes: mount a static binary | no: you build your own image, or send the plugin upstream |

Start with `exec`: it needs no build and no Packeteer code. Move to `grpc` when each call is too slow to start a process for, or the plugin must keep a connection or a cache. Compile in only what must run in-process.

Announcers, RIB sources, leak sources, RPKI and IRR sources, detectors, electors, and federation are compiled in only, because what they return can add or end a route. No out-of-process plugin can announce; `exec` and `grpc` are not registered for those kinds, and a config that names them there is refused at start.

## Interfaces

All kinds are in [pkg/plugin](../pkg/plugin). The three out-of-process kinds are:

| Kind | Method | Returns |
|---|---|---|
| prober | `Probe(ctx, ProbeRequest)` | `ProbeResult`: packets sent and one RTT per reply. The core computes loss, RTT, and jitter. |
| source | `Targets(ctx)` | `[]Target`: a prefix, an optional host inside it, an optional weight |
| notifier | `Notify(ctx, Event)` | an error or nil |

Rules that hold for every plugin:

- A prober binds to `ProbeRequest.Source`. If it cannot use the source, or cannot apply a non-zero `Mark` or `DSCP`, it returns an error (`plugin.ErrSourceUnavailable` in Go), never a 100% loss result. The core then treats the probe source as down and withdraws.
- A source only names what to measure. It does not decide what is announced: the core still requires the prefix in the learned RIB view and in the allowlist.
- A notifier is told about events and cannot change the controller. Do not block in `Notify`; the core gives each notifier its own bounded queue, and a full queue drops events for that notifier only.
- Secrets arrive through the `env` mapping in the plugin's config (`${VAR}` is expanded from Packeteer's environment). Never put one in `config`, a log line, or an error message.

## Lifecycle

1. **Init.** The factory decodes and validates `config` strictly: an unknown key is an error. It does no network I/O. Packeteer refuses to start when it fails, and says which entry (`probers[1] (fast): ...`). For `exec`, the same check is the `init` call; for `grpc`, `Init`. The config editor and `-check` runs do not start your program.
2. **Start.** Begin background work in goroutines and return.
3. **Calls.** Probe, Targets, or Notify, each with a context that carries the timeout.
4. **Stop.** Release everything before the context expires.

Details and timeouts: [Lifecycle](PLUGINS.md#lifecycle), [exec protocol](PLUGINS.md#protocol-packeteer-execv1), [grpc lifecycle](PLUGINS.md#grpc-plugins-long-running).

## Start from a skeleton

Each skeleton in [examples/plugins](../examples/plugins) has a test that runs it.

| Skeleton | Delivery | Test |
|---|---|---|
| [static-targets.sh](../examples/plugins/static-targets.sh) | `exec` source | `TestExampleScript` in `internal/plugins/exec` |
| [exec-prober.sh](../examples/plugins/exec-prober.sh) | `exec` prober, fails when asked to tag packets | `TestExampleProberScript` in `internal/plugins/exec` |
| [grpc-example](../examples/plugins/grpc-example/main.go) | `grpc` prober, source, and notifier in one binary | `TestExamplePlugin` in `internal/plugins/grpcplugin` |
| [go-prober](../examples/plugins/go-prober/prober.go) | compiled-in prober | `prober_test.go` next to it |

Copy one, rename it, and keep the shape of its test.

### `exec`

Mount the script and select it:

```sh
docker run ... -v "$PWD/plugins:/etc/packeteer/plugins:ro" ghcr.io/grandarcher/packeteer:edge
```

```yaml
probers:
  - type: exec
    name: mine
    config:
      command: exec-prober.sh
```

To test it without a Packeteer build, pipe a request to it:

```sh
echo '{"protocol":"packeteer-exec/v1","kind":"prober","method":"probe","name":"mine","params":{"provider":"transit-a","source":"192.0.2.11","target":"198.51.100.1","count":3,"timeout_ms":1000}}' | ./exec-prober.sh
```

### `grpc`

Build a static binary and mount it into the plugin dir. The image is alpine, so a dynamically linked glibc binary will not run.

```sh
CGO_ENABLED=0 go build -o plugins/mine ./path/to/your/plugin
```

### Compiled in

Packages under `internal/` cannot be imported from another module, so a compiled-in plugin lives in a fork of this repository (or is sent here as a PR). Copy `go-prober` to `internal/plugins/<kind>/<name>`, change `TypeName`, and add a blank import for it to `internal/plugins/all/all.go`. Register the factory from `init()` in the registry for its kind (`plugin.Probers`, `plugin.Sources`, `plugin.Notifiers`, and so on). A duplicate type name panics at start.

## Test it

- Unit-test the factory: a valid config, an unknown key, and each out-of-range value must each give the error you expect.
- Test the plugin through the real framing: run the script with the `exec` plugin (copy `TestExampleProberScript`), or build the binary and start it with the `grpc` plugin (copy `TestExamplePlugin`).
- Test the failure paths: an unusable source, a tagged request you cannot honor, a context that is already canceled, and a timeout.
- Use documentation prefixes and ASNs only: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, and ASNs 64496-64511 or 65536-65551. Never commit real prefixes, next hops, or secrets.
- Run the image with `-check` on a config that selects your plugin ([README.md](../README.md#install)). It validates every plugin config and starts no program.
- A compiled-in plugin that is sent upstream also needs the checks in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Safety rules

These come from [AGENTS.md](../AGENTS.md) and apply to a plugin you share too.

- The default mode is `observe`. A plugin never turns on `inject` and never needs it to work.
- Nothing is announced that is not in the learned RIB view and the allowlist. Out-of-process plugins have no way to announce.
- A plugin that affects routing (compiled in only) must keep: the configured community and NO_EXPORT on every route, the `max_improvements` cap, hold time and hysteresis, a withdraw of everything on shutdown, SIGTERM, probe-source failure, stale data, and loss of the RIB session, and no BGP graceful restart.
- Fail closed: an error that makes a measurement untrustworthy is returned as an error, not turned into a good-looking number.

## Share it

Publish the plugin in its own repository with a license, a README that shows the config block and the Packeteer version you tested, and tests that need no real network. Then add a row to [COMMUNITY_PLUGINS.md](COMMUNITY_PLUGINS.md) by PR. A test checks every row, including that an `exec` or `grpc` plugin is a prober, source, or notifier and is listed as not affecting routing.

A plugin you think belongs in the main image, with no outside dependency, can be proposed as an issue first. Built-ins follow [CONTRIBUTING.md](../CONTRIBUTING.md): one issue per PR, tests, docs, and a `config.example.yaml` that stays in `observe`.
