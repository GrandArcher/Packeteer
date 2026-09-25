# Configuration reference

Packeteer reads one YAML document. Unknown keys are errors. Durations use Go's form: `30s`, `15m`, `1h`, `500ms`. A bare `0` on a duration that has a default means "use the default", not "disable".

The field names below are the `yaml` tags on the controller structs in `internal/config` and on each plugin's config struct. `cmd/controller/configdoc_test.go` fails if a tag is missing from this file.

Load order:

1. `-config` (default `/etc/packeteer/config.yaml`, or `PACKETEER_CONFIG` when that variable is set and `-config` is omitted).
2. Defaults, then validation. On failure the process exits before it probes or opens a BGP session.
3. Environment overlays below, then validation again.

```sh
packeteer -check -config config.yaml
packeteer -version
```

`-check` builds and validates plugins, prints a summary, and exits. It sends no probes and opens no BGP session. `-version` prints `packeteer <version>` and does not read the config.

The image entrypoint is the same binary. Flags go after the image name.

## Top level

| Key | Default | Required | Meaning |
|---|---|---|---|
| `mode` | none | yes | `observe`, `suggest`, or `inject`. |
| `asn` | none | yes, non-zero | BGP ASN of this speaker. Neighbors are iBGP in this ASN. |
| `router_id` | none | yes | IPv4 address. IPv6 is rejected. |
| `packeteer_community` | empty | inject | RFC 1997 community `asn:value`. Each half is an integer 0–65535. Quote it in YAML (`"64512:666"`). |
| `local_pref` | 0 | inject | Local preference on every injected route. `0` is rejected in inject mode. Set it above the edge's native local preference. |
| `more_specific_bits` | unset | must be absent | Any value, including `0`, is an error. Packeteer announces the exact prefix it learned from the RIB. |
| `max_improvements` | 50 | no | Cap on active improvements. Integer from 1 to 10000. Biggest gains win when the cap binds. |
| `hold_time` | 0 | inject: positive | Minimum life of an improvement, and the cooldown after a flip-back or a confirmed RIB leave. `0` is legal in observe and suggest (a flip can happen on the next evaluation). Negative is an error. |
| `improvement_ttl` | `1h` | no | Retire an improvement after this long so the native path is measured again. A negative duration disables the TTL. `0` selects the default `1h`. |
| `thresholds` | zeros | inject: both positive | See below. With both deltas at `0`, the decision engine records no improvement in any mode. |
| `providers` | none | at least one | Probe sources and injection next hops. |
| `allowlist` | empty | inject: non-empty | Prefixes that may be injected. |
| `probe` | see below | no | Timing and concurrency. |
| `log` | `info` / `text` | no | Process log. |
| `http` | `127.0.0.1:8080` | no | Read-only dashboard, API, and metrics. |
| `bgp` | no neighbors | inject: at least one neighbor | iBGP sessions. |
| `plugin_dir` | `/etc/packeteer/plugins` | no | Directory for out-of-process plugins. |
| `probers` | `icmp`, then `tcp` | no | Ordered. Later entries run only when an earlier one errors. |
| `sources` | none | no | Probe targets. With none, the process starts and probes nothing. |
| `scorer` | `weighted` | no | One scorer. Lower score is better. |
| `announcer` | none | inject | In-process only. `type: gobgp` publishes on the RIB session. |
| `notifiers` | none | no | Events. A failure here does not withdraw routes by itself. |

`mode: observe` and `mode: suggest` use the same decision path and announce nothing. `suggest` is the checkpoint: read the log, the dashboard, and `/api/decisions` before you change `mode`. The allowlist is enforced only in `inject`.

### `thresholds`

| Key | Default | Bounds |
|---|---|---|
| `min_loss_delta_pct` | 0 | 0–100. Inject requires a value greater than 0. |
| `min_rtt_delta_ms` | 0 | Not negative. Inject requires a value greater than 0. |

A candidate wins when its score is lower and either loss improves by at least `min_loss_delta_pct`, or loss is no worse and average RTT improves by at least `min_rtt_delta_ms`.

### `providers`

| Key | Required | Meaning |
|---|---|---|
| `name` | yes | Unique. |
| `source_ip` | yes | Source address of probes. Unique across providers. Must be configured on the host. Same address family as `next_hop`. |
| `next_hop` | yes | BGP next hop used if this provider is selected. Also how a learned route is matched to a provider. |
| `exclude` | no | `true`: still probe, never select for an improvement. |

### `allowlist`

| Key | Meaning |
|---|---|
| `prefixes` | CIDRs with no host bits. Duplicates are errors. |

A learned prefix is eligible when it is equal to an entry or more specific and inside it. Packeteer still announces that learned prefix, not a prefix it invented. An entry of `198.51.100.0/24` allows `198.51.100.0/24` and `198.51.100.128/25` when the router advertised that exact prefix. It does not allow `198.51.0.0/16`.

### `probe`

| Key | Default | Bounds |
|---|---|---|
| `interval` | `30s` | Greater than `timeout`. Also the period of the staleness check. |
| `timeout` | `2s` | Per packet. Must be shorter than `interval`. |
| `packets` | 10 | 1–1000. |
| `workers` | 8 | 1–1024 concurrent probe runs. |
| `rate_limit_pps` | 100 | 1–100000 packets per second, global. |
| `per_target_concurrency` | 2 | 1–64 concurrent runs toward one destination host. |

A measurement older than `3 * interval + packets * timeout` is stale. That same duration is the deadline for one probe round. The decision loop also wakes every `interval`, so a round that never finishes still withdraws once results are stale.

### `log`

| Key | Default | Values |
|---|---|---|
| `level` | `info` | `debug`, `info`, `warn` (`warning` is accepted), `error`. |
| `format` | `text` | `text` or `json`. |

### `http`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8080` | `host:port`. Wrap IPv6 in brackets: `"[2001:db8::1]:8080"`. `""` disables the server. |

The server accepts GET and HEAD. It does not announce routes. With `--network host`, this address is on the host. Basic auth is not a key in the file; see the environment variables.

### `bgp`

| Key | Default | Meaning |
|---|---|---|
| `listen_port` | 0 | `0`: do not listen; Packeteer connects out. 1–65535: accept sessions. |
| `listen_addresses` | none | Local addresses to bind when listening. Each must be an IP address. |
| `neighbors` | none | Edge routers, iBGP, same ASN as `asn`. |

Each neighbor:

| Key | Default | Meaning |
|---|---|---|
| `address` | required | Peer IP. Duplicates are errors. |
| `port` | 179 | Remote TCP port. `0` means 179. 0–65535 at validation; `0` is replaced when the session is built. |
| `local_address` | unset | Optional source address of the TCP session. |
| `passive` | false | Wait for the router to connect. Requires `listen_port`. |
| `description` | empty | Log label. |

Packeteer proposes a hold time of 90 seconds and a keepalive of 30 seconds. The router's shorter hold time wins. A hold time of zero is never proposed. Graceful restart is not a config key and is never enabled. With no neighbors, the RIB view is off and decisions say ranking only: nothing is injected.

One established session is enough for the view to be ready. All sessions down drops the learned routes and withdraws injected routes.

### Plugin entries

`probers`, `sources`, and `notifiers` are lists. `scorer` and `announcer` are single objects.

| Key | Meaning |
|---|---|
| `type` | Required. Unknown types are errors. The error names the entry and the types that are registered. |
| `name` | Optional. Defaults to `type`. Must be unique within that list. |
| `config` | Optional object. The plugin decodes it and rejects unknown keys. |

## Environment

Set these in the container. They are not keys in the YAML file. `PACKETEER_HTTP_PASSWORD` is not written to the log.

| Variable | Effect |
|---|---|
| `PACKETEER_CONFIG` | Config path when `-config` is omitted. |
| `PACKETEER_PLUGIN_DIR` | When non-empty, replaces `plugin_dir`. |
| `PACKETEER_LOG_LEVEL` | When non-empty, replaces `log.level`. |
| `PACKETEER_LOG_FORMAT` | When non-empty, replaces `log.format`. |
| `PACKETEER_HTTP_LISTEN` | When non-empty, replaces `http.listen`. The value `off` disables HTTP. An empty value does not change the file. |
| `PACKETEER_HTTP_USER` | Basic auth user. Set together with the password, or set neither. |
| `PACKETEER_HTTP_PASSWORD` | Basic auth password. |

`${VAR}` expansion applies inside a webhook `url`, webhook `headers` values, and an `exec` plugin's `env` values. It is not applied to the rest of the file.

## Inject checklist

`mode: inject` is refused unless all of these hold:

- `allowlist.prefixes` is non-empty
- at least one `bgp.neighbors` entry
- `packeteer_community` is set and valid
- `local_pref` is non-zero
- `announcer` is set (`type: gobgp`)
- `hold_time` is positive
- both threshold deltas are positive
- `more_specific_bits` is absent

The `gobgp` announcer has no `config` keys. A config block with any key is an error. Each announced route carries the provider `next_hop`, `local_pref`, `packeteer_community`, and `no-export`. The export policy accepts only routes Packeteer originated that carry the community.

The shipped example stays `mode: observe`. Put an inject config only in the file you mount on a host you control.

## Plugins

Built-in types are listed in [PLUGINS.md](PLUGINS.md). Their `config` keys:

### Prober `icmp`

| Key | Default | Values |
|---|---|---|
| `socket` | `auto` | `auto` (raw, then unprivileged datagram), `raw`, `udp`. |
| `packet_interval` | `100ms` | Not negative. Spacing between echoes in one run. |

### Prober `tcp`

| Key | Default | Values |
|---|---|---|
| `port` | 443 | 1–65535. A SYN-ACK or a RST counts as a reply. |
| `packet_interval` | `100ms` | Not negative. |

### Prober `fixed`

Labs and tests only. Sends no packets.

| Key | Meaning |
|---|---|
| `file` | Re-read on every probe. Same schema as this block, without `file`. Larger than 1 MiB is an error. |
| `sent` | Packets sent when a path omits `sent`. Not negative. |
| `rtt_ms` | RTT used when a path omits `rtt_ms`. Not negative. |
| `paths` | One result per provider. |

Each path:

| Key | Meaning |
|---|---|
| `provider` | Required. Must match a provider `name`. Unique in the list. |
| `sent` | Not negative. |
| `rtt_ms` | Not negative. |
| `loss_pct` | 0–100. |
| `source_down` | `true` fails that probe source closed. |

At least one of `paths`, `sent` / `rtt_ms`, or `file` is required.

### Source `static`

| Key | Meaning |
|---|---|
| `targets` | List of prefixes to probe. |

Each target:

| Key | Meaning |
|---|---|
| `prefix` | Required CIDR, no host bits. Unique in the list. |
| `host` | Optional address inside `prefix`. Default is the first address of the prefix. |
| `weight` | Optional, not negative. |

### Source `flow`

Off unless this source is listed. NetFlow v5, NetFlow v9, IPFIX, and sFlow v5. Raw records are not stored.

| Key | Default | Bounds |
|---|---|---|
| `listen` | none | Required. One `host:port` or a list. Host is an IP address or empty. Duplicate addresses are errors. |
| `window` | `5m` | `1s`–`24h`. |
| `top_n` | 100 | 1–10000. |
| `min_bytes` | 0 | Drop prefixes under this byte total. |
| `aggregate_v4` | 24 | 1–32. Used when the RIB has no covering non-default prefix. |
| `aggregate_v6` | 48 | 1–128. |
| `exclude` | none | CIDRs to ignore, no host bits, no duplicates. |

With `--network host`, `listen` binds host UDP ports. Do not publish them. Each time bucket keeps at most 20000 prefixes.

### Scorer `weighted`

`score = loss_pct * loss_weight + rtt_ms * rtt_weight + jitter_ms * jitter_weight`.

| Key | Default | Bounds |
|---|---|---|
| `loss_weight` | 100 | Not negative. |
| `rtt_weight` | 1 | Not negative. |
| `jitter_weight` | 0.5 | Not negative. |

At least one weight must be positive. Omit the block to keep the defaults.

### Notifier `webhook`

| Key | Default | Meaning |
|---|---|---|
| `url` | none | Required absolute `http` or `https` URL. `${VAR}` expands from the environment. |
| `timeout` | `5s` | Not negative. |
| `headers` | none | Extra request headers. Values expand `${VAR}`. |
| `min_severity` | `info` | `info`, `warning`, or `critical`. |

### Notifier, prober, or source `exec`

| Key | Default | Meaning |
|---|---|---|
| `command` | none | Required. Absolute path, or a path inside `plugin_dir`. `../` is rejected. The file must be executable at startup. |
| `args` | none | Arguments. |
| `timeout` | `30s` | Per call. Not negative. |
| `env` | none | Passed to the process, plus `PATH` and `PACKETEER_PLUGIN_KIND`. Values expand `${VAR}`. Names cannot contain `=` or NUL. |
| `config` | none | Forwarded verbatim in every JSON request. |

### Announcer `gobgp`

No keys. Do not set `config`.

## Example

[config.example.yaml](../config.example.yaml) is a valid `observe` file. Annotated install steps are in the [README](../README.md). Router filters: [mikrotik.md](mikrotik.md), [routers.md](routers.md). Probe sourcing: [policy-routing.md](policy-routing.md).
