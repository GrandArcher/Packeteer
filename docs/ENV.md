# Environment variables

Set these on the container (`-e NAME`). Secrets belong here, never in the config file or git.

## Controller

| Variable | Effect |
|---|---|
| `PACKETEER_CONFIG` | Config path when `-config` is not given. Default `/etc/packeteer/config.yaml`. |
| `PACKETEER_PLUGIN_DIR` | Overrides `plugin_dir`. |
| `PACKETEER_LOG_LEVEL` | `debug`, `info`, `warn`, or `error`. Overrides `log.level`. |
| `PACKETEER_LOG_FORMAT` | `text` or `json`. Overrides `log.format`. |
| `PACKETEER_HTTP_LISTEN` | Overrides `http.listen`. `off` disables the HTTP server. |
| `PACKETEER_HTTP_USER`, `PACKETEER_HTTP_PASSWORD` | The single basic-auth account. Not allowed when `auth.enabled` is true. With these set and no `auth.enabled`, sign-in stays off and this account protects the server. |
| `PACKETEER_ADMIN_USER`, `PACKETEER_ADMIN_PASSWORD` | First admin when `auth` is on (user defaults to `admin`). Without a password, one is generated on the first start. See [auth.md](auth.md#first-run). |
| `PACKETEER_MCP_TOKEN`, `PACKETEER_MCP_URL` | Read by `packeteer-mcp`, the stdio bridge of the MCP server (#302), not by the controller. The API token, and the `/mcp` URL (default `http://127.0.0.1:8080/mcp`; https, or http to loopback). See [mcp.md](mcp.md#stdio). |
| `PACKETEER_UPGRADE_LAUNCHED` | Internal. The launcher sets it on a staged binary it starts, so that process does not hand over again. Do not set it. |
| `PACKETEER_HA_ID` | Instance id for the `lease` elector. See [ha.md](ha.md). |
| `PACKETEER_PEERINGDB_API_KEY` | Optional PeeringDB API key for `lookup` type `peeringdb` (#153). Sent only as an `Authorization` header to `base_url`, never in a URL, and never in `GET /api/lookup`, a log line, or an error. Unset means anonymous, which PeeringDB rate-limits. The `registry` `peeringdb` source (#289) reads the same variable; a push needs it. |
| `PACKETEER_RIPE_USER`, `PACKETEER_RIPE_PASSWORD` | Maintainer account for the `registry` `ripe` source (#289). Read only when a confirmed change is pushed, sent only as basic authentication to `base_url`, and never in the API, a log line, or the audit record. |
| `PACKETEER_IXP_MANAGER_API_KEY` | IXP Manager API key for `ixp.members` type `ixf` (#161) and, when that import is the manager export, for the fabric prober's Can Ping GET (#162). Sent only as the `X-IXP-Manager-API-Key` header, never in the URL. The log records the key identifier; the secret is never logged. |
| `PACKETEER_GEOIP_USER`, `PACKETEER_GEOIP_KEY` | Basic-authentication account for the `geoip` country database download (#135; for MaxMind, the account ID and the license key). Set both or neither. Sent only over https or to a loopback address, never logged or returned. |
| `PACKETEER_POLICY_TOKEN` | Bearer token of the `external_policy` feed (#232) unless `token_env` names another variable. At least 16 characters; compared in constant time and never logged. `packeteer-policy` reads the same variable by default. See [external-policy.md](external-policy.md). |
| `PACKETEER_ATLAS_API_KEY` | Your RIPE Atlas API key for the `atlas` block (#213). Sent only in the `Authorization` header to the Atlas API, never logged, never in the URL, and never in `GET /api/atlas`, the System page, or an error. Unset means the integration makes no request. |
| `PACKETEER_ROUTER_USER`, `PACKETEER_ROUTER_PASSWORD` | Login of the router REST API for `nonbgp.steerer` type `mikrotik` (#300), named by `username_env` and `password_env`. Sent only as basic authentication to the https `url` (http only to a loopback host), never logged and never in an API answer. Use an account that can change routes only. |
| `PACKETEER_NETBOX_TOKEN`, `PACKETEER_PEERING_MANAGER_TOKEN` | API token of the `inventory` type `netbox` or `peeringmanager`. Read only by `packeteer config plan`, `diff`, and `apply`; sent only as an `Authorization` header to `base_url`. See [inventory.md](inventory.md). |

## Referenced from config

Plugins read secrets from variables whose names you choose in the config (`community_env`, `password_env`, `client_secret_env`, `routing_key_env`, ...). The names used in the docs and examples are `PACKETEER_SNMP_COMMUNITY`, `PACKETEER_SNMP_USER`, `PACKETEER_SNMP_AUTH`, `PACKETEER_SNMP_PRIV`, `PACKETEER_SMTP_USER`, `PACKETEER_SMTP_PASSWORD`, `PACKETEER_OIDC_CLIENT_SECRET`, `PACKETEER_TRAP_COMMUNITY` (`snmptrap` notifier), `PAGERDUTY_ROUTING_KEY` (`webhook` preset `pagerduty`), `INFLUX_TOKEN` (`influxdb` exporter), and `PACKETEER_FEED_TOKEN` (`threat_feeds` source). The config holds the variable name; the value stays in the environment.

A `*_env` key set through the config editor (raw YAML, the form, or a federation settings push) must name a variable that starts with the prefix for its place, or one the running config already names there; anything else, such as `PACKETEER_ADMIN_PASSWORD`, is refused (#504). The mounted file is not checked.

| Place | Prefixes |
|---|---|
| `telemetry` `snmp`, `exporters` `snmpagent` | `PACKETEER_SNMP_` |
| `notifiers` `snmptrap` | `PACKETEER_SNMP_`, `PACKETEER_TRAP_` |
| `notifiers` `smtp` | `PACKETEER_SMTP_` |
| `notifiers` `webhook` | `PACKETEER_WEBHOOK_`, `PAGERDUTY_` |
| `exporters` `influxdb` | `PACKETEER_INFLUX_`, `INFLUX_` |
| `exporters` `kafka` | `PACKETEER_KAFKA_` |
| `exporters` `nats` | `PACKETEER_NATS_` |
| `auth.sso` `oidc` | `PACKETEER_OIDC_` |
| `threat_feeds.feeds` `http` | `PACKETEER_FEED_` |
| `external_policy` | `PACKETEER_POLICY_` |
| `nonbgp.steerer` `mikrotik` | `PACKETEER_ROUTER_` |

Any other plugin takes only names the running config already uses there.

## Probe agent

| Variable | Effect |
|---|---|
| `PACKETEER_AGENT_CONFIG` | Config path of `packeteer-agent` when `-config` is not given. Default `/etc/packeteer/agent.yaml`. See [agents.md](agents.md#agent-config). |

A webhook `url` or `headers` value expands only `${PACKETEER_WEBHOOK_*}` variables, and an `otlp` exporter `headers` value only `${PACKETEER_OTLP_*}` variables (#489). The examples use `PACKETEER_WEBHOOK_TOKEN` and `PACKETEER_WEBHOOK_SLACK_URL`.

## Exec plugins

An `exec` plugin process gets `PATH`, `PACKETEER_PLUGIN_KIND`, and its configured `env`, and nothing else. A `grpc` plugin also gets `PACKETEER_PLUGIN_COOKIE` and the other handshake variables the plugin library adds. See [PLUGINS.md](PLUGINS.md).
