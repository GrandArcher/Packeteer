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
| `PACKETEER_HA_ID` | Instance id for the `lease` elector. See [ha.md](ha.md). |
| `PACKETEER_PEERINGDB_API_KEY` | Optional PeeringDB API key for `lookup` type `peeringdb` (#153). Sent only as an `Authorization` header to `base_url`, never in a URL, and never in `GET /api/lookup`, a log line, or an error. Unset means anonymous, which PeeringDB rate-limits. |
| `PACKETEER_IXP_MANAGER_API_KEY` | IXP Manager API key for `ixp.members` type `ixf` (#161) and, when that import is the manager export, for the fabric prober's Can Ping GET (#162). Sent only as the `X-IXP-Manager-API-Key` header, never in the URL. The log records the key identifier; the secret is never logged. |
| `PACKETEER_ATLAS_API_KEY` | Your RIPE Atlas API key for the `atlas` block (#213). Sent only in the `Authorization` header to the Atlas API, never logged, never in the URL, and never in `GET /api/atlas`, the System page, or an error. Unset means the integration makes no request. |

## Referenced from config

Plugins read secrets from variables whose names you choose in the config (`community_env`, `password_env`, `client_secret_env`, `routing_key_env`, ...). The names used in the docs and examples are `PACKETEER_SNMP_COMMUNITY`, `PACKETEER_SNMP_USER`, `PACKETEER_SNMP_AUTH`, `PACKETEER_SNMP_PRIV`, `PACKETEER_SMTP_USER`, `PACKETEER_SMTP_PASSWORD`, and `PACKETEER_OIDC_CLIENT_SECRET`.

## Exec plugins

An `exec` plugin process gets `PATH`, `PACKETEER_PLUGIN_KIND`, and its configured `env`, and nothing else. See [PLUGINS.md](PLUGINS.md).
