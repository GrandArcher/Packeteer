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
| `PACKETEER_HTTP_USER`, `PACKETEER_HTTP_PASSWORD` | The single basic-auth account. Not allowed when `auth.enabled` is true. |
| `PACKETEER_ADMIN_USER`, `PACKETEER_ADMIN_PASSWORD` | First admin when `auth` is on (user defaults to `admin`). See [auth.md](auth.md). |
| `PACKETEER_HA_ID` | Instance id for the `lease` elector. See [ha.md](ha.md). |

## Referenced from config

Plugins read secrets from variables whose names you choose in the config (`community_env`, `password_env`, `client_secret_env`, `routing_key_env`, ...). The names used in the docs and examples are `PACKETEER_SNMP_COMMUNITY`, `PACKETEER_SNMP_USER`, `PACKETEER_SNMP_AUTH`, `PACKETEER_SNMP_PRIV`, `PACKETEER_SMTP_USER`, `PACKETEER_SMTP_PASSWORD`, and `PACKETEER_OIDC_CLIENT_SECRET`.

## Exec plugins

An `exec` plugin process gets `PATH`, `PACKETEER_PLUGIN_KIND`, and its configured `env`, and nothing else. See [PLUGINS.md](PLUGINS.md).
