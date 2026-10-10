# Users, roles, tokens, audit log, and SSO

Packeteer's ops HTTP server (dashboard, API, metrics) can require a user for every request (#32). Each user has a role, scripts use API tokens, every change is written to an audit log that also goes to the notifiers, and single sign-on through OpenID Connect is optional. It all runs in the stock image with a mounted config and environment variables. Auth decides who may call the API. It never changes what Packeteer announces: allowlist, learned-RIB check, `packeteer_community` + NO_EXPORT, `max_improvements`, hold time, and withdraw-on-failure are the same for every role.

## Turn it on

```yaml
storage:
  type: sqlite          # users, token hashes, and the audit log are kept here
  config:
    path: /var/lib/packeteer/packeteer.db
auth:
  enabled: true
http:
  listen: "0.0.0.0:8080"          # or keep 127.0.0.1 behind a TLS proxy
  allow_from: [192.0.2.0/24]      # optional: the NOC network
```

```sh
docker run --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PACKETEER_ADMIN_PASSWORD='a-long-first-password' \
  -v packeteer-data:/var/lib/packeteer \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" ghcr.io/grandarcher/packeteer
```

At start the controller creates the admin `admin` (or `PACKETEER_ADMIN_USER`) with that password if no user has that name. It never changes an existing user, so change the password through the API and drop the variable. `auth` refuses to start together with `PACKETEER_HTTP_USER`: the single basic-auth account is replaced.

Passwords are 12 to 256 characters and stored as PBKDF2-HMAC-SHA256 hashes (600,000 iterations). Local users sign in with HTTP basic auth, so the browser prompts on the dashboard. Put a TLS proxy in front, or keep `http.listen` on loopback, when the network between you and Packeteer is not trusted. Ten failed passwords or tokens from one address within five minutes block that address for the rest of the window (`429`).

## Roles

| Role | May |
|---|---|
| `viewer` | Read the dashboard, every `GET /api/*`, `/metrics`, reports, and the looking glass. Create, list, and revoke its own API tokens. |
| `operator` | Everything a viewer may, plus open and close maintenance windows, add and remove mitigation rules, and run the on-demand probe, traceroute, and whois. |
| `admin` | Everything, plus manage users (`/api/users`), read the audit log (`/api/audit`), and, with `upgrade.enabled`, check, upgrade, and roll back the Packeteer version (`/api/upgrade*`, #196). |

`/healthz`, `/readyz`, `/auth/login`, `/auth/callback`, and `/auth/logout` are public. Anything else without credentials is `401`; with a role that is too low it is `403` (`forbidden: needs role operator`). The full route-to-role table is `routeTable` in `internal/httpapi/access.go`, and a test walks every route with every role.

## Users (admin)

```sh
curl -u admin:... -H 'Content-Type: application/json' http://127.0.0.1:8080/api/users \
  -d '{"name":"noc1","role":"operator","password":"another-long-password"}'
curl -u admin:... -X PATCH -H 'Content-Type: application/json' http://127.0.0.1:8080/api/users/noc1 -d '{"role":"viewer"}'
curl -u admin:... -X PATCH -H 'Content-Type: application/json' http://127.0.0.1:8080/api/users/noc1 -d '{"disabled":true}'
curl -u admin:... -X DELETE http://127.0.0.1:8080/api/users/noc1
```

`PATCH` takes any of `role`, `password`, `disabled`. A change that would leave no enabled admin is refused (`409`). Deleting a user deletes its tokens. Disabling, demoting, or a new password takes effect on the next request and ends the user's SSO sessions.

## API tokens

```sh
curl -u noc1:... -H 'Content-Type: application/json' http://127.0.0.1:8080/api/tokens \
  -d '{"name":"prometheus","role":"viewer","ttl":"720h"}'
# {"id":"3f2a...","token":"pkt_3f2a..._...","role":"viewer","expires":"..."}
curl -H 'Authorization: Bearer pkt_...' http://127.0.0.1:8080/metrics
```

The secret is shown once and stored only as a SHA-256 hash. A token's role defaults to, and may not exceed, its user's role, and it follows the user: demote the user and the token is demoted. Tokens expire (`auth.token_ttl`, default 90 days, at most one year) and are capped at 20 per user. A token cannot create tokens, so a leaked token cannot outlive its own expiry. `GET /api/tokens` lists your tokens (an admin sees all); `DELETE /api/tokens/<id>` revokes one.

## Single sign-on (OIDC)

```yaml
auth:
  enabled: true
  sso:
    type: oidc
    config:
      issuer: https://idp.example.net/realms/noc
      client_id: packeteer
      client_secret_env: PACKETEER_OIDC_CLIENT_SECRET
      redirect_url: https://packeteer.example.net/auth/callback
      scopes: [email, profile, groups]
      role_map: {noc-admins: admin, noc: operator, staff: viewer}
```

Register `redirect_url` at the provider (Keycloak, Authentik, Azure AD, Okta, Google, ...). A browser without a session is sent to `/auth/login`, then to the provider, and back to `/auth/callback`. Packeteer uses the authorization code flow with PKCE, checks the ID token's signature, issuer, audience, expiry, and nonce, maps the groups claim to a role (highest wins; `default_role` when none maps, otherwise the sign-in is refused), records the user in the store with no password, and sets an `HttpOnly`, `Secure`, `SameSite=Strict` session cookie for `auth.session_ttl` (default 12h). Sessions are in memory: a restart signs everyone out. `POST /auth/logout` ends one. The cookie is `Secure`, so serve Packeteer over https (a TLS proxy) or use it on localhost. Local users and tokens keep working next to SSO. Keys: [CONFIG.md](CONFIG.md#sso-oidc).

## Access restriction

`http.allow_from` lists the client prefixes that may connect. Others get `403` on every path. It works with and without `auth`. Behind a reverse proxy the proxy's address is what is matched.

Browsers may not send a cross-site change: `POST`, `PATCH`, and `DELETE` with a cross-site `Sec-Fetch-Site` or `Origin` are refused whatever the credentials.

## Audit log

Every request that can change something (`POST`, `PATCH`, `DELETE`) is recorded after it runs, allowed or not: who (`actor`, `role`, `method`: `password`, `token`, `sso`, or `basic`), from where (`remote`), what (`action`, e.g. `POST /api/mitigations`; `target`, e.g. the rule id; `detail`, e.g. the prefix and action), and how it ended (`result`: `ok`, `denied`, or `failed`, and the HTTP `status`). Changes refused for lack of role are recorded as `denied`. SSO sign-ins (and refused ones), sign-outs, the admin created from the environment, and SIGHUP config reloads are recorded too. Reads are not. Secrets (passwords, token secrets) never are.

Each record goes to the log, to the `sqlite` store (pruned with `retention`), and to every notifier as an `audit.recorded` event ([EVENTS.md](EVENTS.md)); filter it per notifier with `events`. A store or notifier failure is logged and never blocks the change. Admins read it with `GET /api/audit?limit=100&from=<RFC 3339>&to=<RFC 3339>` (newest first, at most 1000). Without `auth`, changes through the basic-auth account are still audited (actor = that user). With no auth at all, only anonymous requests that succeed (troubleshooting tools) are recorded; a refused anonymous request changed nothing and is not.

## Rollback

Set `auth.enabled: false` (or delete the `auth` block) and restart. The server is back to the single basic-auth account from `PACKETEER_HTTP_USER` and `PACKETEER_HTTP_PASSWORD`, or, without them, read-only: every change is refused. Keep `http.listen` on `127.0.0.1` in that mode. Users, tokens, and the audit log stay in the store for when auth is turned on again. Nothing about announcing changes either way.
