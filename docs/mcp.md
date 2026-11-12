# MCP server for AI assistants

Packeteer can serve the [Model Context Protocol](https://modelcontextprotocol.io) so an AI assistant (Claude, Cursor, and others that speak MCP) can read its state. It is a thin layer over the REST API ([API.md](API.md)): each tool is one fixed REST call made as the signed-in caller, so roles, validation, and the audit log are the API's. It announces nothing itself: the one write tool that can lead to an announcement, `pin_prefix`, goes through the same rails as a static rule. Off by default (#302).

## Turn it on

```yaml
mcp:
  enabled: true
  # write_tools: false      # see "Write tools"
  # rate_per_minute: 120    # per user
```

Keys: [CONFIG.md](CONFIG.md#mcp). The endpoint is `POST /mcp` on `http.listen`, with the same `http.allow_from` and sign-in as the rest of the API. It speaks JSON-RPC 2.0 with the streamable HTTP transport's plain JSON replies: one request per POST, no batches, no server-sent events. Only POST is served.

## Tokens and scopes

Create an API token with the `mcp` scope ([auth.md](auth.md#api-tokens)):

```sh
curl -u "noc1:$PACKETEER_PASSWORD" -H 'Content-Type: application/json' http://127.0.0.1:8080/api/tokens \
  -d '{"name":"assistant","role":"viewer","scope":"mcp","ttl":"720h"}'
```

A scoped token works only on `POST /mcp`; every other route answers `403`, so a leaked assistant token cannot read `/api/*` directly or mint tokens. The role is still the token's role, capped by its user's. A token with no scope is also accepted on `/mcp` (read tools only), as is a session or the basic-auth account.

## Read tools

All are GET calls. A tool with an argument rejects unknown, missing, or mistyped values before any request is made.

| Tool | REST call |
|---|---|
| `system_health` | `/api/system` |
| `overview` | `/api/overview` |
| `link_health` | `/api/providers` |
| `link_stats` | `/api/providers/stats` |
| `prefixes` | `/api/prefixes` (`prefix`, `provider`, `asn`, `differs`, `sort`, `limit`, `offset`) |
| `decisions` | `/api/decisions` |
| `decision_explain` | `/api/decisions/<prefix>` (`prefix`): why a decision came out as it did |
| `improvements` | `/api/improvements` |
| `search` | `/api/search` (`q`: prefix, address, AS number, or AS name) |
| `events` | `/api/events` (`severity`, `q`, `from`, `to`, `limit`) |
| `anomalies` | `/api/anomalies` |
| `quarantine` | `/api/quarantine` |
| `leaks` | `/api/leaks` |
| `maintenance_windows` | `/api/maintenance` |
| `pins` | `/api/pins`: prefixes pinned through the API |
| `optimization_status` | `/api/optimization`: whether optimization is paused |
| `herd_overview` | `/api/herd/overview` |
| `herd_events` | `/api/herd/events` (`loss`, `window`) |
| `herd_outside` | `/api/herd/outside` (`prefix`, `origin_asn`) |

Not reachable: `/api/config`, users, tokens, the audit log, `/api/upgrade`, `/api/herd/preview`, the per-vantage herd records (`vantages`, `mesh`, `search`, `monitor`, `map`), `/api/ring_lg`, and `/metrics`. A reply is cut at 256 KiB. Event messages, names, and reasons come from the network and from operators; the tool descriptions tell the assistant to treat them as data.

## Write tools

Off by default. A write tool is listed and callable only when all of these hold:

- `mcp.write_tools: true`.
- `auth` is on and the token has the `mcp:write` scope (`"scope":"mcp:write"` when you create it). A session, the basic-auth account, an unscoped token, or an `mcp` token never gets write tools.
- The token's role is the one the REST call needs (`operator` for all of them), checked by the route itself.

| Tool | REST call |
|---|---|
| `maintenance_open` | `POST /api/maintenance` (`providers`, `duration`, `reason`) |
| `maintenance_close` | `DELETE /api/maintenance/<id>` |
| `pin_prefix` | `POST /api/pins` (`prefix`, `provider`, `max_loss_pct`, `max_rtt_ms`, `duration`, `reason`) |
| `unpin_prefix` | `DELETE /api/pins/<id>` |
| `optimization_pause` | `POST /api/optimization/pause` (`reason`) |
| `optimization_resume` | `DELETE /api/optimization/pause` |
| `alert_acknowledge` | `POST /api/alerts/ack` (`key`, `note`) |

A maintenance window only excludes providers from improvements; it cannot add a route. It needs a `maintenance` policy that takes on-demand windows ([CONFIG.md](CONFIG.md#policy-maintenance)). The other tools are described under [Steering through the API](#steering-through-the-api). Each write is audited as its REST call (for example `POST /api/pins`, actor the token's user, method `token`, detail starting `via mcp`). A write tool asked for without access is refused and audited as `MCP tools/call <tool>` with result `denied`. Reads are not audited.

## Steering through the API

These REST calls (#558) need an operator (or the basic-auth account) like any change, are audited, and are refused with `403` when no one can sign in. Pins, the pause, and acknowledgements are saved after each change and restored on start (#565): with `ha`, in a file beside the lease (`path` + `.steering`), so the instance that takes over restores them before its first decision; otherwise in `storage` (`sqlite`). Without either (memory storage) they are in memory and a restart clears them. A restored pin that has expired, whose provider is no longer configured, or that is outside the allowlist is dropped; the others act under the same rails as a new pin, so nothing outside the learned RIB view is announced. Changes are refused with `409` on an HA standby (call the active instance) and until the saved state is restored. If the store cannot be read, the controller makes no decision and withdraws until it can; it never runs unpaused on an unread pause. A saved document that is unreadable or of another version is logged, not restored, and replaced by the next change, so after a downgrade the newer version's saved pins and pause are lost. In IXP mode `/api/pins` and `/api/optimization` answer `404`.

- **Pin** (`POST /api/pins`) is a static rule set on demand: Decide steers the prefix to `provider` while that path is usable, at or under `max_loss_pct` (required, 0-100) and `max_rtt_ms` (optional), and not lossier than native by `thresholds.min_loss_delta_pct`. It is refused unless the exact prefix is in the learned RIB view and inside `allowlist.prefixes` (in every mode), and the provider is configured. `duration` is 1m to 168h; at most 100 pins, one per prefix. A pin takes precedence over the policy chain for its prefix and otherwise has a static rule's rails: `mode: inject` and the allowlist on every round, `hold_time`, flap quarantine, and `max_improvements` (static pins are kept first). In observe and suggest it is a recommendation. An announced pin carries the packeteer community and NO_EXPORT like every improvement. It applies only while a source lists the prefix: a pin does not add a probe target. `DELETE /api/pins/<id>` ends it, and the next round retires the improvement.
- **Pause** (`POST /api/optimization/pause`, `reason` required) runs every decision round with a cap of zero: each improvement retires at once (inside `hold_time`, no cooldown) and is withdrawn, and none is made. Inbound steering and mitigation are not paused. `DELETE /api/optimization/pause` resumes; with memory storage a restart resumes too. `GET /api/optimization` shows who paused, when, and why.
- **Acknowledge** (`POST /api/alerts/ack`, `key` is an event's `dedup_key` from `GET /api/events`, optional `note`) marks an open warning or critical alert as seen. The newest event with that key, among the newest 1000, must not be a resolving event. Event rows of the open incident then carry `ack` (`by`, `at`, `note`) until an event resolves the alert. Notifications and routing are unchanged.

## Rate limit

`mcp.rate_per_minute` (default 120) is a token bucket per user. Past it, `POST /mcp` answers `429` with `Retry-After`.

## Stdio

A client that starts MCP servers as subprocesses uses `packeteer-mcp`, in the image next to `packeteer`. It forwards each JSON-RPC line on stdin to a running controller's `POST /mcp` and prints the answer; the controller does every check.

| Variable | Meaning |
|---|---|
| `PACKETEER_MCP_TOKEN` | Required. An API token, sent only as an `Authorization` header. |
| `PACKETEER_MCP_URL` | Default `http://127.0.0.1:8080/mcp`. Must be `https`, or `http` to a loopback address: the token is sent in every request. |

A client entry for a controller running in a container named `packeteer`:

```json
{
  "mcpServers": {
    "packeteer": {
      "command": "docker",
      "args": ["exec", "-i", "-e", "PACKETEER_MCP_TOKEN", "packeteer", "packeteer-mcp"],
      "env": {"PACKETEER_MCP_TOKEN": "pkt_..."}
    }
  }
}
```

A client that speaks HTTP can post to `/mcp` directly with `Authorization: Bearer pkt_...`; keep `http.listen` on loopback or behind a TLS proxy.

## Rollback

Set `mcp.enabled: false` (or remove the block) and restart: `POST /mcp` is gone. Saved pins and a saved pause are restored on that restart: remove them through the API first. Revoke `mcp` and `mcp:write` tokens first when going back to a version before #302: that version ignores the scope and treats such a token as a full API token at its role. The `scope` column the upgrade adds to the token table is harmless to an older version.
