# MCP server for AI assistants

Packeteer can serve the [Model Context Protocol](https://modelcontextprotocol.io) so an AI assistant (Claude, Cursor, and others that speak MCP) can read its state. It is a thin layer over the REST API ([API.md](API.md)): each tool is one fixed REST call made as the signed-in caller, so roles, validation, and the audit log are the API's. It never announces anything. Off by default (#302).

## Turn it on

```yaml
mcp:
  enabled: true
  # write_tools: false      # maintenance windows; see "Write tools"
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
| `herd_overview` | `/api/herd/overview` |
| `herd_events` | `/api/herd/events` (`loss`, `window`) |
| `herd_outside` | `/api/herd/outside` (`prefix`, `origin_asn`) |

Not reachable: `/api/config`, users, tokens, the audit log, `/api/upgrade`, `/api/herd/preview`, the per-vantage herd records (`vantages`, `mesh`, `search`, `monitor`, `map`), `/api/ring_lg`, and `/metrics`. A reply is cut at 256 KiB. Event messages, names, and reasons come from the network and from operators; the tool descriptions tell the assistant to treat them as data.

## Write tools

Off by default. A write tool is listed and callable only when all of these hold:

- `mcp.write_tools: true`.
- `auth` is on and the token has the `mcp:write` scope (`"scope":"mcp:write"` when you create it). A session, the basic-auth account, an unscoped token, or an `mcp` token never gets write tools.
- The token's role is the one the REST call needs (`operator` for maintenance), checked by the route itself.

| Tool | REST call |
|---|---|
| `maintenance_open` | `POST /api/maintenance` (`providers`, `duration`, `reason`) |
| `maintenance_close` | `DELETE /api/maintenance/<id>` |

A maintenance window only excludes providers from improvements; it cannot add a route. It needs a `maintenance` policy that takes on-demand windows ([CONFIG.md](CONFIG.md#policy-maintenance)). Each write is audited as its REST call (`POST /api/maintenance`, actor the token's user, method `token`, detail starting `via mcp`). A write tool asked for without access is refused and audited as `MCP tools/call <tool>` with result `denied`. Reads are not audited.

Pin/unpin a prefix to a link, pause/resume optimization, and alert acknowledgement are not built: the REST API has no such call, and this layer adds none.

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

Set `mcp.enabled: false` (or remove the block) and restart: `POST /mcp` is gone. Revoke `mcp` and `mcp:write` tokens first when going back to a version before #302: that version ignores the scope and treats such a token as a full API token at its role. The `scope` column the upgrade adds to the token table is harmless to an older version.
