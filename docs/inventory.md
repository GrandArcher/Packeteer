# Providers from NetBox or Peering Manager

Packeteer can read its providers, next hops, and provider communities from the system of record you already keep them in, and show the change before it touches the config file (#208). This is read-only on the inventory side: Packeteer only sends GET requests, and `plan` and `diff` write nothing. The running controller never reads the inventory. Only `packeteer config plan`, `diff`, and `apply` do, and `apply` writes the config file and nothing else.

Nothing here announces. `mode` stays as the file has it, a provider is never removed, and a key the inventory does not manage is never touched. Providers are restart-only ([CONFIG.md](CONFIG.md#online-reconfiguration)): a running controller keeps the providers it started with, and SIGHUP refuses a changed provider, until it restarts. Steering is unchanged: one exact learned prefix per move, through `Decide`.

## Configure

```yaml
inventory:
  type: netbox          # or peeringmanager
  config:
    base_url: https://netbox.example.invalid
    tag: packeteer      # only records with this tag are read
    timeout: 30s
```

The API token is the environment variable `PACKETEER_NETBOX_TOKEN` or `PACKETEER_PEERING_MANAGER_TOKEN`, never the file. Only `config plan`, `diff`, and `apply` read it; the controller loads the block to check it and does not need the token. `base_url` must be https; plain http is accepted only for a loopback address (a lab). Redirects are not followed, so the token cannot be sent to another host. Keys are listed in [CONFIG.md](CONFIG.md#inventory).

## What is read

A record is read only when it carries the tag. Each record becomes one provider with these managed keys; a key the record has no value for is left as the config has it.

| Provider key | NetBox (`/api/circuits/providers/?tag=`) | Peering Manager (`/api/peering/autonomous-systems/`, tag matched by Packeteer) |
|---|---|---|
| `name` | the provider's slug | the autonomous system name as a slug (lowercase letters, digits, `-`) |
| `asn` | the lowest ASN listed on the provider | `asn` |
| `type` | custom field `packeteer_type` (`transit`, `peer`, `customer`) | `local_context_data.packeteer.type` |
| `source_ip` | custom field `packeteer_source_ip` | `local_context_data.packeteer.source_ip` |
| `next_hop` | custom field `packeteer_next_hop` | `local_context_data.packeteer.next_hop` |
| `communities` | custom field `packeteer_communities` | `local_context_data.packeteer.communities` |

Communities are standard `asn:value` or large `global:data1:data2` (RFC 8092). A list, or one string separated by commas, semicolons, or spaces, is accepted. They replace the provider's `communities` list. The config checks still apply: `packeteer_community` may not be reused, and `0:x` and `65535:x` are reserved.

NetBox: create the four custom fields on the Provider object type (text fields) and a tag; tag the providers to read. A token that starts with `nbt_` is sent as `Bearer`, any other as `Token`.

Peering Manager: put the values under a `packeteer` key in the autonomous system's local context data and give it the tag.

A record with a bad value (an address that is not an IP, an unknown `type`, a malformed community), no usable name, or a name another record also has is skipped and named in the plan. It is never written. A provider that is not in the config yet needs both `next_hop` and `source_ip`, or it is skipped.

## Plan, diff, apply

```sh
docker run --rm -e PACKETEER_NETBOX_TOKEN \
  -v "$PWD/config.yaml:/etc/packeteer/config.yaml" -v packeteer-data:/var/lib/packeteer \
  ghcr.io/grandarcher/packeteer config plan
```

`plan` prints what would change per provider and a plan id. `diff` prints the resulting file as a line diff. Both read the inventory and the file and write nothing. The plan never removes a provider; those in the config that the inventory does not name are listed as left as they are.

```
~ transit-a
    next_hop: 192.0.2.1 -> 192.0.2.9
    communities: 64496:100 -> 64496:100,64496:200
+ peer-b
    asn: 64497
    ...
plan id: 3f9a1c0b7d2e
```

`apply -plan ID` reads the inventory again and writes only if the plan it gets has that id. The id is a hash of the resulting file, so the file written is exactly the one `plan` described; if the inventory or the file changed since, apply refuses and says to plan again. After an apply, `plan` reports that the config already matches the inventory. The result is checked with the same validation the controller starts with before anything is written, and comments in the file are kept, but the file is written again by a YAML encoder with two-space indentation, so blank lines are dropped and a file indented differently shows a whole-file diff in git.

```sh
docker run --rm -e PACKETEER_NETBOX_TOKEN -v "$PWD:/etc/packeteer" -v packeteer-data:/var/lib/packeteer \
  ghcr.io/grandarcher/packeteer config apply -plan 3f9a1c0b7d2e -git
```

Restart the controller to use the new providers.

## Git and the audit log

With `-git`, the config file must be tracked in a git repository and have no uncommitted change; apply then commits the file alone, with the plan as the message and "Packeteer" as the author, and does not push. Mount the directory that holds the repository (the image includes `git`). If the commit fails, the old file is put back. The repository is yours: Packeteer never pushes.

Every apply is an audit record (`CLI config apply`, method `system`, the user running it, the plan id, the providers and keys changed, the commit). Apply starts as the daemon does, so with HTTP on it uses the same storage as the controller (the default `sqlite` file when the config names none; mount the same data volume) and the record shows in `GET /api/audit`. Apply opens the storage before it writes, so a storage that cannot be opened stops the apply; a record that then fails to write is logged, as for the ops API. With HTTP off and no `storage`, the record is written to the log only.

Peering Manager is covered by unit tests against fixtures of its documented API; the lab runs NetBox only.

## Rollback

Remove the `inventory` block, or `git revert` the commit (or restore the file from your own backup) and restart. Nothing was announced by the read.
