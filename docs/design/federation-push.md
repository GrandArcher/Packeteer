# Federation: push settings to every instance (#137)

Status: implemented under #137 and tested with two in-process instances; not yet run in the multi-POP lab, and not on a public edge. Off by default: an instance accepts nothing until `accept_settings_from` names a sender.

Multi-POP federation ([multi-pop.md](../multi-pop.md)) was a read-only view. This adds one write: an admin on one instance sends a config section to the other instances, so a threshold or a policy is the same in every POP without editing each file.

## What is pushed

Two sections only, listed in `federation.PushableSections`:

| Section | Why it is safe to share |
|---|---|
| `thresholds` | Loss and RTT gains and `confirm_rounds`. They decide when a better path wins; every other rail still applies. |
| `policies` | `rules` and `maintenance` policy entries. They only forbid, pin, or rank providers inside `Decide`. |

A peer given an empty section resets that key to its default, so the sender refuses to push a section its own file does not have. The sender reads the sections from its own saved config file, so what is pushed is what that instance runs after its last save. Edit and save locally first, then push.

Never pushed, and refused by name on the receiver: `mode`, `allowlist`, `announcer`, `bgp`, `inbound`, `mitigation`, `max_improvements`, `hold_time`, providers, `federation`, `auth`, `http`, and everything else. A peer never accepts inject or allowlist changes from another instance.

## Flow

1. An admin calls `POST /api/federation/push` (or presses Push on the dashboard) with the sections and, optionally, peer names. The sender needs `http.config_editor` and sign-in, like `PUT /api/config`.
2. The sender reads its file, extracts the sections as canonical YAML, and calls each peer in parallel over the existing mutual-TLS federation: `POST /v1/settings`.
3. The peer's transport authenticates the client certificate against `accept_settings_from`. This list is separate from `allow_clients`: being able to read a snapshot grants nothing.
4. The peer's handler (`cmd/controller/settings_push.go`) takes the same path as `PUT /api/config`:
   - refuse a section that is not pushable, or an empty push;
   - compare with its own file; if the sections are already equal, answer `unchanged` and do nothing;
   - merge the sections into its file (other keys and comments stay);
   - run the editor's check: the parser, the runtime environment, every plugin's own config, and the exec-plugin rule (a pushed policy list cannot add or change an `exec` plugin);
   - refuse unless the only keys that differ from the running config are the pushed sections and the change is fully online, and refuse anything that would turn inject on;
   - write the file (compare-and-swap on the file hash, so a concurrent edit refuses the push), then apply it through the online reload of #128: no restart, no withdraw, a still-valid improvement stays up;
   - if the reload is refused, restore the previous file.
5. Each peer answers with a status: `applied`, `unchanged`, `refused` (with the validation errors), or `failed`. The sender adds `unreachable` for a peer that did not answer. The API returns one row per peer; no peer's answer changes another's.

## Audit

- Sender: the API call is in the audit log as `POST /api/federation/push`, target `federation`, with the sections and each peer's status, and the user who made it.
- Receiver: one `federation.settings` record per push that reached the handler, actor = the sender's certificate name, method `federation`, target = the sections, result `ok` (applied or unchanged), `denied` (refused), or `failed`, with the applied keys or the errors. The reload itself is also recorded as `config.reload` (`federation push`). A certificate that is not in `accept_settings_from` is refused in the transport and logged, not audited, because it never reached a handler.

Both go to the log, the storage plugin when it keeps the audit log, and the `audit.recorded` event.

## Security review

Assets: what the instance announces, and the config file.

| Threat | Control |
|---|---|
| A compromised or mistaken peer turns inject on, widens the allowlist, or changes the announcer | Only `thresholds` and `policies` are accepted; everything else is refused by name. The merged file is also checked, and a push is refused if any other key differs from the running config or if it would enable inject. `confirm_inject` is therefore never needed and never bypassed. |
| A peer with a valid certificate that was only meant to read | `accept_settings_from` is separate from `allow_clients` and empty by default. |
| Code execution through a pushed policy | The editor's exec rule refuses a candidate that adds or changes an `exec` plugin or `plugin_dir`. Only built-in plugin types come through. |
| Invalid or hostile values | The candidate passes the same validation as a start; unknown keys are errors. |
| Pushed settings loosen safety | They cannot reach the safety rails: allowlist, community, NO_EXPORT, `max_improvements`, `hold_time`, and withdraw rules are not pushable. Lower thresholds make `Decide` act on smaller gains; the admin who pushes and the admin who enabled `accept_settings_from` accept that. |
| Replay or tamper in transit | Mutual TLS 1.3 with the shared CA. Pushing the same settings again is a no-op (`unchanged`). |
| Resource use | Body limit 1 MiB, one push applied at a time per instance, a 30s timeout per peer on the sender, peers contacted in parallel. |
| A half-applied change | The file is restored if the online apply is refused. A fatal reload error (BGP speaker changed) stops the process, which withdraws everything, as for `PUT /api/config`. |
| An attacker who holds an admin account on one POP | They can change thresholds and policies on every POP that lists it. They cannot enable inject or change the allowlist anywhere. Disabling the feature is removing `accept_settings_from`. |

Receiving needs the config editor (`http.config_editor: true`), because the push is written to the mounted file so a restart keeps it. The config file must be writable. A read-only mount refuses the push with the write error.

## Not built

- Push of other sections (`max_improvements`, `hold_time`, `sources`). Each needs its own review; the list is one slice in code.
- A dry-run push, a staged rollout, or pull-based sync.
- Scheduled or automatic pushes. A push is always an admin action.
