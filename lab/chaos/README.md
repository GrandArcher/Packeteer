# Chaos soak (#585)

`lab/e2e-chaos.sh [PROFILE]` brings up the HA lab (`lab/docker-compose-ha.yml`: one FRR edge, pk-a and pk-b on one lease, documentation prefix 198.51.100.0/24, private AS 64512) and runs `lab/chaos` against it. Docker is required; the `chaos` CI job runs the short profile on every pull request.

```sh
bash lab/e2e-chaos.sh                        # lab/chaos/short.yaml
CHAOS_OUT=/tmp/chaos bash lab/e2e-chaos.sh   # report somewhere else
```

## Profile

| Key | Meaning |
|---|---|
| `name` | report name |
| `duration` | soak window; the faults run in order and the list repeats until it is over, and the first pass always completes |
| `pass_pause` | optional quiet time, sampled and checked, after each pass before the next (default none) |
| `inject_lab` | the configs under test may run `mode: inject`, with an allowlist of documentation prefixes only |
| `configs` | the Packeteer configs the lab mounts, checked before and after the run |
| `faults` | any of `session-flap`, `link-flap`, `sigterm`, `sigkill` |

`short.yaml` is one pass of all four, a few minutes. Its window is shorter than one pass because a second pass of link flaps could reach the default `flap_quarantine` (6 changes an hour) of `lab/packeteer-ha-*.yaml`; `hosted.yaml` sets `pass_pause: 30m` for that reason: a link flap is two changes of the prefix, so one pass every 30 minutes stays at 4 changes an hour.

## Faults

Each fault starts from the baseline: one instance announcing and both sessions Established.

| Fault | What is done | Expected on the edge |
|---|---|---|
| `session-flap` | `neighbor <active> shutdown`, then `no neighbor ... shutdown` | the active's routes go, the standby takes over, the session comes back and the instance stays standby for 5s |
| `link-flap` | `lab/probes/transit-b-down.yaml` (transit-b's probe source fails) for 10s, then `prefer-b.yaml` | no Packeteer route while transit-b is down, then one again |
| `sigterm` | `docker compose kill -s SIGTERM` on the active, then `start` | its routes are withdrawn while its session is Established, the standby takes over, exit code 0 |
| `sigkill` | `docker compose kill -s SIGKILL` on the active, then `start` | its routes go with the session within the negotiated hold time plus 6s, then the standby takes over, exit code 137 |

## Invariants

Checked on the edge (`show bgp ipv4 unicast json` and `show bgp neighbors json` in one vtysh call), never on Packeteer's own view:

- `learned-rib`: every prefix the edge accepts from Packeteer also has a path from a source that is not Packeteer. The table is read after the edge's inbound policy, which keeps only routes with 64512:666.
- `documentation`: every prefix on the edge is in 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, or 2001:db8::/32, and every neighbor AS is a documentation or private ASN.
- `graceful-restart`: no Established Packeteer session carries the graceful-restart capability.
- `ha-both`: the edge never holds routes from both instances.
- `down-session-routes`: a session that is not Established keeps no routes for more than 3s.
- `sigterm-withdraw`: after SIGTERM the routes leave while the session is up: a sample shows it, or FRR's `updatesRecv` from that peer rose after the signal (FRR keeps the count across resets, an UPDATE only arrives on an Established session, and the only UPDATE Packeteer sends on SIGTERM is the withdraw).
- `sigkill-hold`: after SIGKILL the routes and the session are gone within the hold time plus 6s.
- `config-mode`: a config under test, or a running instance's `/api/ha` mode, is `inject` only in an `inject_lab` profile, with documentation prefixes in the allowlist; `config.example.yaml` stays `mode: observe`.

## Report

`chaos-result.json` and `chaos-summary.md` are written to `$CHAOS_OUT` on every run. The JSON has the profile, start, end, `duration_s`, `pass`, the sample count, `fault_counts`, every fault (`withdraw_ms`, `restore_ms`, `hold_ms`, `withdrawn_while_up`, `exit_code`, `error`), `violations` (empty on a green run; a repeat counts in `count`), `errors` (a fault whose expected state never came, or an unexpected exit code), and session and lease `events`. The summary is the same in a few lines with one table row per fault kind. The run exits 1 when there is any violation or error.

## Weekly job and multi-day runs (#589)

`.github/workflows/chaos.yml` runs `lab/chaos/hosted.yaml` (5h window, one pass every 30 minutes) every Thursday at 03:47 UTC, after building the lab from the commit, and uploads `chaos-out/` (`chaos-result.json` and `chaos-summary.md`) as the `chaos-result` artifact even when the job fails. A broken invariant or a lab that does not recover exits 1 and fails the job; nothing ignores a red run. `workflow_dispatch` takes `profile` (`hosted`, or `short` for a few minutes), `duration` (a Go duration that overrides the profile's), and `runner`. GitHub-hosted jobs stop at 6 hours, so the weekly window is 5h.

A multi-day run needs a self-hosted runner or a lab host with Docker, Go (see `go.mod`), and `docker compose`. This repository has no self-hosted runner; use your own.

```sh
# on the lab host, from a checkout of the commit under test
CHAOS_DURATION=72h CHAOS_OUT=/var/lib/chaos/run1 bash lab/e2e-chaos.sh lab/chaos/hosted.yaml

# or from Actions, on a runner you registered with the label "chaos-lab"
gh workflow run chaos.yml -f profile=hosted -f duration=72h -f runner=chaos-lab
```

The workflow times out after 345 minutes on `ubuntu-latest` and after 75 hours on any other `runner` label (so `ubuntu-24.04` is treated as self-hosted: use `ubuntu-latest` for hosted); the window plus the image build and the final recovery must fit, so edit `timeout-minutes` for a window past 72h. Run it under `tmux` or a service on a lab host, because the script runs in the foreground; Ctrl-C stops the harness, which writes the report of what ran as a failed run (the interrupt is an error), and the script tears the lab down.

- Disk: the compose file rotates every container's log at 5 files of 20 MB, so the lab keeps at most about 100 MB per container whatever the length. The report grows with events only: a repeated violation is one entry with a `count`, and each fault adds one entry, about 190 a day at one pass every 30 minutes. Keep a few GB free for Docker's image and volume layers.
- Where the report is written: `$CHAOS_OUT` (default `chaos-out` in the checkout), written once at the end. A run that is killed before the end writes none, and the Actions artifact comes from the same directory; a lab host reads the files there.
- Pacing: keep `pass_pause` at 20 minutes or more with the shipped HA configs, for the flap quarantine reason above.
- Same safety as the short profile: documentation prefix and private ASN, `mode: inject` only inside the profile's `inject_lab`, `config.example.yaml` stays `mode: observe`, nothing announces outside the learned RIB, no graceful restart.
