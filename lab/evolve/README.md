Experimental and lab only: this harness never changes Packeteer's shipped defaults, and nothing in the product calls it.

# Path-scoring evolution harness (#584)

`lab/evolve` replays recorded decision rounds through the real `Decide` path, under a baseline config and under config variants, and scores each variant against the baseline by the loss, latency, and flap count of the paths it would have chosen. A variant is an ordinary config file that differs in scorer weights, thresholds, `hold_time`, `confirm_rounds`, or other decision knobs. It is not a new scorer type.

## The contract

- Shipped defaults (`config.example.yaml`, the image, the thresholds and weights in code) change only when a human opens a normal pull request with the score report attached. A winning variant is evidence for that pull request, nothing more.
- Nothing is auto-merged or auto-applied. The harness writes no config, never writes `/etc/packeteer/config.yaml`, signals no process, and builds no announcer: it links the scorers and the history store only, which `TestNoAnnouncerIsLinked` checks.
- It exits 1 when a variant's `mode` differs from the base's (so a variant can never turn inject on), and when the base, a variant, `/etc/packeteer/config.yaml`, or the file `PACKETEER_CONFIG` names changed during the run. It exits 2 on bad usage.
- Lab history only. No production or operator-supplied RIB or prefix goes in this directory. The checked-in fixture uses documentation prefixes only: 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24 (2001:db8::/32 is the IPv6 range to use), with providers `lab-a` and `lab-b` and private ASN 64512.

## Run it

```
go run ./lab/evolve -history lab/evolve/testdata/history.jsonl \
  -base lab/evolve/testdata/baseline.yaml \
  -variant lab/evolve/testdata/worse.yaml -variant lab/evolve/testdata/better.yaml
```

```
replayed 60 rounds from 2026-10-01T12:00:00Z to 2026-10-01T12:29:30Z; nothing was announced and no config was written
side                     loss %     rtt ms  flaps  moves  samples  vs baseline
baseline                  0.167      60.83      0      1      180
worse                     2.222      61.67      5     12      180  worse
better                    0.167      53.87      0      2      180  better
```

`-history` is a sqlite storage file with `round_retention` on (the store `packeteer whatif` reads, [onboarding.md](../../docs/onboarding.md#replay-history)), opened read-only, or a `.jsonl` round file: one `{"at": <RFC 3339 time>, "input": <policy.Input as JSON>}` per line, oldest first. Every round in the file is replayed. `-variant` repeats. `-json` prints the report as JSON for a driver.

CI runs the fixture above in the `test` job and `go test ./lab/evolve` checks its verdicts. It runs no search.

## Scores

- `loss %` and `rtt ms` are means over every prefix and round of the measurement of the path the prefix was on during that round: the provider an improvement left it on after the round before, else the native provider. A move is scored by the rounds after it, not by the measurement that made it. A path without a usable measurement in a round is left out; `samples` counts the rest.
- `flaps` is the replay's flap count: switches, plus new improvements of a prefix retired earlier in the history. `moves` is new, switched, and retired improvements.
- `vs baseline` compares each metric alone, lower being better: `better` when none is worse and one is better, `worse` the reverse, `mixed` for a trade-off (a human weighs it), `same` otherwise.

The replay limits of `packeteer whatif` apply: each side starts with no improvement standing, the measurements are those recorded (a path does not change because traffic moved onto it), and synthesized sub-ranges, inbound steers, and mitigation rules are not replayed. The means are not weighted by prefix volume.

## External drivers

A search tool such as OpenEvolve may write variant files, call the harness with `-json`, and read the `verdict` and the scores. It is optional: not vendored, not a Go module dependency, and not used by CI. Its output is a candidate for a pull request, under the contract above.
