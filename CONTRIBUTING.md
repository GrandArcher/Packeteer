# Contributing

Read [AGENTS.md](AGENTS.md) first. It holds the safety, Docker-first, and plugin rules every change follows.

## Community

Chat with maintainers and other contributors on the [Packeteer Discord](https://discord.gg/MWCCGw8Rq6). Bugs and feature requests still go in GitHub issues.

## Setup

```
make setup   # installs golangci-lint, staticcheck, deadcode, and govulncheck, enables the pre-commit hook
make test    # build, vet, gofmt check, go test, then a list of the tests that skipped here (root, node)
make race    # go test -race ./... (the CI race job; about 3 minutes)
make lint    # golangci-lint, staticcheck, deadcode -test, CHANGELOG line length, ASCII docs
make vuln    # govulncheck
```

Go 1.27 is required (see `go.mod`). Docker is not needed for unit tests; the container image and the FRR lab run in CI. The image builder in `Dockerfile` is pinned by digest to the `golang:<go.mod minor>-alpine` tag; Dependabot bumps the digest weekly. Before tagging a release, merge any open Dependabot digest PR, or bump the digest by hand.

## Known CI flakes (#660)

A red job is a finding until its log shows one of these. Rerun with `gh run rerun ID --failed` (or `--job JOBID`); do not rerun a failure that is not listed, and never retry a test to hide a regression.

- Fuzz steps in the `test` job: the Go fuzzing engine can end a run with `context deadline exceeded` just after `-fuzztime` (seen on FuzzDecodeV5, FuzzSFlow, FuzzBMPStream, FuzzParse). `lab/fuzzrun` runs each target up to 3 times and retries only when the output has that line and no `Failing input written to` or panic, and logs why. A crash or a written input fails at once.
- `e2e` FRR HA lab and `failure-matrix (ha)`: a runner stall of more than a second makes one lease tick time out on the lock, and the active instance steps down and withdraws by design. The lab pair now uses `ttl: 6s` (`renew: 1s`), so one failed tick does not step it down; a crash takeover takes about 13s with the edge's 9s hold time (`TestLabHAConfigsSurviveOneFailedTick`). A step-down that still shows in a log with `lease lock: timed out` is this stall; a step-down with no such line is a finding. The `stale-measurements` case of the HA matrix has no failing log in the last 300 CI runs and is not separately fixed.
- `load` and `load-bmp`: the RSS growth and RSS still rising rows have gone over budget with peak RSS inside its budget (growth 457 MiB in run 43455983840 and 390 in 43693052499 against 384; still rising 203 in 43430859174 and 275 in 43904183660 against 192), while other runs read 0 to 258. That is the collector's sawtooth on a shared runner (docs/performance.md). No in-repo change fixes it without a different measurement or a higher budget, and a budget moves only with a measured reason and the reviewer's agreement, so these stay reruns. A run that is over on peak RSS, learn time, or the active and passive floors is not this flake.
- `gitleaks` stuck `in_progress`, and a Go module proxy `INTERNAL_ERROR` in a Docker build step (`go: ...: stream error: ... INTERNAL_ERROR`): GitHub or proxy side; rerun the job.

## Pull requests

- One issue per PR, from a branch off `main`. Never push to `main`.
- A PR merges when these CI checks pass: `test`, `docker`, `e2e`, `lint`, `race`, `govulncheck`, and `gitleaks`.
- Title: `#N outcome`. Body: `Closes #N`, summary, how tested, and rollback for any announce-path change.
- Add tests for the behavior you change. BGP tests use simulated routers and documentation prefixes and ASNs only.
- Keep `config.example.yaml` in `mode: observe`. Do not commit secrets, real prefixes, or live RIBs.
- New capabilities are plugins behind the interfaces in `pkg/plugin` (see [docs/PLUGINS.md](docs/PLUGINS.md)).
- Writing a plugin, in this repository or in your own: [docs/PLUGIN_AUTHORING.md](docs/PLUGIN_AUTHORING.md). To list one that lives elsewhere, add a row to [docs/COMMUNITY_PLUGINS.md](docs/COMMUNITY_PLUGINS.md).

Environment variables are listed in [docs/ENV.md](docs/ENV.md). Vulnerabilities: see [SECURITY.md](SECURITY.md).
