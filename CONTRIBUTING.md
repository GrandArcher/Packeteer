# Contributing

Read [AGENTS.md](AGENTS.md) first. It holds the safety, Docker-first, and plugin rules every change follows.

## Community

Chat with maintainers and other contributors on the [Packeteer Discord](https://discord.gg/MWCCGw8Rq6). Bugs and feature requests still go in GitHub issues.

## Setup

```
make setup   # installs golangci-lint, staticcheck, deadcode, and govulncheck, enables the pre-commit hook
make test    # build, vet, gofmt check, go test (what CI runs)
make race    # go test -race ./... (the CI race job; about 3 minutes)
make lint    # golangci-lint, staticcheck, deadcode -test, CHANGELOG line length
make vuln    # govulncheck
```

Go 1.26 is required (see `go.mod`). Docker is not needed for unit tests; the container image and the FRR lab run in CI.

## Pull requests

- One issue per PR, from a branch off `main`. Never push to `main`.
- Title: `#N outcome`. Body: `Closes #N`, summary, how tested, and rollback for any announce-path change.
- Add tests for the behavior you change. BGP tests use simulated routers and documentation prefixes and ASNs only.
- Keep `config.example.yaml` in `mode: observe`. Do not commit secrets, real prefixes, or live RIBs.
- New capabilities are plugins behind the interfaces in `pkg/plugin` (see [docs/PLUGINS.md](docs/PLUGINS.md)).

Environment variables are listed in [docs/ENV.md](docs/ENV.md). Vulnerabilities: see [SECURITY.md](SECURITY.md).
