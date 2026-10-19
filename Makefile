# Targets match what .github/workflows/ci.yml runs.
GOLANGCI_LINT_VERSION ?= v2.14.0
STATICCHECK_VERSION ?= 2026.2.1
DEADCODE_VERSION ?= v0.52.0

.PHONY: setup build vet fmt-check test race lint vuln check hub-snapshot

setup: ## install dev tools (golangci-lint, staticcheck, deadcode, govulncheck) and the pre-commit hook
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)
	go install golang.org/x/tools/cmd/deadcode@$(DEADCODE_VERSION)
	go install golang.org/x/vuln/cmd/govulncheck@latest
	git config core.hooksPath .githooks
	go mod download

build:
	go build ./...

vet:
	go vet ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt needed on:"; echo "$$unformatted"; exit 1; fi

test: build vet fmt-check
	go test ./...

race:
	go test -race ./...

lint:
	golangci-lint run
	staticcheck ./...
	@dead="$$(deadcode -test ./...)"; if [ -n "$$dead" ]; then echo "unreachable code:"; echo "$$dead"; exit 1; fi
	scripts/check-changelog.sh

vuln:
	scripts/govulncheck.sh

check: test race lint vuln

hub-snapshot: ## release step: refresh the built-in herd hub list from HUB_URL
	@test -n "$(HUB_URL)" || { echo "set HUB_URL=https://..."; exit 1; }
	curl -fsS --max-time 30 "$(HUB_URL)" -o internal/herd/hub_snapshot.json
	go test ./internal/herd -run TestParseHubListRefusals
