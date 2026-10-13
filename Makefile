# Targets match what .github/workflows/ci.yml runs.
GOLANGCI_LINT_VERSION ?= v2.14.0
STATICCHECK_VERSION ?= 2026.2.1
DEADCODE_VERSION ?= v0.52.0

.PHONY: setup build vet fmt-check test lint vuln check

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

lint:
	golangci-lint run
	staticcheck ./...
	@dead="$$(deadcode -test ./...)"; if [ -n "$$dead" ]; then echo "unreachable code:"; echo "$$dead"; exit 1; fi
	scripts/check-changelog.sh

vuln:
	scripts/govulncheck.sh

check: test lint vuln
