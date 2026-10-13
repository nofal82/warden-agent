# CloudVertex Warden — developer commands. Run `make help`.
# CI runs the same checks directly (see .github/workflows/ci.yml).

GO        ?= go
GOBIN     := $(shell $(GO) env GOPATH 2>/dev/null)/bin
HAS_GO    := $(shell git ls-files '*.go' 2>/dev/null | head -n 1)
FUZZTIME  ?= 30s

# Pinned tool versions. Keep in sync with .github/workflows/ci.yml.
GOLANGCI_LINT_VERSION := v2.13.2
GOSEC_VERSION         := v2.28.0
GOVULNCHECK_VERSION   := v1.9.0
GITLEAKS_VERSION      := v8.30.1

.DEFAULT_GOAL := help
.PHONY: help tools rules hooks-test fmt lint sec vuln test fuzz-short ci build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-12s %s\n", $$1, $$2}'

tools: ## Install lint and security tools (golangci-lint, gosec, govulncheck, gitleaks)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/zricethezav/gitleaks/v8@$(GITLEAKS_VERSION)

rules: ## Warden rule checker: no shell, no secrets, os/exec only where allowed
	python3 .github/scripts/check_rules.py

hooks-test: ## Self-test the Claude Code guard hooks
	python3 .claude/hooks/test_hooks.py

fmt: ## Format Go code
ifneq ($(HAS_GO),)
	gofmt -w $$(git ls-files '*.go')
endif

lint: ## gofmt check, go vet, golangci-lint
ifneq ($(HAS_GO),)
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "Not gofmt-ed:"; echo "$$out"; exit 1; fi
	$(GO) list ./... >/dev/null
	$(GO) vet ./...
	$(GOBIN)/golangci-lint run ./...
else
	@echo "lint: no Go packages yet"
endif

sec: ## gosec static security scan and gitleaks secret scan
ifneq ($(HAS_GO),)
	$(GOBIN)/gosec -quiet ./...
endif
	$(GOBIN)/gitleaks detect --source . --redact --no-banner

vuln: ## govulncheck: known vulnerabilities in dependencies
ifneq ($(HAS_GO),)
	$(GOBIN)/govulncheck ./...
else
	@echo "vuln: no Go packages yet"
endif

test: ## Tests with race detector, coverage and coverage gate
ifneq ($(HAS_GO),)
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	python3 .github/scripts/coverage_gate.py coverage.out
else
	@echo "test: no Go packages yet"
endif

fuzz-short: ## Run every Go fuzz test for FUZZTIME each (default 30s)
	@found=0; \
	for f in $$(git ls-files '*_test.go'); do \
	  for fn in $$(grep -oE '^func (Fuzz[A-Za-z0-9_]+)' $$f | awk '{print $$2}'); do \
	    found=1; pkg=./$$(dirname $$f); \
	    echo "== $$fn in $$pkg ($(FUZZTIME))"; \
	    $(GO) test -run='^$$' -fuzz="^$$fn$$" -fuzztime=$(FUZZTIME) $$pkg || exit 1; \
	  done; \
	done; \
	if [ $$found = 0 ]; then echo "fuzz-short: no fuzz tests yet"; fi

ci: rules hooks-test lint sec vuln test ## Everything CI runs, locally

build: ## Build binaries into ./bin
ifneq ($(HAS_GO),)
	@if [ -d cmd ]; then CGO_ENABLED=0 $(GO) build -trimpath -o bin/ ./cmd/...; else echo "build: no cmd/ yet"; fi
endif

clean: ## Remove build output
	rm -rf bin coverage.out
