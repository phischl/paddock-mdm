SHELL := /bin/bash
.DEFAULT_GOAL := help

include deploy/compose/versions.env
export

COMPOSE_DIR   := deploy/compose
SECRETS_DIR   := $(COMPOSE_DIR)/.secrets
GO_MODULES    := $(shell go list -m -f '{{.Dir}}' | sed 's|^$(CURDIR)|.|')
GO_PACKAGES   := $(addsuffix /...,$(GO_MODULES))
UNIT_PACKAGES := $(filter-out ./test/acceptance/...,$(GO_PACKAGES)) ./test/acceptance/cmd/devseed/...
WEB_DIR       := server/web
IMAGE         ?= paddock-server:dev
UID           := $(shell id -u)
GID           := $(shell id -g)

# GOTOOLCHAIN=local keeps every build on the toolchain the module declares (go 1.25).
export GOTOOLCHAIN := local

COMPOSE := docker compose --project-directory $(COMPOSE_DIR) -p paddock \
	--env-file $(COMPOSE_DIR)/versions.env --env-file $(COMPOSE_DIR)/.env \
	-f $(COMPOSE_DIR)/compose.yaml -f $(COMPOSE_DIR)/compose.audit.yaml -f $(COMPOSE_DIR)/compose.dev.yaml

NODE_RUN := docker run --rm -u $(UID):$(GID) -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
	-v $(CURDIR):/src -w /src/$(WEB_DIR) $(NODE_IMAGE)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-16s %s\n", $$1, $$2}'

.PHONY: build
build: ## Build ./paddock-server for the host
	CGO_ENABLED=0 go build -trimpath -o paddock-server ./server/cmd/paddock-server

.PHONY: gen
gen: ## Generate sqlc, oapi-codegen, TypeScript API types and the audit code document
	cd server && go generate ./...
	@if [ -f $(WEB_DIR)/package.json ]; then $(NODE_RUN) npm run gen; fi

.PHONY: lint
lint: lint-go lint-web ## Run all linters

.PHONY: lint-go
lint-go:
	docker run --rm -v $(CURDIR):/src -w /src \
		-v paddock-gomod:/go/pkg/mod -v paddock-golangci-cache:/root/.cache \
		-e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false \
		$(GOLANGCI_LINT_IMAGE) golangci-lint run $(GO_PACKAGES)
	go vet $(GO_PACKAGES)
	go test -count=1 -run '^TestOpenAPISpec$$' ./server/internal/transport/http/admin/

.PHONY: lint-web
lint-web:
	@if [ -f $(WEB_DIR)/package.json ]; then \
		$(NODE_RUN) sh -c 'npm ci --no-audit --no-fund >/dev/null && npm run lint && npm run typecheck'; \
	else echo "lint-web: no portal yet, skipped"; fi

.PHONY: test
test: ## Unit and integration tests (requires Docker)
	go test -count=1 $(UNIT_PACKAGES)
	@if [ -f $(WEB_DIR)/package.json ]; then $(NODE_RUN) sh -c 'npm ci --no-audit --no-fund >/dev/null && npm run test'; fi

.PHONY: fuzz
fuzz: ## Run every fuzz test of pkg for FUZZTIME each (default 30s)
	@for target in $$(grep -rhoE '^func Fuzz[A-Za-z0-9_]+' pkg --include='*_test.go' | sed 's/^func //'); do \
		dir=$$(grep -rlE "^func $$target\(" pkg --include='*_test.go' | xargs dirname); \
		echo "fuzz $$target ($$dir)"; \
		go test -run '^$$' -fuzz "^$$target$$" -fuzztime $(or $(FUZZTIME),30s) ./$$dir/ || exit 1; \
	done

.PHONY: web
web: ## Build the portal into server/web/dist (containerized)
	@if [ -f $(WEB_DIR)/package.json ]; then \
		$(NODE_RUN) sh -c 'npm ci --no-audit --no-fund >/dev/null && npm run build'; \
	else echo "web: no portal yet, skipped"; fi

.PHONY: image
image: ## Build the paddock-server container image
	docker build -f $(COMPOSE_DIR)/Dockerfile \
		--build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) --build-arg NODE_IMAGE=$(NODE_IMAGE) \
		--build-arg RUNTIME_IMAGE=$(RUNTIME_IMAGE) -t $(IMAGE) .

.PHONY: dev-secrets
dev-secrets: ## Generate local development secrets (idempotent)
	$(COMPOSE_DIR)/scripts/gen-dev-secrets.sh

.PHONY: up
up: ## Start the full stack (infrastructure, OpenBao/bucket bootstrap, Paddock roles) and wait until healthy
	$(COMPOSE) up -d
	$(COMPOSE_DIR)/scripts/wait-healthy.sh
	$(COMPOSE_DIR)/scripts/openbao-bootstrap.sh
	$(COMPOSE_DIR)/scripts/rustfs-audit-bootstrap.sh
	$(COMPOSE_DIR)/scripts/rustfs-bundles-bootstrap.sh
	$(COMPOSE) --profile paddock up -d --build
	$(COMPOSE_DIR)/scripts/wait-healthy.sh --profile paddock

.PHONY: down
down: ## Stop the stack (pass V=1 to delete volumes)
	$(COMPOSE) --profile paddock down $(if $(V),-v,)

.PHONY: bao-bootstrap
bao-bootstrap: ## Initialize and unseal OpenBao, create keys, policies and AppRoles (development)
	$(COMPOSE_DIR)/scripts/openbao-bootstrap.sh

.PHONY: bao-unseal
bao-unseal: ## Unseal OpenBao with the stored development shares
	$(COMPOSE_DIR)/scripts/openbao-bootstrap.sh unseal

.PHONY: audit-bootstrap
audit-bootstrap: ## Create the WORM audit bucket and the writer credential
	$(COMPOSE_DIR)/scripts/rustfs-audit-bootstrap.sh

.PHONY: bundles-bootstrap
bundles-bootstrap: ## Create the bundles bucket and the compiler and gateway credentials
	$(COMPOSE_DIR)/scripts/rustfs-bundles-bootstrap.sh

.PHONY: dev-seed
dev-seed: ## Create organizations acme and globex and assign the dev users
	go run ./test/acceptance/cmd/devseed

.PHONY: acceptance
acceptance: ## Run acceptance gates against the running stack (optional T=<regex>)
	go test -count=1 -timeout 30m ./test/acceptance/... $(if $(T),-run '$(T)',) -v

.PHONY: e2e
e2e: ## Run Playwright end-to-end tests against the running stack
	CGO_ENABLED=0 go build -o bin/devicesim ./test/acceptance/cmd/devicesim
	docker run --rm --network host -u $(UID):$(GID) -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
		-e PADDOCK_E2E_SECRETS=/src/$(SECRETS_DIR) -e PADDOCK_E2E_DEVICESIM=/src/bin/devicesim \
		-v $(CURDIR):/src -w /src/$(WEB_DIR) \
		$(PLAYWRIGHT_IMAGE) sh -c 'npm ci --no-audit --no-fund >/dev/null && npx playwright test'

.PHONY: ci
ci: lint test web ## Everything CI runs

.PHONY: logs
logs: ## Show logs of the stack
	$(COMPOSE) --profile paddock logs --no-color --tail 300
