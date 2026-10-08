SHELL := /bin/bash
.DEFAULT_GOAL := help

include deploy/compose/versions.env
export

# GOTOOLCHAIN=auto lets an older host Go fetch the toolchain go.work and go.mod declare (toolchain line); $(shell) does
# not see exported variables before GNU make 4.4, hence the explicit setting there.
export GOTOOLCHAIN := auto

COMPOSE_DIR   := deploy/compose
SECRETS_DIR   := $(COMPOSE_DIR)/.secrets
GO_MODULES    := $(shell GOTOOLCHAIN=$(GOTOOLCHAIN) go list -m -f '{{.Dir}}' | sed 's|^$(CURDIR)|.|')
GO_PACKAGES   := $(addsuffix /...,$(GO_MODULES))
UNIT_PACKAGES := $(filter-out ./test/acceptance/... ./test/system/...,$(GO_PACKAGES)) ./test/acceptance/cmd/devseed/...
WEB_DIR       := server/web
IMAGE         ?= paddock-server:dev
UID           := $(shell id -u)
GID           := $(shell id -g)

# BACKUP=1 adds the backups (plan M6a; compose.backup.yaml with the development wiring of compose.backup.dev.yaml).
BACKUP_FILES := $(if $(BACKUP),-f $(COMPOSE_DIR)/compose.backup.yaml -f $(COMPOSE_DIR)/compose.backup.dev.yaml,)
ifneq ($(BACKUP),)
export PADDOCK_BACKUP_S3_ENDPOINT ?= https://backup-s3-tls:9443
endif

COMPOSE := docker compose --project-directory $(COMPOSE_DIR) -p paddock \
	--env-file $(COMPOSE_DIR)/versions.env --env-file $(COMPOSE_DIR)/.env \
	-f $(COMPOSE_DIR)/compose.yaml -f $(COMPOSE_DIR)/compose.audit.yaml -f $(COMPOSE_DIR)/compose.dev.yaml $(BACKUP_FILES)

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
lint: lint-go lint-vuln lint-image lint-web lint-prometheus ## Run all linters, govulncheck and the server image build

# Prometheus configuration and alert rules (plan M6a decision 8): promtool check config, check rules and the rule tests
# of alerts_test.yml, in the pinned Prometheus image.
.PHONY: lint-prometheus
lint-prometheus:
	docker run --rm -v $(CURDIR)/$(COMPOSE_DIR)/prometheus:/etc/prometheus:ro -w /etc/prometheus --entrypoint sh \
		$(PROMETHEUS_IMAGE) -c 'promtool check config prometheus.yml && promtool check rules alerts.yml && \
			promtool test rules alerts_test.yml'

.PHONY: lint-go
lint-go:
	docker run --rm -v $(CURDIR):/src -w /src \
		-v paddock-gomod:/go/pkg/mod -v paddock-golangci-cache:/root/.cache \
		-e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false \
		$(GOLANGCI_LINT_IMAGE) golangci-lint run $(GO_PACKAGES)
	go vet $(GO_PACKAGES)
	go test -count=1 -run '^TestOpenAPISpec$$' ./server/internal/transport/http/admin/

# govulncheck checks every workspace module, including its tests, in the pinned Go image (plan M2.1 decision 2); a
# vulnerability in reachable code fails.
.PHONY: lint-vuln
lint-vuln:
	docker run --rm -v $(CURDIR):/src -w /src/server \
		-v paddock-gomod:/go/pkg/mod -v paddock-govulncheck-cache:/root/.cache \
		-e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false \
		$(GO_BUILD_IMAGE) sh -c 'set -e; \
			for m in $(GO_MODULES); do echo "govulncheck $$m"; go tool govulncheck -test -C /src/$$m ./...; done'

# The build stage of the server image compiles the Go workspace, so a commit that breaks the image fails lint (plan
# M2.1 decision 5); the compiler image (with visudo) is built as well (plan M3a decision 17).
.PHONY: lint-image
lint-image:
	@for target in build compiler; do \
		docker build --target $$target -f $(COMPOSE_DIR)/Dockerfile \
			--build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) --build-arg NODE_IMAGE=$(NODE_IMAGE) \
			--build-arg RUNTIME_IMAGE=$(RUNTIME_IMAGE) \
			--build-arg COMPILER_RUNTIME_IMAGE=$(COMPILER_RUNTIME_IMAGE) . || exit 1; \
	done

.PHONY: lint-web
lint-web:
	@if [ -f $(WEB_DIR)/package.json ]; then \
		$(NODE_RUN) sh -c 'npm ci --no-audit --no-fund >/dev/null && npm run lint && npm run typecheck'; \
	else echo "lint-web: no portal yet, skipped"; fi

.PHONY: typecheck
typecheck: ## Type-check every Go module (go vet, including tests) and the portal (vue-tsc, containerized)
	go vet $(GO_PACKAGES)
	@if [ -f $(WEB_DIR)/package.json ]; then $(NODE_RUN) sh -c 'npm ci --no-audit --no-fund >/dev/null && npm run typecheck'; fi

.PHONY: test
test: ## Unit and integration tests (requires Docker)
	go test -count=1 $(UNIT_PACKAGES)
	go test -count=1 -tags paddock_revoke_testtarget ./agent/internal/revoke/
	bash $(COMPOSE_DIR)/scripts/restore-drill-guard_test.sh
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
		--build-arg RUNTIME_IMAGE=$(RUNTIME_IMAGE) \
		--build-arg COMPILER_RUNTIME_IMAGE=$(COMPILER_RUNTIME_IMAGE) -t $(IMAGE) .

.PHONY: dev-secrets
dev-secrets: ## Generate local development secrets (idempotent)
	$(COMPOSE_DIR)/scripts/gen-dev-secrets.sh
	@$(MAKE) --no-print-directory dev-release-key

RELEASE_KEY_DIR := $(SECRETS_DIR)/release
MINISIGN        := cd agent && go run aead.dev/minisign/cmd/minisign

.PHONY: dev-release-key
dev-release-key: ## Generate the password-less development agent and revocation release key pairs (idempotent; never for production)
	@mkdir -p $(RELEASE_KEY_DIR) && chmod 700 $(RELEASE_KEY_DIR)
	@for key in minisign revoke-minisign; do \
		if [ -f $(RELEASE_KEY_DIR)/$$key.pub ]; then echo "release key exists: $(RELEASE_KEY_DIR)/$$key.pub"; else \
			($(MINISIGN) -G -W -p $(CURDIR)/$(RELEASE_KEY_DIR)/$$key.pub -s $(CURDIR)/$(RELEASE_KEY_DIR)/$$key.key </dev/null >/dev/null) && \
			chmod 644 $(RELEASE_KEY_DIR)/$$key.pub && chmod 600 $(RELEASE_KEY_DIR)/$$key.key && \
			echo "created development release key $(RELEASE_KEY_DIR)/$$key.pub" || exit 1; fi; \
	done

# --- Production (plan M6a, docs/operations/install.md) ------------------------------------------------------------
# HOST is the host of the two-host topology (controlplane or audit). A HOST variable inherited from the shell (zsh sets
# it to the machine name) is ignored; pass it on the make command line.
ifeq ($(origin HOST),environment)
HOST := controlplane
endif
HOST ?= controlplane
PROD_FILES_controlplane := compose.yaml compose.prod.yaml compose.backup.yaml
PROD_FILES_audit        := compose.audit.yaml compose.audit.prod.yaml
PROD_FILES               = $(PROD_FILES_$(HOST))
comma                   := ,
space                   := $(subst ,, )
PROD_COMPOSE             = docker compose --project-directory $(COMPOSE_DIR) -p paddock \
	--env-file $(COMPOSE_DIR)/versions.env --env-file $(COMPOSE_DIR)/.env $(foreach f,$(PROD_FILES),-f $(COMPOSE_DIR)/$(f))

.PHONY: prod-secrets
prod-secrets: ## Generate the production secrets of one host (HOST=controlplane|audit; idempotent, prints no secret)
	@test -n "$(PROD_FILES)" || { echo "usage: make prod-secrets HOST=controlplane|audit"; exit 2; }
	$(COMPOSE_DIR)/scripts/gen-prod-secrets.sh $(HOST)

# The check runs from source in the pinned Go image, so the host needs neither Go nor a built image; the repository is
# mounted read-only at its own path, where Compose resolved the secret files. ONLINE=1 (audit host) also reads the
# audit bucket's Object Lock configuration on the network paddock_audit-store.
.PHONY: prod-check
prod-check: ## Check the production configuration of one host (HOST=controlplane|audit, ONLINE=1): PASS/FAIL checklist
	@test -n "$(PROD_FILES)" || { echo "usage: make prod-check HOST=controlplane|audit [ONLINE=1]"; exit 2; }
	@set -o pipefail; $(PROD_COMPOSE) --profile '*' config --format json | \
		docker run --rm -i $(if $(ONLINE),--network paddock_audit-store,) \
			-v $(CURDIR):$(CURDIR):ro -w $(CURDIR) -v paddock-gomod:/go/pkg/mod \
			-e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false $(GO_BUILD_IMAGE) \
			go run ./server/cmd/paddock-server prod-check --host $(HOST) \
				--compose-files $(subst $(space),$(comma),$(strip $(PROD_FILES))) \
				--dev-release-key $(CURDIR)/$(RELEASE_KEY_DIR)/minisign.pub \
				--dev-release-key $(CURDIR)/$(RELEASE_KEY_DIR)/revoke-minisign.pub $(if $(ONLINE),--online,)

# Agent builds (plan M2b decisions 5, 17, 18, 25). VERSION is the agent version; TAGS adds build tags, e.g.
# TAGS=paddock_dev for the development probation and drift interval (system tests). The supervisor gets the release
# public key compiled in (default: the development key). paddock-revoke gets TAGS too (it reads agent.yml as paddockd
# does) and REVOKE_TAGS (plan M4c decision 13): paddock_revoke_testtarget for the system tests only, never in a release
# (agent-release refuses it).
VERSION                 ?= 0.0.0-dev
TAGS                    ?=
REVOKE_TAGS             ?=
RELEASE_PUBLIC_KEY_FILE ?= $(RELEASE_KEY_DIR)/minisign.pub
AGENT_LDFLAGS            = -s -w -X github.com/phischl/paddock-mdm/agent/internal/buildinfo.Version=$(VERSION)
AGENT_BUILD              = CGO_ENABLED=0 go build -trimpath -tags '$(TAGS)'

.PHONY: agent
agent: ## Build paddockd, paddock-supervisor and paddock-revoke for amd64 and arm64 into bin/agent/<arch>/ (VERSION, TAGS, REVOKE_TAGS)
	@test -s $(RELEASE_PUBLIC_KEY_FILE) || { echo "missing $(RELEASE_PUBLIC_KEY_FILE): run make dev-release-key"; exit 1; }
	@for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch $(AGENT_BUILD) -ldflags '$(AGENT_LDFLAGS)' -o bin/agent/$$arch/paddockd ./agent/cmd/paddockd && \
		GOOS=linux GOARCH=$$arch $(AGENT_BUILD) -ldflags '$(AGENT_LDFLAGS) -X main.releasePublicKey=$(shell sed -n 2p $(RELEASE_PUBLIC_KEY_FILE))' \
			-o bin/agent/$$arch/paddock-supervisor ./agent/cmd/paddock-supervisor && \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -tags '$(TAGS) $(REVOKE_TAGS)' -ldflags '$(AGENT_LDFLAGS)' \
			-o bin/agent/$$arch/paddock-revoke ./agent/cmd/paddock-revoke || exit 1; \
	done
	@echo "built bin/agent/{amd64,arm64}/{paddockd,paddock-supervisor,paddock-revoke} $(VERSION) $(TAGS) $(REVOKE_TAGS)"

.PHONY: deb
deb: agent ## Build the paddock-supervisor, paddock-agent and paddock-revoke Debian packages for amd64 into bin/deb/ (VERSION, TAGS, REVOKE_TAGS)
	rm -f bin/deb/*.deb && mkdir -p bin/deb/stage
	cp bin/agent/amd64/paddockd bin/agent/amd64/paddock-supervisor bin/agent/amd64/paddock-revoke bin/deb/stage/
	for pkg in paddock-supervisor paddock-agent paddock-revoke; do \
		printf '%s (%s) unstable; urgency=medium\n\n  * Release %s; see CHANGELOG.md.\n\n -- Paddock <paddock@paddock-mdm.invalid>  %s\n' \
			$$pkg $(VERSION) $(VERSION) "$$(date -R -u)" | gzip -9n >bin/deb/stage/$$pkg.changelog.gz && \
		docker run --rm -u $(UID):$(GID) -v $(CURDIR):/src -w /src -e ARCH=amd64 -e VERSION=$(VERSION) $(NFPM_IMAGE) \
			package --config packaging/nfpm/$$pkg.yaml --packager deb --target bin/deb/ || exit 1; \
	done
	@ls -1 bin/deb/*.deb

# fleetd (plan M5a decision 3): fleetctl packages orbit and osquery from Fleet's update server (needs outbound HTTPS)
# without enroll secret, scripts, Fleet Desktop or auto-updates. fleetctl accepts a Fleet URL only together with an
# enroll secret, so the package has neither: the agent installs it and gives fleetd both from the bundle.
.PHONY: fleetd-deb
fleetd-deb: ## Build the fleetd Debian package fleet-osquery (amd64) with fleetctl into bin/fleetd/
	rm -rf bin/fleetd && mkdir -p bin/fleetd
	docker run --rm -u $(UID):$(GID) -e HOME=/tmp -e USER=paddock -v $(CURDIR)/bin/fleetd:/out -w /out $(FLEETCTL_IMAGE) \
		package --type deb --arch amd64 --enable-scripts=false --disable-updates --fleet-desktop=false --disable-open-folder
	mv bin/fleetd/build/fleet-osquery_*_amd64.deb bin/fleetd/ && rm -rf bin/fleetd/build
	@ls -1 bin/fleetd/fleet-osquery_*_amd64.deb

.PHONY: agent-release
agent-release: ## Build paddockd, the Debian packages VERSION (TAGS) and fleetd, sign them with the development release key and upload and publish them
	@test -n "$(filter-out 0.0.0-dev,$(VERSION))" || { echo "usage: make agent-release VERSION=x.y.z [TAGS=...]"; exit 1; }
	@test -z "$(REVOKE_TAGS)" || { echo "agent-release never builds paddock-revoke with REVOKE_TAGS ($(REVOKE_TAGS))"; exit 1; }
	$(MAKE) --no-print-directory deb VERSION=$(VERSION) TAGS='$(TAGS)'
	$(MAKE) --no-print-directory fleetd-deb
	go run ./test/acceptance/cmd/agentrelease --version $(VERSION) --publish \
		--artifact amd64=bin/agent/amd64/paddockd --artifact arm64=bin/agent/arm64/paddockd \
		$$(for f in bin/deb/*.deb bin/fleetd/*.deb; do printf -- '--deb %s ' "$$f"; done)

.PHONY: up
up: ## Start the full stack (infrastructure, OpenBao/bucket bootstrap, Paddock roles) and wait until healthy (BACKUP=1: with backups)
	$(COMPOSE) up -d $(if $(BACKUP),--build,)
	$(COMPOSE_DIR)/scripts/wait-healthy.sh
	$(COMPOSE_DIR)/scripts/openbao-bootstrap.sh
	$(COMPOSE_DIR)/scripts/rustfs-audit-bootstrap.sh
	$(COMPOSE_DIR)/scripts/rustfs-bundles-bootstrap.sh
	$(COMPOSE_DIR)/scripts/fleet-bootstrap.sh
	$(if $(BACKUP),$(COMPOSE_DIR)/scripts/rustfs-backup-bootstrap.sh,)
	$(COMPOSE) --profile paddock --profile observability up -d --build
	$(COMPOSE_DIR)/scripts/wait-healthy.sh --profile paddock

.PHONY: down
down: ## Stop the stack (pass V=1 to delete volumes)
	$(COMPOSE) --profile paddock --profile observability down $(if $(V),-v,)

.PHONY: restore-drill
restore-drill: ## Restore drill on the development stack (started with make up BACKUP=1): backup, loss, restore, RTO; destroys the databases' volumes
	$(COMPOSE_DIR)/scripts/restore-drill.sh

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

.PHONY: fleet-bootstrap
fleet-bootstrap: ## Set up Fleet: admin user, API-only user paddock (token), global enroll secret (development)
	$(COMPOSE_DIR)/scripts/fleet-bootstrap.sh

.PHONY: dev-seed
dev-seed: ## Create organizations acme and globex and assign the dev users
	go run ./test/acceptance/cmd/devseed

# Guard against hangs; suite ~35 min since M4c. Slower machines (CI runners) raise ACCEPTANCE_TIMEOUT.
ACCEPTANCE_TIMEOUT ?= 45m

.PHONY: acceptance
# The exactly-once gate checks about 180 cases of ≈ 11 s each (delivery plus the 5 s settle check); they run in
# parallel, PADDOCK_ACCEPTANCE_PARALLEL at a time (default 8).
acceptance: ## Run acceptance gates against the running stack (optional T=<regex>, PADDOCK_ACCEPTANCE_PARALLEL, ACCEPTANCE_TIMEOUT)
	go test -count=1 -timeout $(ACCEPTANCE_TIMEOUT) ./test/acceptance/... $(if $(T),-run '$(T)',) -v

.PHONY: system-test
system-test: ## Run the agent system tests on the VirtualBox VMs against the running stack (VM=<vm|all>, optional T=<regex>)
	@test -n "$(VM)" || { echo "usage: make system-test VM=<paddock-u2404|paddock-u2604|all> [T=<regex>]"; exit 1; }
	$(MAKE) --no-print-directory deb VERSION=0.1.0 TAGS=paddock_dev REVOKE_TAGS=paddock_revoke_testtarget
	$(MAKE) --no-print-directory fleetd-deb
	CGO_ENABLED=0 go build -trimpath -o bin/revoke-release/paddock-revoke ./agent/cmd/paddock-revoke
	CGO_ENABLED=0 go build -o bin/agentrelease ./test/acceptance/cmd/agentrelease
	PADDOCK_SYSTEM_VMS=$(VM) go test -count=1 -timeout 8h ./test/system/... $(if $(T),-run '$(T)',) -v

.PHONY: e2e
e2e: ## Run Playwright end-to-end tests against the running stack
	CGO_ENABLED=0 go build -o bin/devicesim ./test/acceptance/cmd/devicesim
	CGO_ENABLED=0 go build -o bin/agentrelease ./test/acceptance/cmd/agentrelease
	docker run --rm --network host -u $(UID):$(GID) -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
		-e PADDOCK_E2E_SECRETS=/src/$(SECRETS_DIR) -e PADDOCK_E2E_DEVICESIM=/src/bin/devicesim \
		-e PADDOCK_E2E_AGENTRELEASE=/src/bin/agentrelease \
		-v $(CURDIR):/src -w /src/$(WEB_DIR) \
		$(PLAYWRIGHT_IMAGE) sh -c 'npm ci --no-audit --no-fund >/dev/null && npx playwright test'

.PHONY: ci
ci: lint test web ## Everything CI runs

.PHONY: logs
logs: ## Show logs of the stack
	$(COMPOSE) --profile paddock logs --no-color --tail 300

# --- Security scans (CI jobs `secrets` and `trivy`) --------------------------------------------------------------
TRIVY_CACHE     ?= $(HOME)/.cache/trivy
TRIVY_ARGS      := --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress
COMPILER_IMAGE  ?= paddock-compiler:dev
PGBACKREST_IMAGE ?= paddock-pgbackrest:dev

.PHONY: scan scan-secrets scan-fs scan-images image-compiler image-pgbackrest
scan: scan-secrets scan-fs scan-images ## Run gitleaks (full history) and trivy (filesystem and images)

scan-secrets: ## gitleaks over the full git history (false positives: .gitleaksignore)
	docker run --rm -v $(CURDIR):/repo $(GITLEAKS_IMAGE) git /repo --no-banner --redact

scan-fs: ## trivy: dependencies, misconfiguration and secrets in the working tree
	mkdir -p $(TRIVY_CACHE)
	docker run --rm -v $(CURDIR):/src:ro -v $(TRIVY_CACHE):/root/.cache/trivy $(TRIVY_IMAGE) fs \
		--scanners vuln,misconfig,secret $(TRIVY_ARGS) \
		--skip-dirs /src/server/web/node_modules --skip-dirs /src/bin --skip-dirs /src/test/vms/virtualbox/work /src

image-compiler: ## Build the compiler container image
	docker build --target compiler -f $(COMPOSE_DIR)/Dockerfile \
		--build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) --build-arg NODE_IMAGE=$(NODE_IMAGE) \
		--build-arg RUNTIME_IMAGE=$(RUNTIME_IMAGE) \
		--build-arg COMPILER_RUNTIME_IMAGE=$(COMPILER_RUNTIME_IMAGE) -t $(COMPILER_IMAGE) .

image-pgbackrest: ## Build the pgBackRest image of the backups (compose.backup.yaml)
	docker build -f $(COMPOSE_DIR)/pgbackrest/Dockerfile \
		--build-arg COMPILER_RUNTIME_IMAGE=$(COMPILER_RUNTIME_IMAGE) -t $(PGBACKREST_IMAGE) .

scan-images: image image-compiler image-pgbackrest ## trivy: OS packages and Go binaries in the built images
	mkdir -p $(TRIVY_CACHE)
	for img in $(IMAGE) $(COMPILER_IMAGE) $(PGBACKREST_IMAGE); do \
		docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v $(TRIVY_CACHE):/root/.cache/trivy \
			$(TRIVY_IMAGE) image $(TRIVY_ARGS) $$img || exit 1; \
	done
