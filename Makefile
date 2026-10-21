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
UNIT_PACKAGES := $(filter-out ./test/acceptance/... ./test/system/...,$(GO_PACKAGES)) ./test/acceptance/cmd/devseed/... \
	./test/acceptance/cmd/acceptanceshard/...
WEB_DIR       := server/web
IMAGE         ?= paddock-server:dev
UID           := $(shell id -u)
GID           := $(shell id -g)

# The Compose file sets live in scripts/lib.sh (plan M7b decision 18); lib_files reads one of its variables.
# SECRETS_DIR is not exported: lib.sh takes an exported SECRETS_DIR as an override, and this one is relative.
LIB_SH    := $(COMPOSE_DIR)/scripts/lib.sh
lib_files  = $(shell sed -n 's/^$(1)="\(.*\)"$$/\1/p' $(LIB_SH))
unexport SECRETS_DIR

# BACKUP=1 adds the backups (plan M6a; compose.backup.yaml with the development wiring of compose.backup.dev.yaml).
BACKUP_FILES := $(if $(BACKUP),$(call lib_files,DEV_BACKUP_FILES),)
ifneq ($(BACKUP),)
export PADDOCK_BACKUP_S3_ENDPOINT ?= https://backup-s3-tls:9443
endif

COMPOSE := docker compose --project-directory $(COMPOSE_DIR) -p paddock \
	--env-file $(COMPOSE_DIR)/versions.env --env-file $(COMPOSE_DIR)/.env \
	$(foreach f,$(call lib_files,DEV_FILES) $(BACKUP_FILES),-f $(COMPOSE_DIR)/$(f))

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
	cd cli && go generate ./...
	@if [ -f $(WEB_DIR)/package.json ]; then $(NODE_RUN) npm run gen; fi

.PHONY: lint
lint: lint-go lint-vuln lint-image lint-web lint-prometheus lint-caddy lint-licenses lint-supervisor-budget ## Run all linters, govulncheck, the license gate and the server image build

# The supervisor's line budget (plan M2b decision 15, amendment 2026-10-12): at most 800 non-blank, non-comment lines of
# non-test Go code across agent/internal/supervisor/ and agent/cmd/paddock-supervisor/.
.PHONY: lint-supervisor-budget
lint-supervisor-budget:
	bash test/supervisor-budget.sh

# License gate (plan M6b decision 3, C8): every Go dependency of every workspace module (go-licenses, pinned, run with
# go run in the pinned Go image) and every npm production dependency of the portal (license-checker-rseidelsohn,
# dev dependency, its JSON evaluated as SPDX expressions by scripts/check-licenses.ts: AND needs every license allowed,
# OR one) must carry a license of the allow list; anything else fails with the package name. go-licenses resolves
# the imports for linux/amd64 only. Paddock's own packages are MIT (LICENSE). Bundled container images:
# docs/compliance/third-party.md.
GO_LICENSES_VERSION := v2.0.1
ALLOWED_LICENSES    := MIT ISC BSD-2-Clause BSD-3-Clause Apache-2.0 MPL-2.0 BlueOak-1.0.0 0BSD CC0-1.0 Python-2.0 Unlicense

.PHONY: lint-licenses
lint-licenses: ## License gate: Go and npm production dependencies against the allow list
	docker run --rm -v $(CURDIR):/src -w /src \
		-v paddock-gomod:/go/pkg/mod -v paddock-golicenses-cache:/root/.cache \
		-e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false \
		$(GO_BUILD_IMAGE) sh -c 'set -e; \
			for m in $(GO_MODULES); do echo "go-licenses $$m"; cd /src/$$m; \
				go run github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION) check ./... \
					--ignore github.com/phischl/paddock-mdm \
					--allowed_licenses=$(subst $(space),$(comma),$(ALLOWED_LICENSES)); done'
	@if [ -f $(WEB_DIR)/package.json ]; then \
		$(NODE_RUN) sh -c 'set -e; npm ci --no-audit --no-fund >/dev/null; \
			npx license-checker-rseidelsohn --production --excludePrivatePackages --json --out /tmp/licenses.json; \
			node scripts/check-licenses.ts /tmp/licenses.json "$(subst $(space),;,$(ALLOWED_LICENSES))"'; \
	else echo "lint-licenses: no portal yet, skipped"; fi

# Prometheus configuration and alert rules (plan M6a decision 8): promtool check config, check rules and the rule tests
# of alerts_test.yml, in the pinned Prometheus image.
.PHONY: lint-prometheus
lint-prometheus:
	docker run --rm -v $(CURDIR)/$(COMPOSE_DIR)/prometheus:/etc/prometheus:ro -w /etc/prometheus --entrypoint sh \
		$(PROMETHEUS_IMAGE) -c 'promtool check config prometheus.yml && promtool check rules alerts.yml && \
			promtool test rules alerts_test.yml'

# Edge entrypoint (plan M7a step 1): validation messages, the rendered servers block and `caddy validate` of both
# Caddyfiles with that block, in the pinned Caddy image.
.PHONY: lint-caddy
lint-caddy:
	docker run --rm -v $(CURDIR)/$(COMPOSE_DIR)/caddy:/test:ro --entrypoint sh $(CADDY_IMAGE) /test/entrypoint_test.sh

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
# M2.1 decision 5); the compiler image (with visudo) is built as well (plan M3a decision 17). The build stage is also
# cross-compiled for arm64 (on the build platform, no QEMU), so a commit that breaks the published arm64 images fails
# lint too (plan M7b decision 20).
.PHONY: lint-image
lint-image:
	@for target in build compiler build/linux/arm64; do \
		docker build --target $${target%%/*} $$(case $$target in */*) echo --platform $${target#*/};; esac) \
			-f $(COMPOSE_DIR)/Dockerfile \
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
	bash $(COMPOSE_DIR)/scripts/load-guard_test.sh
	bash $(COMPOSE_DIR)/scripts/wait-healthy_test.sh
	bash $(COMPOSE_DIR)/scripts/openbao-restore_test.sh
	bash $(COMPOSE_DIR)/scripts/rustfs-alias_test.sh
	bash $(COMPOSE_DIR)/scripts/secrets-argv_test.sh
	bash $(COMPOSE_DIR)/scripts/fleet-bootstrap_test.sh
	bash packaging/release_test.sh
	bash deploy/bundle/bundle_test.sh
	bash deploy/bundle/ci/prune-edge_test.sh
	bash deploy/bundle/ci/assert-hardening_test.sh
	bash test/scan-secrets_test.sh
	bash test/supervisor-budget_test.sh
	$(MAKE) --no-print-directory image-pgbackrest
	PADDOCK_PGBACKREST_IMAGE=$(PGBACKREST_IMAGE) bash $(COMPOSE_DIR)/pgbackrest/pgbackrest_test.sh
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

# --- Operator bundle (plan M7b decisions 20–22, ADR 0022, docs/operations/install.md) -----------------------------
# Production hosts run the bundle's ./paddock; make is not used there. `make bundle` builds a local bundle that
# references the local images by tag (from source: make image image-compiler image-pgbackrest bundle).
comma          := ,
space          := $(subst ,, )
BUNDLE_VERSION  = $(or $(RELEASE_VERSION),0.0.0-local)

.PHONY: bundle
bundle: ## Build a local operator bundle of the local images (IMAGE, COMPILER_IMAGE, PGBACKREST_IMAGE) into dist/bundle/
	LOCAL_SERVER_IMAGE=$(IMAGE) LOCAL_COMPILER_IMAGE=$(COMPILER_IMAGE) LOCAL_PGBACKREST_IMAGE=$(PGBACKREST_IMAGE) \
		deploy/bundle/build.sh --version $(BUNDLE_VERSION) --channel local --images local --out dist/bundle

.PHONY: bundle-test
bundle-test: ## Drift test of the operator bundle against deploy/compose/ (part of make test)
	bash deploy/bundle/bundle_test.sh

.PHONY: bundle-smoke-lab
bundle-smoke-lab: ## Smoke test of the lab profile of the local bundle behind Nginx (plan M8a decision 18; binds 80, 443, 8080)
	deploy/bundle/ci/smoke-lab.sh dist/bundle/paddock-deploy-0.0.0-local.tar.gz

# Agent builds (plan M2b decisions 5, 17, 18, 25). VERSION is the agent version; TAGS adds build tags, e.g.
# TAGS=paddock_dev for the development probation and drift interval (system tests). The supervisor gets the release
# public key compiled in (default: the development key). paddock-revoke gets TAGS too (it reads agent.yml as paddockd
# does) and REVOKE_TAGS (plan M4c decision 13): paddock_revoke_testtarget for the system tests only, never in a release
# (agent-release refuses it).
VERSION                 ?= 0.0.0-dev
# The Debian version of VERSION: a SemVer pre-release 0.1.0-alpha.1 becomes 0.1.0~alpha.1, which sorts before 0.1.0
# (nfpm's semver handling names the package so; `deb` checks that it did).
DEB_VERSION              = $(shell printf '%s' '$(VERSION)' | sed 's/-/~/')
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
			$$pkg $(DEB_VERSION) $(VERSION) "$$(date -R -u)" | gzip -9n >bin/deb/stage/$$pkg.changelog.gz && \
		docker run --rm -u $(UID):$(GID) -v $(CURDIR):/src -w /src -e ARCH=amd64 -e VERSION=$(VERSION) $(NFPM_IMAGE) \
			package --config packaging/nfpm/$$pkg.yaml --packager deb --target bin/deb/ || exit 1; \
		test -f bin/deb/$${pkg}_$(DEB_VERSION)_amd64.deb || { echo "nfpm did not build bin/deb/$${pkg}_$(DEB_VERSION)_amd64.deb"; exit 1; }; \
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
	@test -z "$(filter paddock_testbroken_supervisor,$(subst $(comma), ,$(TAGS)))" || { echo "agent-release never builds a broken supervisor (TAGS=$(TAGS))"; exit 1; }
	$(MAKE) --no-print-directory deb VERSION=$(VERSION) TAGS='$(TAGS)'
	$(MAKE) --no-print-directory fleetd-deb
	go run ./test/acceptance/cmd/agentrelease --version $(VERSION) --publish \
		--artifact amd64=bin/agent/amd64/paddockd --artifact arm64=bin/agent/arm64/paddockd \
		$$(for f in bin/deb/*.deb bin/fleetd/*.deb; do printf -- '--deb %s ' "$$f"; done)

.PHONY: up
# dev-secrets first: it only creates missing files, so a stack started before a new secret existed gets it on upgrade.
# OpenBao is bootstrapped (and so unsealed) before the first wait: a recreated OpenBao starts sealed, and role
# containers still running from an earlier `make up` cannot get healthy until it is unsealed.
up: dev-secrets ## Start the full stack (infrastructure, OpenBao/bucket bootstrap, Paddock roles) and wait until healthy (BACKUP=1: with backups)
	$(COMPOSE) up -d $(if $(BACKUP),--build,)
	$(COMPOSE_DIR)/scripts/postgres-unsealer-role.sh
	$(COMPOSE_DIR)/scripts/openbao-bootstrap.sh
	$(COMPOSE_DIR)/scripts/wait-healthy.sh
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

# Guard against hangs; the whole suite took ~85 min on a development machine and ~82 min on a GitHub runner since M8x
# (measured 2026-10-18) and 101 min on a GitHub runner on 2026-10-21 (PR #118). CI therefore runs it in shards
# (SHARD=i/n, PDK-359), each against its own stack: with three shards ~27-29 min of measured gate time each, about
# 35 min per `make acceptance` step on a runner. Keep at least 20 % headroom when gates are added.
ACCEPTANCE_TIMEOUT ?= 120m

# paddockctl is static and has no runtime dependencies (plan M6c decision 24); Linux amd64 and arm64 only.
PADDOCKCTL_LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: paddockctl
paddockctl: ## Build paddockctl for amd64 and arm64 into bin/paddockctl/<arch>/ (VERSION)
	@for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(PADDOCKCTL_LDFLAGS)" \
			-o bin/paddockctl/$$arch/paddockctl ./cli/cmd/paddockctl || exit 1; \
	done
	@echo "built bin/paddockctl/{amd64,arm64}/paddockctl $(VERSION)"

.PHONY: acceptance
# The exactly-once gate checks about 180 cases of ≈ 11 s each (delivery plus the 5 s settle check); they run in
# parallel, PADDOCK_ACCEPTANCE_PARALLEL at a time (default 8).
# SHARD=i/n runs shard i of n: test/acceptance/cmd/acceptanceshard puts every listed test into exactly one shard,
# balanced by test/acceptance/shard-weights.txt.
acceptance: ## Run acceptance gates against the running stack (optional T=<regex> or SHARD=<i/n>, PADDOCK_ACCEPTANCE_PARALLEL, ACCEPTANCE_TIMEOUT, PADDOCK_ACCEPTANCE_DISRUPTIVE=1 for TestSessionsEndAll and TestAutoUnsealRestart)
	CGO_ENABLED=0 go build -trimpath -o bin/paddockctl/paddockctl ./cli/cmd/paddockctl
	@set -eo pipefail; run='$(T)'; \
	if [ -n '$(SHARD)' ]; then \
		[ -z "$$run" ] || { echo "acceptance: T and SHARD are mutually exclusive" >&2; exit 1; }; \
		run="$$(go test -list '.*' ./test/acceptance/... | \
			go run ./test/acceptance/cmd/acceptanceshard -shard '$(SHARD)' -weights test/acceptance/shard-weights.txt)"; \
		echo "acceptance shard $(SHARD): -run '$$run'"; \
	fi; \
	set --; [ -z "$$run" ] || set -- -run "$$run"; \
	set -x; PADDOCK_ACCEPTANCE_PADDOCKCTL=$(CURDIR)/bin/paddockctl/paddockctl \
		go test -count=1 -timeout $(ACCEPTANCE_TIMEOUT) ./test/acceptance/... "$$@" -v

.PHONY: system-test
system-test: ## Run the agent system tests on the VirtualBox VMs against the running stack (VM=<vm|all>, optional T=<regex>)
	@test -n "$(VM)" || { echo "usage: make system-test VM=<paddock-u2404|paddock-u2604|all> [T=<regex>]"; exit 1; }
	$(MAKE) --no-print-directory deb VERSION=0.1.0 TAGS=paddock_dev REVOKE_TAGS=paddock_revoke_testtarget
	$(MAKE) --no-print-directory fleetd-deb
	CGO_ENABLED=0 go build -trimpath -o bin/revoke-release/paddock-revoke ./agent/cmd/paddock-revoke
	CGO_ENABLED=0 go build -o bin/agentrelease ./test/acceptance/cmd/agentrelease
	PADDOCK_SYSTEM_VMS=$(VM) go test -count=1 -timeout 8h ./test/system/... $(if $(T),-run '$(T)',) -v

# The Playwright image ships the browsers of exactly one @playwright/test version (PDK-290): refuse a mismatch before
# any test runs instead of failing on missing browsers. Dependabot ignores the package; bump both together.
.PHONY: e2e-check-playwright
e2e-check-playwright:
	@npm="$$(sed -n 's/.*"@playwright\/test": "\([^"]*\)".*/\1/p' $(WEB_DIR)/package.json)"; \
	image="$$(printf '%s\n' '$(PLAYWRIGHT_IMAGE)' | sed -n 's/.*playwright:v\([^-]*\)-.*/\1/p')"; \
	if [ -z "$$npm" ] || [ "$$npm" != "$$image" ]; then \
		echo "@playwright/test $$npm in server/web/package.json does not match PLAYWRIGHT_IMAGE v$$image in deploy/compose/versions.env; bump both together" >&2; \
		exit 1; \
	fi

.PHONY: e2e
e2e: e2e-check-playwright ## Run Playwright end-to-end tests against the running stack (PADDOCK_E2E_SCREENSHOTS=1 also writes the README screenshots)
	CGO_ENABLED=0 go build -o bin/devicesim ./test/acceptance/cmd/devicesim
	CGO_ENABLED=0 go build -o bin/agentrelease ./test/acceptance/cmd/agentrelease
	docker run --rm --network host -u $(UID):$(GID) -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
		-e PADDOCK_E2E_SECRETS=/src/$(SECRETS_DIR) -e PADDOCK_E2E_DEVICESIM=/src/bin/devicesim \
		-e PADDOCK_E2E_AGENTRELEASE=/src/bin/agentrelease -e PADDOCK_E2E_SCREENSHOTS \
		-v $(CURDIR):/src -w /src/$(WEB_DIR) \
		$(PLAYWRIGHT_IMAGE) sh -c 'npm ci --no-audit --no-fund >/dev/null && npx playwright test'

# Load test (plan M6b decision 1, docs/operations/capacity.md). Both run on the Compose network paddock_cp and talk to
# one gateway replica directly (http://paddock-gateway:8081), each device with its own X-Paddock-Client-IP address.
LOAD_DIR := bin/load
COUNT    ?= 10000
SCENARIO ?= checkin
# Never against production (PDK-006 review 1): load-guard.sh refuses unless the running gateway of the project paddock
# is not PADDOCK_ENV=production and the checkout is a development one.
LOAD_GUARD = gw=$$(docker ps -q --filter label=com.docker.compose.project=paddock \
		--filter label=com.docker.compose.service=paddock-gateway | head -1); \
	gw_env=$$([ -n "$$gw" ] && docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' $$gw | \
		sed -n 's/^PADDOCK_ENV=//p' | tail -1); \
	bash $(COMPOSE_DIR)/scripts/load-guard.sh $(COMPOSE_DIR) "$$gw_env" $$(docker ps -a \
		--filter label=com.docker.compose.project=paddock --format '{{.Label "com.docker.compose.project.config_files"}}' | \
		tr ',' '\n' | sort -u)

.PHONY: load-identities
load-identities: ## Enroll COUNT load test devices with the enrollment configurations CONFIGS (auto-approving tokens) into bin/load/identities.json
	@test -n "$(CONFIGS)" || { echo "usage: make load-identities CONFIGS='token-1.json token-2.json …' [COUNT=10000]"; exit 2; }
	@$(LOAD_GUARD)
	CGO_ENABLED=0 go build -trimpath -o $(LOAD_DIR)/identities ./test/load/cmd/identities
	docker run --rm --network paddock_cp -u $(UID):$(GID) -v $(CURDIR):/src -w /src $(RUNTIME_IMAGE) \
		/src/$(LOAD_DIR)/identities $(foreach c,$(CONFIGS),--config $(c)) --count $(COUNT) \
		--server http://paddock-gateway:8081 --client-ip --out $(LOAD_DIR)/identities.json

.PHONY: load-test
load-test: ## Run the k6 scenario SCENARIO=checkin|ingest against the running stack (RATE, VUS, WARMUP, DURATION, EVENTS_PER_S, BATCH, DRAIN, SCRAPE_INTERVAL_S)
	@test -s $(LOAD_DIR)/identities.json || { echo "missing $(LOAD_DIR)/identities.json: run make load-identities"; exit 2; }
	@$(LOAD_GUARD)
	docker run --rm --network paddock_cp -u $(UID):$(GID) -v $(CURDIR)/test/load/k6:/scripts:ro -v $(CURDIR)/$(LOAD_DIR):/data \
		-e IDENTITIES=/data/identities.json \
		$(foreach v,RATE VUS WARMUP DURATION EVENTS_PER_S BATCH DRAIN GATEWAY_URL PROMETHEUS_URL SCRAPE_INTERVAL_S,$(if $($(v)),-e $(v)='$($(v))',)) \
		$(K6_IMAGE) run --summary-export /data/$(SCENARIO)-summary.json /scripts/$(SCENARIO).js

.PHONY: ci
ci: lint test web ## Everything CI runs

.PHONY: logs
logs: ## Show logs of the stack (token= values redacted, RR-63)
	set -o pipefail; . $(LIB_SH) && $(COMPOSE) --profile paddock logs --no-color --tail 300 | redact_tokens

# --- Release (plan M6b decision 4, plan M7b decisions 4–7 and 20, docs/operations/agent-releases.md) ---------------
# The release workflow (.github/workflows/release.yml, tags v*.*.*) and the edge job of ci.yml call these targets, in
# this order: release-images PUSH=1, release-packages (stable only), release-sbom, release-bundle, release-sums,
# release-sign. RELEASE_VERSION is the version without the leading v: for RELEASE_CHANNEL=stable x.y.z or a pre-release
# x.y.z-alpha.N, -beta.N, -rc.N; for RELEASE_CHANNEL=edge edge-<yyyymmdd>-<sha7>. Images: a pre-release is tagged with
# its version only; a plain x.y.z also with <major>.<minor> and, only when it is the highest plain x.y.z among the v*
# tags, latest; an edge build with its version and edge, never latest (packaging/release_test.sh checks the rules).
# Everything lands in dist/release/<version>/. DRY_RUN=1 prints the docker, syft and cosign commands instead.
RELEASE_VERSION         ?=
RELEASE_CHANNEL         ?= stable
RELEASE_PLATFORMS       ?= linux/amd64,linux/arm64
RELEASE_REGISTRY        ?= ghcr.io/phischl
RELEASE_SERVER_REPO     ?= $(RELEASE_REGISTRY)/paddock-server
RELEASE_COMPILER_REPO   ?= $(RELEASE_REGISTRY)/paddock-compiler
RELEASE_PGBACKREST_REPO ?= $(RELEASE_REGISTRY)/paddock-pgbackrest
RELEASE_DIR             ?= dist/release/$(RELEASE_VERSION)
RELEASE_SOURCE          ?= https://github.com/phischl/paddock-mdm
DOCKER_CONFIG_DIR       ?= $(HOME)/.docker
# Extra flags of every docker buildx build, e.g. the workflow's layer cache (--cache-from/--cache-to type=gha).
RELEASE_BUILDX_FLAGS    ?=
RELEASE_IMAGES           = server=$(RELEASE_SERVER_REPO):$(RELEASE_VERSION) compiler=$(RELEASE_COMPILER_REPO):$(RELEASE_VERSION) \
	pgbackrest=$(RELEASE_PGBACKREST_REPO):$(RELEASE_VERSION)

# Tag rules (decisions 4–5). RELEASE_GIT_TAGS is overridable for the tests.
RELEASE_GIT_TAGS        ?= $(shell git tag --list 'v*' 2>/dev/null)
RELEASE_PLAIN            = $(shell printf '%s' '$(RELEASE_VERSION)' | grep -Ex '[0-9]+\.[0-9]+\.[0-9]+')
RELEASE_HIGHEST          = $(shell printf '%s\n' $(patsubst v%,%,$(RELEASE_GIT_TAGS)) '$(RELEASE_VERSION)' | \
	grep -Ex '[0-9]+\.[0-9]+\.[0-9]+' | sort -V | tail -1)
RELEASE_LATEST           = $(if $(filter stable,$(RELEASE_CHANNEL)),$(if $(RELEASE_PLAIN),$(filter $(RELEASE_VERSION),$(RELEASE_HIGHEST))))
RELEASE_TAGS             = $(RELEASE_VERSION) $(if $(filter edge,$(RELEASE_CHANNEL)),edge,$(if $(RELEASE_PLAIN),$(basename $(RELEASE_VERSION)) \
	$(if $(RELEASE_LATEST),latest)))
RELEASE_COMMIT          := $(shell git rev-parse HEAD 2>/dev/null)
RELEASE_CREATED         := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

SYFT_RUN   = docker run --rm -u $(UID):$(GID) --tmpfs /tmp:rw,mode=1777 -e HOME=/tmp -e SYFT_CHECK_FOR_APP_UPDATE=false \
	-e DOCKER_CONFIG=/docker -v $(DOCKER_CONFIG_DIR):/docker:ro -v $(CURDIR)/$(RELEASE_DIR):/work -w /work $(SYFT_IMAGE)
# cosign reads the registry login of the docker CLI and, in GitHub Actions, the OIDC token request variables.
COSIGN_RUN = docker run --rm -u $(UID):$(GID) --tmpfs /tmp:rw,mode=1777 -e HOME=/tmp -e DOCKER_CONFIG=/docker \
	-e ACTIONS_ID_TOKEN_REQUEST_URL -e ACTIONS_ID_TOKEN_REQUEST_TOKEN -e SIGSTORE_ID_TOKEN \
	-v $(DOCKER_CONFIG_DIR):/docker:ro -v $(CURDIR)/$(RELEASE_DIR):/work -w /work $(COSIGN_IMAGE)
# release_run (shell): runs its arguments, or prints them with DRY_RUN=1.
RELEASE_RUN = run() { if [ -n "$(DRY_RUN)" ]; then echo "dry-run: $$*"; else "$$@"; fi; }
# release_platforms (shell): "<key> <os/arch> <manifest digest> <repo>" per platform of images.txt; with DRY_RUN=1 and
# no pushed images, placeholders for RELEASE_PLATFORMS.
RELEASE_PLATFORM_LINES = platforms() { \
	if [ -s $(RELEASE_DIR)/images.txt ]; then \
		sed -n -E 's|^([a-z]+)/([a-z0-9]+/[a-z0-9]+)=([^@]+)@(sha256:[0-9a-f]+)$$|\1 \2 \4 \3|p' $(RELEASE_DIR)/images.txt; \
	else for entry in $(RELEASE_IMAGES); do key=$${entry%%=*}; repo=$${entry\#*=}; repo=$${repo%:*}; \
		for p in $(subst $(comma), ,$(RELEASE_PLATFORMS)); do echo "$$key $$p sha256:<$$p-digest> $$repo"; done; done; fi; }; \
	index() { sed -n "s|^$$1=\([^:]*\):[^@]*@\(sha256:[0-9a-f]*\)$$|\1@\2|p" $(RELEASE_DIR)/images.txt 2>/dev/null || true; }

.PHONY: release-check
release-check:
	@case "$(RELEASE_CHANNEL)" in \
		stable) echo "$(RELEASE_VERSION)" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$$' || \
			{ echo "usage: RELEASE_VERSION=x.y.z or x.y.z-alpha.N, -beta.N, -rc.N (without v)"; exit 2; } ;; \
		edge) echo "$(RELEASE_VERSION)" | grep -Eq '^edge-[0-9]{8}-[0-9a-f]{7}$$' || \
			{ echo "usage: RELEASE_VERSION=edge-YYYYMMDD-sha7 RELEASE_CHANNEL=edge"; exit 2; } ;; \
		*) echo "usage: RELEASE_CHANNEL=stable|edge"; exit 2 ;; \
	esac

# The supervisor compiles in the release public key (line 2 of the minisign file): a release must name the production
# key explicitly, line 2 must be a minisign Ed25519 public key (42 bytes, "Ed"), and it must not be the development
# key's line 2 (whatever the comment line) nor be built with build tags.
.PHONY: release-key-check
release-key-check: release-check
	@test "$(RELEASE_CHANNEL)" = stable || { echo "agent packages are released on the stable channel only"; exit 2; }
	@test "$(origin RELEASE_PUBLIC_KEY_FILE)" != file || { echo "set RELEASE_PUBLIC_KEY_FILE to the production release public key"; exit 2; }
	@test -s "$(RELEASE_PUBLIC_KEY_FILE)" || { echo "missing $(RELEASE_PUBLIC_KEY_FILE)"; exit 2; }
	@key=$$(sed -n 2p "$(RELEASE_PUBLIC_KEY_FILE)" | tr -d '\r'); \
	{ echo "$$key" | grep -Eq '^[A-Za-z0-9+/]{56}$$' && [ "$$(echo "$$key" | base64 -d 2>/dev/null | wc -c)" -eq 42 ] && \
		[ "$$(echo "$$key" | base64 -d 2>/dev/null | head -c 2)" = Ed ]; } || \
		{ echo "$(RELEASE_PUBLIC_KEY_FILE): line 2 is not a minisign Ed25519 public key"; exit 2; }; \
	for dev in $(RELEASE_KEY_DIR)/minisign.pub $(RELEASE_KEY_DIR)/revoke-minisign.pub; do \
		if [ -f "$$dev" ] && [ "$$(sed -n 2p "$$dev" | tr -d '\r')" = "$$key" ]; then echo "$(RELEASE_PUBLIC_KEY_FILE) is a development key"; exit 2; fi; \
	done
	@test -z "$(TAGS)$(REVOKE_TAGS)" || { echo "a release is built without TAGS and REVOKE_TAGS"; exit 2; }

.PHONY: release-artifacts
release-artifacts: release-key-check ## Build the release RELEASE_VERSION locally into dist/release/<version>/: images (only with PUSH=1), unsigned debs and agent binaries, SBOMs, bundle, SHA256SUMS
	rm -rf $(RELEASE_DIR) && mkdir -p $(RELEASE_DIR)
	$(MAKE) --no-print-directory release-images $(if $(PUSH),,DRY_RUN=1)
	$(MAKE) --no-print-directory release-packages
	$(MAKE) --no-print-directory release-sbom $(if $(PUSH),,DRY_RUN=1)
	$(MAKE) --no-print-directory release-bundle
	$(MAKE) --no-print-directory release-sums
	@ls -1 $(RELEASE_DIR)

# Multi-platform images (decision 2), pushed with every tag of RELEASE_TAGS and the labels of decision 6; images.txt
# records the index digest and the platform manifest digests (§6.3), attestation manifests excluded.
.PHONY: release-images
release-images: release-check ## Build and push the three images for RELEASE_PLATFORMS with the tags and labels of the channel (PUSH=1; DRY_RUN=1 prints)
	@test -n "$(PUSH)$(DRY_RUN)" || { echo "release-images pushes multi-platform images: set PUSH=1 (DRY_RUN=1 prints the commands)"; exit 2; }
	@set -e; $(RELEASE_RUN); mkdir -p $(RELEASE_DIR); [ -n "$(DRY_RUN)" ] || : >$(RELEASE_DIR)/images.txt; \
	meta=$$(mktemp); trap 'rm -f "$$meta"' EXIT; \
	for entry in $(RELEASE_IMAGES); do \
		key=$${entry%%=*}; repo=$${entry#*=}; repo=$${repo%:*}; target=; dockerfile=$(COMPOSE_DIR)/Dockerfile; \
		case $$key in \
			server) desc="Paddock server with the embedded portal: every role but the compiler, prod-check and the admin commands" ;; \
			compiler) desc="Paddock compiler role: the server binary on Debian with visudo"; target="--target compiler" ;; \
			pgbackrest) desc="pgBackRest for the backups of the Paddock databases"; dockerfile=$(COMPOSE_DIR)/pgbackrest/Dockerfile ;; \
		esac; \
		tags=; for t in $(RELEASE_TAGS); do tags="$$tags -t $$repo:$$t"; done; \
		run docker buildx build --platform $(RELEASE_PLATFORMS) --push $$target -f $$dockerfile $(RELEASE_BUILDX_FLAGS) \
			--build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) --build-arg NODE_IMAGE=$(NODE_IMAGE) \
			--build-arg RUNTIME_IMAGE=$(RUNTIME_IMAGE) --build-arg COMPILER_RUNTIME_IMAGE=$(COMPILER_RUNTIME_IMAGE) \
			--label org.opencontainers.image.source=$(RELEASE_SOURCE) \
			--label org.opencontainers.image.url=$(RELEASE_SOURCE) \
			--label org.opencontainers.image.documentation=$(RELEASE_SOURCE)/blob/main/docs/operations/install.md \
			--label org.opencontainers.image.title=$$(basename $$repo) \
			--label "org.opencontainers.image.description=$$desc" \
			--label org.opencontainers.image.version=$(RELEASE_VERSION) \
			--label org.opencontainers.image.revision=$(RELEASE_COMMIT) \
			--label org.opencontainers.image.created=$(RELEASE_CREATED) \
			--label org.opencontainers.image.licenses=MIT \
			--label org.opencontainers.image.vendor=Paddock \
			--label io.paddock.channel=$(RELEASE_CHANNEL) \
			--metadata-file "$$meta" $$tags .; \
		[ -z "$(DRY_RUN)" ] || continue; \
		digest=$$(grep -oE '"containerimage.digest": *"sha256:[0-9a-f]{64}"' "$$meta" | grep -oE 'sha256:[0-9a-f]{64}'); \
		test -n "$$digest" || { echo "no index digest of $$repo in the buildx metadata"; exit 1; }; \
		echo "$$key=$$repo:$(RELEASE_VERSION)@$$digest" >>$(RELEASE_DIR)/images.txt; \
		docker buildx imagetools inspect "$$repo@$$digest" \
			--format '{{range .Manifest.Manifests}}{{.Platform.OS}}/{{.Platform.Architecture}} {{.Digest}}{{"\n"}}{{end}}' | \
			while read -r platform pdigest; do \
				case "$$platform" in ""|unknown/*) continue ;; esac; \
				echo "$$key/$$platform=$$repo@$$pdigest" >>$(RELEASE_DIR)/images.txt; \
			done; \
	done; \
	[ -n "$(DRY_RUN)" ] || cat $(RELEASE_DIR)/images.txt

# Agent binaries and Debian packages, unsigned; the sign job of the release workflow signs paddockd and the
# paddock-agent and paddock-supervisor packages (packaging/sign-release.sh, ADR 0006 amendment 2026-10-11), and
# paddock-revoke stays unsigned (revocation release key offline). GitHub renames release assets with characters such
# as ~, so a pre-release's packages (Debian version x.y.z~alpha.N inside) are named
# <name>_<release version>_<arch>-unsigned.deb.
RELEASE_DEB_DIR ?= bin/deb

.PHONY: release-packages
release-packages: release-key-check ## Build the unsigned agent binaries and Debian packages of RELEASE_VERSION into dist/release/<version>/
	mkdir -p $(RELEASE_DIR)
	$(MAKE) --no-print-directory deb VERSION=$(RELEASE_VERSION) RELEASE_PUBLIC_KEY_FILE=$(RELEASE_PUBLIC_KEY_FILE) TAGS= REVOKE_TAGS=
	$(MAKE) --no-print-directory release-debs
	@for arch in amd64 arm64; do cp bin/agent/$$arch/paddockd $(RELEASE_DIR)/paddockd_$(RELEASE_VERSION)_linux_$$arch-unsigned || exit 1; done

.PHONY: release-debs
release-debs: release-check
	@for f in $(RELEASE_DEB_DIR)/*.deb; do b=$$(basename "$$f" .deb); \
		cp "$$f" "$(RELEASE_DIR)/$${b%%_*}_$(RELEASE_VERSION)_$${b##*_}-unsigned.deb" || exit 1; done

.PHONY: release-names-check
release-names-check:
	@bad=$$(find $(RELEASE_DIR) -maxdepth 1 -type f -printf '%f\n' | grep -v '^[A-Za-z0-9._+-]*$$' || true); \
		test -z "$$bad" || { echo "release file names GitHub would rename: $$bad"; exit 2; }

# The publish job replaces each -unsigned agent file with its signed file and .minisig from RELEASE_SIGNED_DIR (the
# sign job's output) before release-sums, so SHA256SUMS names the published files. No paddockd, paddock-agent or
# paddock-supervisor file may stay unsigned; paddock-revoke is never in RELEASE_SIGNED_DIR.
RELEASE_SIGNED_DIR ?=

.PHONY: release-merge-signed
release-merge-signed: release-check
	@test -d "$(RELEASE_SIGNED_DIR)" || { echo "usage: make release-merge-signed RELEASE_SIGNED_DIR=<dir of the sign job>"; exit 2; }
	@set -e; for f in "$(RELEASE_SIGNED_DIR)"/*; do b=$$(basename "$$f"); \
		case "$$b" in \
			paddock-revoke_*) echo "$$b: paddock-revoke is never signed in CI"; exit 2 ;; \
			*.minisig) test -f "$(RELEASE_SIGNED_DIR)/$${b%.minisig}" || { echo "$$b without its file"; exit 2; } ;; \
			*.deb) test -f "$$f.minisig" || { echo "$$b without $$b.minisig"; exit 2; }; rm -f "$(RELEASE_DIR)/$${b%.deb}-unsigned.deb" ;; \
			*) test -f "$$f.minisig" || { echo "$$b without $$b.minisig"; exit 2; }; rm -f "$(RELEASE_DIR)/$$b-unsigned" ;; \
		esac; cp "$$f" "$(RELEASE_DIR)/$$b"; done
	@left=$$(find $(RELEASE_DIR) -maxdepth 1 -type f \( -name 'paddockd_*-unsigned' -o -name 'paddock-agent_*-unsigned.deb' \
		-o -name 'paddock-supervisor_*-unsigned.deb' \) -printf '%f\n'); \
		test -z "$$left" || { echo "agent files without a signed counterpart: $$left"; exit 2; }

# One SPDX SBOM per image and platform, read by syft from the registry (decision 7).
.PHONY: release-sbom
release-sbom: release-check ## SPDX SBOM per pushed image and platform with syft into dist/release/<version>/ (DRY_RUN=1 prints)
	@if [ -z "$(DRY_RUN)" ] && ! [ -s $(RELEASE_DIR)/images.txt ]; then echo "no pushed images: run make release-images PUSH=1"; exit 2; fi
	@set -e; $(RELEASE_RUN); $(RELEASE_PLATFORM_LINES); mkdir -p $(RELEASE_DIR); \
	platforms | while read -r key platform pdigest repo; do \
		digest=$$(index $$key); digest=$${digest:-$$repo@sha256:<index digest>}; \
		sbom=$$(basename $$repo)_$(RELEASE_VERSION)_$${platform%%/*}_$${platform#*/}.spdx.json; \
		run $(SYFT_RUN) registry:$$digest --platform $$platform --source-name $$repo --source-version $(RELEASE_VERSION) \
			-o spdx-json=/work/$$sbom; \
		[ -n "$(DRY_RUN)" ] || echo "SBOM $(RELEASE_DIR)/$$sbom"; \
	done

# The operator bundle of the pushed images (decisions 11–13); without pushed images (a local release-artifacts) a
# bundle of the local images. Only the tarball stays in the release directory.
.PHONY: release-bundle
release-bundle: release-check ## Operator bundle paddock-deploy-<version>.tar.gz of the pushed images into dist/release/<version>/
	@mkdir -p $(RELEASE_DIR)
	@if grep -q '^server=' $(RELEASE_DIR)/images.txt 2>/dev/null; then \
		deploy/bundle/build.sh --version $(RELEASE_VERSION) --channel $(RELEASE_CHANNEL) --images $(RELEASE_DIR)/images.txt --out $(RELEASE_DIR); \
	else echo "no pushed images: bundle of the local images"; \
		LOCAL_SERVER_IMAGE=$(IMAGE) LOCAL_COMPILER_IMAGE=$(COMPILER_IMAGE) LOCAL_PGBACKREST_IMAGE=$(PGBACKREST_IMAGE) \
		deploy/bundle/build.sh --version $(RELEASE_VERSION) --channel local --images local --out $(RELEASE_DIR); fi
	rm -rf $(RELEASE_DIR)/paddock-deploy-$(RELEASE_VERSION)

# SHA256SUMS over the final asset names; images.txt (an input of the workflow) and the signatures are not assets of it.
.PHONY: release-sums
release-sums: release-check release-names-check ## SHA256SUMS over dist/release/<version>/
	cd $(RELEASE_DIR) && find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name images.txt ! -name '*.sigstore.json' \
		-printf '%f\n' | LC_ALL=C sort | xargs sha256sum >SHA256SUMS
	@cat $(RELEASE_DIR)/SHA256SUMS

# Keyless with the workflow's GitHub OIDC identity (decision 7): every index recursively (index and platform manifests),
# one SBOM attestation per platform manifest, SHA256SUMS and the bundle tarball as blobs.
.PHONY: release-sign
release-sign: release-check ## Sign the images recursively, attest their SBOMs per platform, sign SHA256SUMS and the bundle keyless with cosign (DRY_RUN=1 prints)
	@test -s $(RELEASE_DIR)/SHA256SUMS || { echo "missing $(RELEASE_DIR)/SHA256SUMS: run make release-sums"; exit 2; }
	@if [ -z "$(DRY_RUN)" ] && ! [ -s $(RELEASE_DIR)/images.txt ]; then echo "no pushed images: run make release-images PUSH=1"; exit 2; fi
	@set -e; $(RELEASE_RUN); $(RELEASE_PLATFORM_LINES); \
	for entry in $(RELEASE_IMAGES); do key=$${entry%%=*}; repo=$${entry#*=}; repo=$${repo%:*}; \
		digest=$$(index $$key); \
		if [ -z "$$digest" ]; then test -n "$(DRY_RUN)" || { echo "no index digest of $$key in images.txt"; exit 2; }; \
			digest="$$repo@sha256:<index digest>"; fi; \
		run $(COSIGN_RUN) sign --yes --recursive "$$digest"; \
	done; \
	platforms | while read -r key platform pdigest repo; do \
		sbom=$$(basename $$repo)_$(RELEASE_VERSION)_$${platform%%/*}_$${platform#*/}.spdx.json; \
		test -n "$(DRY_RUN)" || test -s $(RELEASE_DIR)/$$sbom || { echo "missing $(RELEASE_DIR)/$$sbom: run make release-sbom"; exit 2; }; \
		run $(COSIGN_RUN) attest --yes --type spdxjson --predicate /work/$$sbom "$$repo@$$pdigest"; \
	done; \
	run $(COSIGN_RUN) sign-blob --yes --bundle /work/SHA256SUMS.sigstore.json /work/SHA256SUMS; \
	bundle=paddock-deploy-$(RELEASE_VERSION).tar.gz; \
	test -n "$(DRY_RUN)" || test -s $(RELEASE_DIR)/$$bundle || { echo "missing $(RELEASE_DIR)/$$bundle: run make release-bundle"; exit 2; }; \
	run $(COSIGN_RUN) sign-blob --yes --bundle /work/$$bundle.sigstore.json /work/$$bundle

# The publish job re-signs SHA256SUMS after release-merge-signed and release-sums, so the signature covers the final
# asset names (keyless, the same identity as release-sign).
.PHONY: release-sign-sums
release-sign-sums: release-check ## Sign SHA256SUMS keyless with cosign (DRY_RUN=1 prints)
	@test -s $(RELEASE_DIR)/SHA256SUMS || { echo "missing $(RELEASE_DIR)/SHA256SUMS: run make release-sums"; exit 2; }
	@set -e; $(RELEASE_RUN); [ -n "$(DRY_RUN)" ] || rm -f $(RELEASE_DIR)/SHA256SUMS.sigstore.json; \
	run $(COSIGN_RUN) sign-blob --yes --bundle /work/SHA256SUMS.sigstore.json /work/SHA256SUMS

# --- Security scans (CI jobs `secrets` and `trivy`) --------------------------------------------------------------
TRIVY_CACHE     ?= $(HOME)/.cache/trivy
TRIVY_ARGS      := --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress
COMPILER_IMAGE  ?= paddock-compiler:dev
PGBACKREST_IMAGE ?= paddock-pgbackrest:dev

.PHONY: scan scan-secrets scan-secrets-diff scan-secrets-strip-default scan-secrets-canary scan-fs scan-images \
	image-compiler image-pgbackrest
scan: scan-secrets scan-fs scan-images ## Run gitleaks (branch history) and trivy (filesystem and images)

# The current branch only, never --all: a finding on an unrelated stale branch must not fail this scan. CI narrows it
# to a pull request's own commits with GITLEAKS_LOG_OPTS=<merge-base>..HEAD. GITLEAKS_REPO lets the regression test
# (test/scan-secrets_test.sh) run both scan recipes against a scratch repository.
GITLEAKS_LOG_OPTS ?= HEAD
GITLEAKS_REPO ?= $(CURDIR)

# Both scans read .gitleaks.toml and any .gitleaksignore from GITLEAKS_CONFIG_REF; empty (local runs) means the working
# tree. CI sets it to a pull request's merge base, so a pull request cannot loosen the scan that checks it (PDK-065):
# a pull request that changes either file is scanned with the base's version, and an allowlist for a false positive
# takes effect only once merged, so it lands in its own pull request first. gitleaks always loads the .gitleaksignore
# at the root of its source and of its working directory, whatever --gitleaks-ignore-path says, so the history scan
# reads the git dir instead of the checkout, the file scan keeps a changed .gitleaksignore under another name, and
# both always pass the chosen file (empty when there is none). An inline `gitleaks:allow` comment would let the scanned
# content allow itself, so both scans pass --ignore-gitleaks-allow. gitleaks resolves an `[extend] path` from its
# working directory, which the file scan fills with the pull request's files, so a configuration that extends another
# file fails; `useDefault = true` alone is allowed.
# The configuration both scans run is generated (ADR 0026): the default configuration of GITLEAKS_IMAGE without the
# paths of its global allowlist, extended by that .gitleaks.toml. Those paths skip whole files and directories in every
# scan mode (src/bootstrap.js, d.png/creds.bin, javascript.json), and a repository configuration that extends the
# default with useDefault cannot drop them. gitleaks cannot print its default, but embeds it uncompressed (go:embed):
# the bytes from the single occurrence of GITLEAKS_DEFAULT_CONFIG_HEADER in /usr/bin/gitleaks are checked against the
# size and sha256 pinned next to GITLEAKS_IMAGE, so an image bump without new pins, or a changed binary layout, fails
# instead of scanning with an unknown default. A default whose global paths the strip does not recognise fails too.
# $(1) is the directory the container mounts the configuration at: the child's `[extend] path` names the stripped
# default by its absolute path there, a mount that holds none of the scanned files.
# The child is not derived from .gitleaks.toml by text: GITLEAKS_CHILD_CONFIG parses it with Python's tomllib, refuses
# everything outside a closed whitelist (top level title, extend = {useDefault = true} and allowlists with their known
# keys and types; names compare exactly, so [Extend] or Extend.disabledRules fail) and writes the child itself (ADR
# 0026, amendment 2026-10-12), because pattern matching on TOML text was bypassed by strings holding `[extend]` or
# `'''` and by gitleaks' case-insensitive keys. GITLEAKS_PATTERNS_CHECK then compiles every allowlist pattern with
# Go's regexp, the engine gitleaks uses, in GO_BUILD_IMAGE without network, and refuses one that does not compile or
# matches the empty string (and so everything). Before either scan reads PR content, a canary run of the generated
# configuration must report a fake token, generated per run and never printed, under node_modules/ and vendor/, paths
# the default's global allowlist skipped, and under an ordinary path chosen per run: a configuration that lost its
# rules or path coverage fails.
# What this cannot cover: a pull request runs its own ci.yml and this Makefile, so it can also change how it is
# scanned. The scan's integrity therefore rests on code review of .github/, the Makefile and
# deploy/compose/versions.env (included above as make syntax; it pins GITLEAKS_IMAGE and its default configuration);
# CODEOWNERS names a reviewer for them, and the branch ruleset on main requires that review
# (docs/operations/secret-scan.md).
GITLEAKS_CONFIG_REF ?=
# Test seam of test/scan-secrets_test.sh, never set by the CI scan steps: a directory where the steps of the generated
# configuration keep what they produced, keyed by their inputs, so the test's many cases on the same base configuration
# run the Go pattern check, the copy of /usr/bin/gitleaks and the canary once each (PDK-072). Only a check that ran is
# kept (the verdicts of a Go check that exited 0, a canary that was reported); everything else still runs on every call.
GITLEAKS_TEST_CACHE ?=
GITLEAKS_DEFAULT_CONFIG_HEADER = \# This file has been auto-generated. Do not edit manually.
GITLEAKS_CHILD_CONFIG = python3 $(CURDIR)/deploy/compose/scripts/gitleaks-child-config.py
GITLEAKS_PATTERNS_CHECK = $(CURDIR)/deploy/compose/scripts/gitleaks-patterns.go
# gitleaks_strip_default,<in>,<out>,<label>: <in> without the multi-line `paths = [` array before the first
# [[rules]]; the result must parse, hold rules and keep no paths in its global allowlist in any key form.
gitleaks_strip_default = awk '/^[[:space:]]*\[\[rules\]\]/ { r = 1 } \
		!r && /^[[:space:]]*paths[[:space:]]*=[[:space:]]*\[[[:space:]]*$$/ { s = 1; next } \
		s { if ($$0 ~ /^[[:space:]]*\][[:space:]]*$$/) s = 0; next } { print }' $(1) >$(2) || exit 1; \
	$(GITLEAKS_CHILD_CONFIG) verify-default $(2) || { echo "$@: $(3) after the strip is not a default with rules and" \
		"without global paths; its layout changed and must be looked at (ADR 0026)" >&2; exit 1; }
# gitleaks_canary,<config dir>,<its path in the container>: the configuration in <config dir> must report a fake
# GitHub token under node_modules/, vendor/github.com/ and an ordinary path chosen per run, so that an allowlist built
# around the fixed canary paths (^[^nv./]) still fails it.
GITLEAKS_CANARY = node_modules/canary.txt vendor/github.com/canary/canary.txt
gitleaks_canary = rnd=$$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8); \
	canaries="$(GITLEAKS_CANARY) src/$$rnd/canary.txt"; \
	for f in $$canaries; do \
		mkdir -p -- "$$tmp/canary/$${f%/*}" || exit 1; \
		printf 'GITHUB_TOKEN=ghp_%s\n' "$$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)" \
			>"$$tmp/canary/$$f" || exit 1; done; \
	mkdir -p "$$tmp/canary-out" || exit 1; \
	docker run --rm --user "$$(id -u):$$(id -g)" -v $(1):$(2):ro -v "$$tmp/canary:/canary:ro" \
		-v "$$tmp/canary-out:/out" -w /canary $(GITLEAKS_IMAGE) dir . --config $(2)/gitleaks.toml --no-banner \
		--redact --exit-code 0 --report-format json --report-path /out/report.json >"$$tmp/canary-out/log" 2>&1; \
	if ! $(GITLEAKS_CHILD_CONFIG) canary "$$tmp/canary-out/report.json" $$canaries; then \
		echo "$@: the generated configuration lost its rules or path coverage (ADR 0026); gitleaks said:" >&2; \
		sed -E 's/\x1b\[[0-9;]*m//g' "$$tmp/canary-out/log" >&2; exit 1; fi; \
	rm -rf -- "$$tmp/canary" "$$tmp/canary-out"
gitleaks_config = mkdir "$$tmp/cfg" || exit 1; ref='$(GITLEAKS_CONFIG_REF)'; \
	if [ -n "$$ref" ]; then \
		git -C "$$repo" show "$$ref:.gitleaks.toml" >"$$tmp/repo.toml" || \
			{ echo "$@: no .gitleaks.toml at $$ref" >&2; exit 1; }; \
		if git -C "$$repo" cat-file -e "$$ref:.gitleaksignore" 2>/dev/null; then \
			git -C "$$repo" show "$$ref:.gitleaksignore" >"$$tmp/cfg/gitleaksignore" || exit 1; \
		else : >"$$tmp/cfg/gitleaksignore"; fi; \
	else \
		cp -- "$$repo/.gitleaks.toml" "$$tmp/repo.toml" || exit 1; \
		if [ -f "$$repo/.gitleaksignore" ]; then cp -- "$$repo/.gitleaksignore" "$$tmp/cfg/gitleaksignore" || exit 1; \
		else : >"$$tmp/cfg/gitleaksignore"; fi; \
	fi; \
	$(GITLEAKS_CHILD_CONFIG) child "$$tmp/repo.toml" "$(1)/default.toml" "$$tmp/child.toml" "$$tmp/patterns.json" || \
		{ echo "$@: .gitleaks.toml from $${ref:-the working tree} is outside what the generated configuration" \
			"accepts (ADR 0026, amendment 2026-10-12)" >&2; exit 1; }; \
	tc='$(GITLEAKS_TEST_CACHE)'; \
	key=$$({ printf '%s\n' '$(GO_BUILD_IMAGE)'; cat -- "$(GITLEAKS_PATTERNS_CHECK)" "$$tmp/patterns.json"; } | \
		sha256sum) || exit 1; key=$${key%% *}; \
	if [ -n "$$tc" ] && [ -f "$$tc/patterns-$$key" ]; then cp -- "$$tc/patterns-$$key" "$$tmp/verdicts.jsonl"; prc=$$?; \
	else docker run --rm -i --network none -e GOFLAGS= -e GOTOOLCHAIN=local -v "$(GITLEAKS_PATTERNS_CHECK):/p.go:ro" \
		$(GO_BUILD_IMAGE) go run /p.go <"$$tmp/patterns.json" >"$$tmp/verdicts.jsonl" 2>"$$tmp/patterns.err"; prc=$$?; \
		if [ -n "$$tc" ] && [ "$$prc" -eq 0 ]; then cp -- "$$tmp/verdicts.jsonl" "$$tc/patterns-$$key" || exit 1; fi; \
	fi; \
	if [ "$$prc" -ne 0 ]; then cat -- "$$tmp/patterns.err" >&2; \
		echo "$@: the Go pattern check could not run (exit $$prc, $(GO_BUILD_IMAGE)); the scan fails closed" >&2; \
		exit 1; fi; \
	if ! $(GITLEAKS_CHILD_CONFIG) patterns "$$tmp/patterns.json" "$$tmp/verdicts.jsonl"; then \
		echo "$@: .gitleaks.toml from $${ref:-the working tree} is outside what the generated configuration" \
			"accepts: Go's regexp refuses an allowlist pattern (ADR 0026, amendment 2026-10-12)" >&2; exit 1; fi; \
	pins="GITLEAKS_DEFAULT_CONFIG_BYTES and GITLEAKS_DEFAULT_CONFIG_SHA256 (deploy/compose/versions.env)"; \
	key=$$(printf '%s\n' '$(GITLEAKS_IMAGE)' | sha256sum) || exit 1; key=$${key%% *}; \
	if [ -n "$$tc" ] && [ -f "$$tc/gitleaks-$$key" ]; then cp -- "$$tc/gitleaks-$$key" "$$tmp/gitleaks.bin" || exit 1; \
	else docker run --rm --entrypoint /bin/cat $(GITLEAKS_IMAGE) /usr/bin/gitleaks >"$$tmp/gitleaks.bin" || \
		{ echo "$@: cannot copy /usr/bin/gitleaks out of $(GITLEAKS_IMAGE)" >&2; exit 1; }; \
		if [ -n "$$tc" ]; then cp -- "$$tmp/gitleaks.bin" "$$tc/gitleaks-$$key" || exit 1; fi; \
	fi; \
	off=$$(LC_ALL=C grep -obaF -- '$(GITLEAKS_DEFAULT_CONFIG_HEADER)' "$$tmp/gitleaks.bin" | cut -d: -f1); \
	case $$off in ''|*[!0-9]*) echo "$@: the header of the default configuration occurs" \
		"$$(printf '%s' "$$off" | grep -c .) times in /usr/bin/gitleaks of $(GITLEAKS_IMAGE), not once;" \
		"check $$pins against the image (docs/operations/secret-scan.md)" >&2; exit 1 ;; esac; \
	bytes='$(GITLEAKS_DEFAULT_CONFIG_BYTES)'; case $$bytes in ''|*[!0-9]*) bytes=0 ;; esac; \
	tail -c +$$((off + 1)) "$$tmp/gitleaks.bin" | head -c "$$bytes" >"$$tmp/default.toml" || exit 1; \
	rm -f -- "$$tmp/gitleaks.bin"; sum=$$(sha256sum <"$$tmp/default.toml") || exit 1; \
	if [ "$$bytes" -eq 0 ] || [ "$$(wc -c <"$$tmp/default.toml")" -ne "$$bytes" ] || \
		[ "$${sum%% *}" != '$(GITLEAKS_DEFAULT_CONFIG_SHA256)' ]; then \
		echo "$@: the default configuration in $(GITLEAKS_IMAGE) does not match $$pins;" \
			"an image bump updates the image and both pins together (docs/operations/secret-scan.md)" >&2; exit 1; fi; \
	$(call gitleaks_strip_default,"$$tmp/default.toml","$$tmp/cfg/default.toml",the default of $(GITLEAKS_IMAGE)); \
	mv -- "$$tmp/child.toml" "$$tmp/cfg/gitleaks.toml" || exit 1; \
	key=$$({ printf '%s\n' '$(GITLEAKS_IMAGE)' '$(GITLEAKS_CANARY)' '$(1)'; \
		cat -- $(lastword $(GITLEAKS_CHILD_CONFIG)) "$$tmp/repo.toml" "$$tmp/cfg/default.toml"; } | sha256sum) || exit 1; \
	key=$${key%% *}; \
	if [ -z "$$tc" ] || [ ! -f "$$tc/canary-$$key" ]; then \
		$(call gitleaks_canary,"$$tmp/cfg",$(1)); \
		if [ -n "$$tc" ]; then : >"$$tc/canary-$$key" || exit 1; fi; \
	fi; \
	echo "$@: configuration from $${ref:-the working tree} on the default of $(GITLEAKS_IMAGE) without its global paths"

# A git worktree's .git file points into the main checkout's git dir, so that dir is mounted at its own path.
# `--remerge-diff` shows what a merge commit changes beyond its automatic merge, so a secret added only in a merge
# resolution is seen (PDK-057). It writes temporary objects, which go to a scratch object directory while the
# repository stays read-only. gitleaks exits 0 when its git call fails, so an error line fails, and so does a scan of
# 0 commits, unless the range resolves and holds merge commits only: a clean merge has an empty remerge diff.
# `--remerge-diff` shows nothing for an octopus merge (more than two parents), so a range with one fails.
scan-secrets: ## gitleaks over the current branch history (false positives: allowlists in .gitleaks.toml)
	@repo='$(GITLEAKS_REPO)'; \
	common=$$(git -C "$$repo" rev-parse --path-format=absolute --git-common-dir) || exit 1; \
	octopus=$$(git -C "$$repo" rev-list --min-parents=3 --max-count=1 $(GITLEAKS_LOG_OPTS)) || \
		{ echo "scan-secrets: git cannot resolve $(GITLEAKS_LOG_OPTS)" >&2; exit 1; }; \
	if [ -n "$$octopus" ]; then echo "scan-secrets: $$octopus is an octopus merge: its changes cannot be scanned" \
		"(--remerge-diff shows none), and octopus merges are not allowed in Paddock's history" >&2; exit 1; fi; \
	gitdir=$$(git -C "$$repo" rev-parse --absolute-git-dir) || exit 1; \
	tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	$(call gitleaks_config,$$tmp/cfg); \
	out=$$(docker run --rm --user "$$(id -u):$$(id -g)" -v "$$repo:$$repo:ro" -v "$$common:$$common:ro" \
		-v "$$tmp:$$tmp" -e GIT_OBJECT_DIRECTORY="$$tmp" -e GIT_ALTERNATE_OBJECT_DIRECTORIES="$$common/objects" \
		-w "$$tmp/cfg" $(GITLEAKS_IMAGE) \
		git "$$gitdir" --config "$$tmp/cfg/gitleaks.toml" --gitleaks-ignore-path "$$tmp/cfg/gitleaksignore" \
		--ignore-gitleaks-allow --no-banner --redact --log-opts='--remerge-diff $(GITLEAKS_LOG_OPTS)' 2>&1); rc=$$?; \
	printf '%s\n' "$$out"; \
	plain=$$(printf '%s\n' "$$out" | sed -E 's/\x1b\[[0-9;]*m//g'); \
	if printf '%s\n' "$$plain" | grep -qE '(^|[[:space:]])(ERR|FTL)[[:space:]]|^(fatal|error):'; then \
		echo "scan-secrets: gitleaks or git reported an error ($(GITLEAKS_LOG_OPTS))" >&2; exit 1; fi; \
	commits=$$(printf '%s\n' "$$plain" | sed -nE 's/.*[^0-9]([0-9]+) commits scanned.*/\1/p'); \
	if [ "$${commits:-0}" -eq 0 ]; then \
		nonmerge=$$(git -C "$$repo" rev-list --no-merges --max-count=1 $(GITLEAKS_LOG_OPTS)) && \
		merges=$$(git -C "$$repo" rev-list --merges --max-count=1 $(GITLEAKS_LOG_OPTS)) || \
			{ echo "scan-secrets: git cannot resolve $(GITLEAKS_LOG_OPTS)" >&2; exit 1; }; \
		if [ -n "$$nonmerge" ] || [ -z "$$merges" ]; then \
			echo "scan-secrets: gitleaks scanned 0 commits ($(GITLEAKS_LOG_OPTS))" >&2; exit 1; fi; \
		echo "scan-secrets: $(GITLEAKS_LOG_OPTS) holds only merge commits whose remerge diff adds nothing;" \
			"0 commits scanned is expected"; \
	fi; \
	exit $$rc

# Second layer for pull requests, two views of <merge base>..HEAD with the same configuration and ignore handling:
# layer 0 holds the current content of every file the pull request changes, merge commits included (PDK-057), and the
# layers from 1 on every blob the range adds (PDK-068). gitleaks' git mode skips binary patches, so a binary file with
# a secret that a later commit of the pull request removes again was seen by neither the history scan nor layer 0.
# The blobs come from the raw diff of every commit in the range against each parent, so each new blob is written under
# every path it was added at and the base's path allowlists and fingerprints apply as in layer 0; blobs that share a
# path go into separate layers, each scanned from its own root. A path's search for a free layer starts after the layer
# its last blob went to: layers only gain files and directories, so one that could not take the path never can later
# (PDK-072). Each placed blob reserves its path with an empty file, so the collision checks see it, and one
# `git cat-file --batch` fills them all; its output must match the requested blobs one by one or the scan fails.
# The layers run in parallel, as many as the container has CPUs, because a long range has hundreds of them and one
# gitleaks run after the other dominated the scan (PDK-087). Each layer keeps its own output and exit status; the
# output is printed in layer order afterwards, and a layer whose status is missing or not 0 fails the scan.
# Only pull request ranges pay for this: the history scan of main (scan-secrets) is unchanged. A file over
# GITLEAKS_MAX_MB (decimal megabytes; GitHub refuses files over 100 MiB) fails the scan instead of being skipped by
# --max-target-megabytes.
# gitleaks identifies archives by name only, so a changed file or blob whose name ends, case-insensitively, in one of
# GITLEAKS_ZIP_EXT is written with the suffix .zip (creds.docx is scanned as creds.docx.zip) and one ending in .tgz
# with the suffix .tar.gz, and archives are opened one level deep (--max-archive-depth 1; nested archives and other
# archive names are not opened, and the CI job's timeout bounds the decompression). The collision checks, the choice of
# a free blob layer and .gitleaksignore fingerprints use that name; every other file keeps its path, since the
# generated configuration no longer skips names (ADR 0026). gitleaks still skips files whose magic bytes map to
# application/* (real PDFs, fonts, executables, compressed data) in every mode. Re-check on image bump: the list
# against the archive formats of the GITLEAKS_IMAGE in use.
GITLEAKS_DIFF_BASE ?= origin/main
GITLEAKS_MAX_MB = 100
GITLEAKS_ZIP_EXT = jar war docx xlsx pptx odt ods odp

# Test seam of test/scan-secrets_test.sh: the strip of the default configuration and its check, run on
# GITLEAKS_STRIP_FILE instead of the pinned default, with the result on stdout.
scan-secrets-strip-default:
	@tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	$(call gitleaks_strip_default,'$(GITLEAKS_STRIP_FILE)',"$$tmp/out.toml",$(GITLEAKS_STRIP_FILE)); \
	cat -- "$$tmp/out.toml"

# Test seam of test/scan-secrets_test.sh: the canary on GITLEAKS_CANARY_DIR, a directory with a gitleaks.toml that is
# mounted at its own path.
scan-secrets-canary:
	@tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	$(call gitleaks_canary,'$(GITLEAKS_CANARY_DIR)','$(GITLEAKS_CANARY_DIR)'); echo "$@: the canary was reported"

scan-secrets-diff: ## gitleaks over the files changed since GITLEAKS_DIFF_BASE and every blob added since then
	@repo='$(GITLEAKS_REPO)'; \
	base=$$(git -C "$$repo" merge-base '$(GITLEAKS_DIFF_BASE)' HEAD) || exit 1; \
	tmp=$$(mktemp -d) || exit 1; trap 'rm -rf "$$tmp"' EXIT; \
	$(call gitleaks_config,/cfg); \
	git -C "$$repo" diff -z --name-only --diff-filter=d "$$base"..HEAD >"$$tmp/files" || exit 1; \
	scan_name() { local e; sn=$$1; \
		for e in $(GITLEAKS_ZIP_EXT); do case $${sn,,} in *.$$e) sn=$$sn.zip; return ;; esac; done; \
		case $${sn,,} in *.tgz) sn=$$sn.tar.gz ;; esac; }; \
	n=0; mkdir -p "$$tmp/scan/0" || exit 1; \
	while IFS= read -r -d '' f; do \
		if [ -f "$$repo/$$f" ] || [ -L "$$repo/$$f" ]; then \
			scan_name "$$f"; dir=.; case $$sn in */*) dir=$${sn%/*} ;; esac; \
			if ! mkdir -p -- "$$tmp/scan/0/$$dir" 2>/dev/null || [ -e "$$tmp/scan/0/$$sn" ] || \
				[ -L "$$tmp/scan/0/$$sn" ]; then echo "$@: cannot write a changed file as $$sn" >&2; exit 1; fi; \
			cp -P -- "$$repo/$$f" "$$tmp/scan/0/$$sn" || exit 1; n=$$((n + 1)); fi; \
	done <"$$tmp/files"; \
	git -C "$$repo" rev-list --objects --no-object-names "$$base"..HEAD >"$$tmp/objects" || exit 1; \
	git -C "$$repo" cat-file --batch-check='%(objectname) %(objecttype)' <"$$tmp/objects" >"$$tmp/types" || exit 1; \
	if grep -qvE '^[0-9a-f]+ (blob|tree|commit|tag)$$' "$$tmp/types"; then \
		echo "$@: git cannot read every object of $$base..HEAD" >&2; exit 1; fi; \
	declare -A new=() seen=() free=(); \
	while read -r id type; do if [ "$$type" = blob ]; then new[$$id]=1; fi; done <"$$tmp/types"; \
	git -C "$$repo" log -z -m --root --no-renames --no-abbrev --raw --format= --diff-filter=d "$$base"..HEAD \
		>"$$tmp/raw" || exit 1; \
	b=0; layers=0; ids=(); dests=(); \
	while IFS= read -r -d '' tok; do \
		while [ "$${tok#$$'\n'}" != "$$tok" ]; do tok=$${tok#$$'\n'}; done; \
		case $$tok in :*) ;; *) continue ;; esac; \
		read -r _ _ _ id _ <<<"$$tok"; \
		IFS= read -r -d '' p || { echo "$@: truncated raw diff of $$base..HEAD" >&2; exit 1; }; \
		scan_name "$$p"; \
		if [ -z "$${new[$$id]:-}" ] || [ -n "$${seen["$$id $$sn"]:-}" ]; then continue; fi; \
		seen["$$id $$sn"]=1; \
		case "/$$p/" in *//*|*/./*|*/../*) echo "$@: unsafe path in $$base..HEAD" >&2; exit 1 ;; esac; \
		dir=.; case $$sn in */*) dir=$${sn%/*} ;; esac; \
		k=$${free["$$sn"]:-1}; while :; do \
			d="$$tmp/scan/$$k"; fresh=; [ -d "$$d" ] || fresh=1; \
			if { [ -d "$$d/$$dir" ] || mkdir -p -- "$$d/$$dir" 2>/dev/null; } && [ ! -e "$$d/$$sn" ] && \
				[ ! -L "$$d/$$sn" ]; then break; fi; \
			if [ -n "$$fresh" ]; then echo "$@: cannot write blob $$id" >&2; exit 1; fi; \
			k=$$((k + 1)); \
		done; \
		free["$$sn"]=$$((k + 1)); \
		: >"$$d/$$sn" || exit 1; ids+=("$$id"); dests+=("$$d/$$sn"); \
		b=$$((b + 1)); if [ "$$k" -gt "$$layers" ]; then layers=$$k; fi; \
	done <"$$tmp/raw"; \
	if [ "$$b" -gt 0 ]; then \
		printf '%s\n' "$${ids[@]}" | git -C "$$repo" cat-file --batch >"$$tmp/blobs" || exit 1; \
		exec 3<"$$tmp/blobs" || exit 1; \
		for i in "$${!ids[@]}"; do \
			read -r oid type size <&3 && [ "$$oid $$type" = "$${ids[i]} blob" ] && \
				case $$size in ''|*[!0-9]*) false ;; esac && head -c "$$size" <&3 >"$${dests[i]}" && \
				IFS= read -r nl <&3 && [ -z "$$nl" ] || \
				{ echo "$@: git cat-file --batch did not return blob $${ids[i]} as requested" >&2; exit 1; }; \
		done; \
		exec 3<&-; rm -f -- "$$tmp/blobs"; \
	fi; \
	for d in "$$tmp/scan"/*; do \
		ign="$$d/.gitleaksignore"; \
		if [ -e "$$ign" ] || [ -L "$$ign" ]; then \
			if [ -e "$$ign.changed" ] || [ -L "$$ign.changed" ]; then echo "$@: .gitleaksignore.changed" \
				"is reserved for scanning a changed .gitleaksignore" >&2; exit 1; fi; \
			mv -- "$$ign" "$$ign.changed" || exit 1; fi; \
	done; \
	big=$$(find "$$tmp/scan" -type f -size +$(GITLEAKS_MAX_MB)000000c -printf '%P\n') || exit 1; \
	if [ -n "$$big" ]; then echo "$@: files over $(GITLEAKS_MAX_MB) MB cannot be scanned:" >&2; \
		printf '  %s\n' "$$big" >&2; exit 1; fi; \
	echo "$@: $$n file(s) changed and $$b blob(s) added in $$base..HEAD ($$layers blob layer(s))"; \
	if [ "$$n" -eq 0 ] && [ "$$b" -eq 0 ]; then echo "$@: nothing to scan"; exit 0; fi; \
	docker run --rm -v "$$tmp/scan:/scan:ro" -v "$$tmp/cfg:/cfg:ro" --entrypoint /bin/sh $(GITLEAKS_IMAGE) -c \
		'o=$$(mktemp -d) || exit 1; rc=0; \
		for d in /scan/*; do echo "$${d#/scan/}"; done | xargs -P "$$(nproc)" -I{} sh -c "$$1" sh {} "$$o" || rc=1; \
		for d in /scan/*; do l=$${d#/scan/}; echo "$@: layer $$l"; cat -- "$$o/$$l.log"; \
			[ "$$(cat -- "$$o/$$l.rc" 2>/dev/null)" = 0 ] || rc=1; done; exit $$rc' sh \
		'cd "/scan/$$1" && gitleaks dir . --config /cfg/gitleaks.toml --gitleaks-ignore-path /cfg/gitleaksignore \
		--ignore-gitleaks-allow --max-target-megabytes $(GITLEAKS_MAX_MB) --max-archive-depth 1 --no-banner --redact \
		>"$$2/$$1.log" 2>&1; echo "$$?" >"$$2/$$1.rc"'

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

.PHONY: upstream-check
upstream-check: ## Compare the pins of versions.env, the Himmelblau default, fleetd and the Fleet NVD release with upstream
	go run ./tools/upstreamwatch check
