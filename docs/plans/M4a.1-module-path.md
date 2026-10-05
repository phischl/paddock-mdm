# Implementierungsplan: M4a.1 — Go module path matches the repository

Status: Ready for implementation · 2026-10-05 · Author: architect
Basis: product-owner decision 2026-10-05 (repository `github.com/phischl/paddock-mdm`); M0 plan R1 (placeholder path)

Binding language: **MUST** / **MUST NOT**.

## 1. Goal
All Go modules use paths below `github.com/phischl/paddock-mdm`, so `go install` and imports work from the public
repository.

## 2. Binding decisions
1. Module paths: `github.com/phischl/paddock-mdm/pkg`, `…/server`, `…/agent`, `…/test/acceptance`, `…/test/system`
   (replacing `github.com/paddock-mdm/paddock/…`). All imports, `replace` directives, `go.work`, ldflags `-X` paths
   (Makefile, Dockerfile, packaging), sqlc/oapi-codegen configs and generated code are updated; generated code is
   regenerated with `make gen`, not edited by hand.
2. Non-Go identifiers stay unchanged: package names (`paddock-agent`), image names, `urn:paddock:` problem types,
   OpenAPI titles, the CODEOWNERS team placeholder.
3. No other change. CHANGELOG `Changed`: "Go module path is `github.com/phischl/paddock-mdm/…`" (**BREAKING** for
   anyone importing the modules — nobody outside the repository does yet).

## 3. Steps
1. Rewrite paths (scripted), `make gen`, `make lint test`, `make deb`, `make down V=1 && make dev-secrets up dev-seed
   acceptance e2e`, `make system-test VM=paddock-u2604 T='TestAgentGates/.*/S1'` (one VM suffices: binaries and
   packages change only in their embedded paths). `grep -rn "paddock-mdm/paddock" --include=*.go --include=go.* .`
   returns nothing. Commit `refactor!: module path github.com/phischl/paddock-mdm`.

## 4. Stop conditions
A tool or generated artefact cannot be regenerated with the new path; any test needs weakening.
