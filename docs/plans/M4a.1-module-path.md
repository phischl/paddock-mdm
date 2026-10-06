# Implementierungsplan: M4a.1 — Go module path; local admin hidden from the login screen

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

4. **Local admin hidden from GDM** (architect decision 2026-10-06, M4a report question): the agent writes
   `/var/lib/AccountsService/users/<local_admin_username>` with `[User]\nSystemAccount=true` (protected path; drift
   restored). The account stays usable via "Not listed?" at GDM, TTY and SSH. Gate L3/LA1 keyboard navigation is
   adapted back to the list without the local admin; a new LA3 check asserts the account is not listed (AccountsService
   D-Bus `ListCachedUsers` or the GDM screenshot) and can still log in via "Not listed?". CHANGELOG `Changed`.

## 3. Steps
1. Rewrite paths (scripted), `make gen`, `make lint test`, `make deb`, `make down V=1 && make dev-secrets up dev-seed
   acceptance e2e`, `make system-test VM=paddock-u2604 T='TestAgentGates/.*/S1'` (one VM suffices: binaries and
   packages change only in their embedded paths). `grep -rn "paddock-mdm/paddock" --include=*.go --include=go.* .`
   returns nothing. Commit `refactor!: module path github.com/phischl/paddock-mdm`.
2. Decision 4; run LA1, LA3, L3 on both VMs. Commit `feat(agent): hide the managed local admin from the login screen`.

## 4. Stop conditions
A tool or generated artefact cannot be regenerated with the new path; any test needs weakening.
