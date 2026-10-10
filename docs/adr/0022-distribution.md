# 0022 — Distribution: published images and an operator bundle
Status: Accepted (2026-10-10)

## Context
Operators installed from a git checkout with make and local image builds (plan M6a). The product owner wants
installation without cloning or building: images on a registry and a self-contained Compose bundle, with the
development stack still building from source and no drift between the two.

## Options
- **Generator that rewrites the Compose files for the bundle** (strip `build:`, replace images). + One source.
  − A YAML transformation step with its own tooling and failure modes; the bundle is not what the repository tests.
- **Copy: the production Compose files carry no `build:`; the development overlay adds it.** + The bundle is a
  byte copy of what the repository tests; no YAML tooling. − `build:` lives in the dev overlay, per service.
- **Separate repository for the bundle.** − Drift by construction.

## Decision
Copy. Three images (`paddock-server`, `paddock-compiler`, `paddock-pgbackrest`) on `ghcr.io/phischl/`, multi-platform
(amd64, arm64), signed keylessly with SBOM attestations, stable tags from `v*` tags and an `edge` channel from `main`.
The bundle `paddock-deploy-<version>.tar.gz` is the only production path; `make` is not used on production hosts.
The bootstrap scripts become production-capable; development-only shortcuts stay behind `require_development`.
Agent packages stay offline-signed and outside the bundle.

## Consequences
+ Install and upgrade are the same documented path, exercised by CI on every release and every green commit.
+ Mirroring is a `.env` override. − The control plane remains amd64-only while Fleet's image is. − GHCR package
visibility is a manual step. Follow-ups: upgrade smoke from the previous release; Fleet on arm64 when upstream
publishes it.
