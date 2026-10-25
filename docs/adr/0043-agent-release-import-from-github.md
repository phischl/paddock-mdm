# 0043 — Agent release import from GitHub
Status: Accepted (architect, 2026-10-25)

## Context

An operator brings a new agent release onto the control plane by hand: download the signed files from the GitHub
release, rename them into the layout `<dir>/<arch>/paddockd` and `<dir>/<name>_<version>_<arch>.deb`, make them
readable for the api service and run `./paddock agent-release <version> <dir>` on the host
(`docs/operations/install.md` §10). On the lab this took several attempts on 2026-10-25 and needs shell access to the
host; the upload itself worked as soon as the files were in the `<arch>/paddockd` layout — the manual renaming, not
the verification, was the failure point. The maintainer wants one button in the portal that fetches the newest release from the official repository
and publishes it, ready for the existing staged rollout (PDK-427, wanted for 0.1.0-alpha.6).

Facts about the code that bound the design (checked 2026-10-25):

- The api role already holds everything a release import needs: the release public keys
  (`PADDOCK_RELEASE_PUBLIC_KEY_FILE`, `PADDOCK_REVOKE_RELEASE_PUBLIC_KEY_FILE`), the artifact store credentials of
  `paddock-agent-artifacts`, and the use cases `app.AgentReleases.Create`, `UploadArtifact`, `UploadPackage` and
  `Publish`, each an `ActionRunner` action with its own audit event. `PublishFromHost`
  (`server/internal/app/agentreleases.go`) verifies every file before anything is created and then runs these use
  cases in order; `paddock-server admin agent-release` is its only caller. The worker constructs `AgentReleases`
  without store and verifiers.
- The server's HTTP `WriteTimeout` is 120 s (`server/cmd/paddock-server/run.go`); Caddy's `reverse_proxy` sets no
  response timeout.
- The only outbound call to the public internet today is the worker's OSV download
  (`server/internal/adapters/osvfeed`): a plain `http.Client` with a total timeout and a size bound; the development
  stack points it at a Caddy file server the acceptance gate starts on the network `cp` under a fixed alias
  (`compose.dev.yaml`, `test/acceptance/osv_test.go`). The Go default transport honours `HTTPS_PROXY`, `HTTP_PROXY`
  and `NO_PROXY`.
- Release files on GitHub (`.github/workflows/release.yml`, `make release-packages`, `packaging/sign-release.sh`, ADR 0006
  amendment 2026-10-11): `paddockd_<v>_linux_amd64` and `paddockd_<v>_linux_arm64`; `paddock-agent_<v>_amd64.deb` and
  `paddock-supervisor_<v>_amd64.deb` — `make deb` builds the packages for **amd64 only** (v0.1.0-alpha.5 has 19 assets,
  the packages exist as `_amd64.deb` alone), while the sign script signs every `paddock-agent` and `paddock-supervisor`
  package it finds, whatever its architecture; each signed file has a `.minisig` whose trusted comment is
  `paddock-agent version=<v> arch=<arch>`; `paddock-revoke_<v>_<arch>-unsigned.deb` (never
  signed by CI); `SHA256SUMS` with a keyless Sigstore bundle `SHA256SUMS.sigstore.json`. The tag is `v<v>` with `<v>`
  matching `make release-check`: `x.y.z` or `x.y.z-(alpha|beta|rc).N`. fleetd and the offline-signed `paddock-revoke`
  are attached by hand after the workflow, outside `SHA256SUMS`.
- GitHub's REST API (`GET /repos/{owner}/{repo}/releases`, version `2022-11-28`): draft releases are invisible to
  unauthenticated callers; `per_page` is 30 by default and 100 at most; each asset carries `name`, `size` and
  `browser_download_url`; the unauthenticated primary rate limit is 60 requests per hour per source IP, a token raises
  it to 5 000; an exceeded limit answers 403 or 429 with `x-ratelimit-remaining: 0` and `x-ratelimit-reset` (UTC epoch
  seconds). Asset downloads under `github.com/<owner>/<repo>/releases/download/…` redirect to
  `*.githubusercontent.com` and are not metered by the API limit.
- Design contract 5 (signed artifacts, the public key belongs to the supervisor), 6 (staged rollout) and 8 (fail safe);
  CLAUDE.md: configuration only through environment variables, secrets only from `*_FILE`; ADR 0018: state-changing
  actions are `POST /<collection>/{id}/<verb>`; ADR 0034: step-up for high-risk platform actions.

## Options

### Which role makes the outbound call
- **The worker, as a job the portal polls.** + The worker is the role that already reaches the internet (OSV).
  − It would gain the artifact store credentials and the release keys; a job table, a status endpoint and a poll loop
  in the portal are needed; three times the scope of the feature.
- **A new role (`paddock-release-importer`), like ADR 0031's notifier.** + Least privilege for the process that
  reaches the internet. − One more service, database role, set of secrets, bundle and `prod-check` work, for a call
  whose destination is operator configuration, not administrator input (the SSRF argument of ADR 0031 does not apply).
- **The api, synchronously in the request (chosen).** + Nothing new to deploy; the api holds the keys, the store and
  the use cases; one request, one audit event, one response the portal shows. − The import must finish inside the
  server's write timeout; a slow link fails the import (nothing is stored) and the operator falls back to the host
  command.

### Trust chain
- **minisign only (chosen).** The control plane's copy of the production release public key is the trust anchor;
  GitHub is transport. + The signature binds content, version and architecture (`pkg/releasesig`); the same check the
  supervisor makes before installing; no new dependency. − A compromise of the GitHub repository together with the
  release key secret produces a validly signed agent — the risk ADR 0006 (amendment 2026-10-11) already accepts for
  every release, import or not.
- **minisign plus `SHA256SUMS` with its Sigstore bundle.** + Proves the files were produced by the release workflow
  of this repository. − Verifying a Sigstore bundle needs `sigstore-go` (a large dependency tree) or the `cosign`
  binary in the image; `SHA256SUMS` does not cover fleetd or `paddock-revoke`; the identity it proves ("built by the
  workflow in this repository") is the same party that serves the files, so it adds no independent factor as long as
  the signing key lives in that workflow's environment. Deferred; revisit when the release key returns offline.

### Where the source is configured
- **A platform setting in the portal.** + Changeable without a restart. − Whoever holds a platform administrator
  session could point the fleet at another repository (minisign still protects, but the surface grows); CLAUDE.md
  binds configuration to environment variables.
- **Environment variables of the api role (chosen).** + The host operator decides where agent code comes from, as
  they decide the keys; air-gapped installations switch it off in `.env`; no migration.

### API shape
- **`POST /api/platform/v1/agent-releases/{version}/import`.** − The resource does not exist before the import; the
  path suggests an action on an existing release.
- **`POST /api/platform/v1/agent-releases/import` with the version in the body (chosen)**, plus a check operation
  that does not change state. + The collection verb is the shape of `POST /api/platform/v1/sessions/end-all`; the
  body carries the version the administrator confirmed in the dialog, so what was shown is what is imported.

### Check operation: GET or POST
- **GET.** + Safe and idempotent by the book. − It performs a metered outbound call; anything that follows links
  (prefetch, a monitoring probe, a reload) would spend the rate budget.
- **POST (chosen).** The check runs only when an administrator clicks; it needs the CSRF header like every POST. It
  carries no `x-paddock-audit`: it changes nothing and grants nothing.

## Decision

1. **Boundary.** The api role imports agent releases from a GitHub-compatible release source, synchronously in the
   request. The adapter is the package `server/internal/adapters/githubreleases`; the use cases are
   `app.ReleaseImports` in `server/internal/app/releaseimport.go`, which depend on `app.AgentReleases` and a small
   `ReleaseSource` interface declared in `app`. The import of a version is one privileged action
   `agent_release.imported` (platform administrator, step-up required, one audit event per attempt); inside it, the
   existing use cases `Create`, `UploadArtifact`, `UploadPackage` and `Publish` run with the same principal and record
   their own events, exactly as the platform API and `paddock-server admin agent-release` do. `PublishFromHost` and
   the import share one function that verifies every file before anything is created or stored; the host command
   keeps its system actor, the import keeps the administrator.
2. **Trust chain.** Every imported file is verified with the release public key the api already holds
   (`PADDOCK_RELEASE_PUBLIC_KEY_FILE`) and, for the agent binaries, with the trusted comment
   `paddock-agent version=<v> arch=<arch>`, before the release is created. GitHub is transport only: nothing it says
   about a file (size, digest, content type, tag) is trusted beyond the selection of candidates. `SHA256SUMS` and
   its Sigstore bundle are not fetched or verified (option above; residual risk RR-84). Unsigned files are never
   imported; `paddock-revoke` is never imported through this path, with or without a signature — it stays on the
   offline two-person path (`docs/operations/agent-releases.md`).
3. **Version selection.** Candidates are the releases of the first page of
   `GET <source url>/repos/<repo>/releases?per_page=100` that are not drafts and whose `tag_name` is `v<v>` with `<v>`
   matching `^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)\.(0|[1-9][0-9]*))?$`
   (`agentrelease.ValidateSourceVersion`, the rule of `make release-check`; GitHub's `prerelease` flag is ignored).
   *Latest* is the candidate with the highest SemVer precedence (`pkg/semver.Compare`). A version is *importable*
   when it is newer than the newest **published** release stored on the control plane and no published release with
   that version exists; a stored **draft** of the same version is continued, as `PublishFromHost` continues one.
   Equal is not newer; downgrades are refused (409 `release_not_newer`). The import takes the version from the
   request body and applies the same rule to it, so what the check showed is what is imported.
4. **Asset set.** The required set is exactly what the release workflow ships today: `paddockd_<v>_linux_amd64`,
   `paddockd_<v>_linux_arm64`, `paddock-agent_<v>_amd64.deb` and `paddock-supervisor_<v>_amd64.deb`, each with
   `<asset>.minisig`. Optional, imported when present with its `.minisig`: `paddock-agent_<v>_<arch>.deb` and
   `paddock-supervisor_<v>_<arch>.deb` for every other architecture of `agentrelease.Arches` (the sign script signs
   them as soon as `make deb` builds them, so the import needs no change then), and
   `fleet-osquery_<fleetd version>_<arch>.deb` (imported as package `fleet-osquery` with `package_version`, verified
   with the agent release key as today). An optional asset that is present without its signature refuses the import.
   A missing required asset or signature refuses the import (422 `release_incomplete`, the detail names the first
   missing asset). Every other asset — `paddock-revoke*`, `*-unsigned*`, `SHA256SUMS*`, `*.sigstore.json`, anything
   else — is ignored. The required set lives in one place, `agentrelease.SourceAssets`, and a unit test holds it equal
   to the files `packaging/release_test.sh` expects from the sign job.
5. **Transport policy.** `https` only; `http` only with `PADDOCK_ENV=development` (the loader refuses it otherwise).
   The client's transport is `http.DefaultTransport.(*http.Transport).Clone()` with `DialContext` timeout 10 s,
   `TLSHandshakeTimeout` 10 s and `ResponseHeaderTimeout` 15 s; proxies come from the environment
   (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, passed through to the api service by Compose). Requests carry
   `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `User-Agent: paddock-server` and, when a
   token is configured, `Authorization: Bearer <token>`. Bounds: the release list body ≤ 1 MiB and ≤ 15 s; each asset
   ≤ `agentrelease.MaxArtifactBytes` (128 MiB) by the listed `size` and by a limited reader, ≤ 60 s; each `.minisig`
   ≤ 4 KiB; the whole import ≤ 90 s (a context deadline below the server's 120 s write timeout). An asset URL
   (`browser_download_url`) and every redirect target (at most 5) must use the allowed scheme and a host that is the
   source URL's host, `github.com`, or a subdomain of `githubusercontent.com`; anything else fails the import. A
   403 or 429 with `x-ratelimit-remaining: 0` is reported as 502 `release_source_unavailable` with the reset time in
   the detail; nothing is retried. Response bodies of failed requests are discarded.
6. **Configuration** (api role, environment variables):
   `PADDOCK_AGENT_RELEASE_SOURCE_REPO` — `<owner>/<repo>` matching `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`, default
   `phischl/paddock-mdm`; the value `off` disables the feature (air-gapped installations): the portal hides the
   panel, the check and the import answer 403 `release_source_disabled`.
   `PADDOCK_AGENT_RELEASE_SOURCE_URL` — the API base, default `https://api.github.com`; a GitHub Enterprise Server
   uses `https://<host>/api/v3`; the development stack uses `http://github-fixture:8080`.
   `PADDOCK_AGENT_RELEASE_SOURCE_TOKEN_FILE` — optional; the file holds a token with read access to the repository's
   releases; it is never logged, never audited, never shown. Without it the unauthenticated budget of 60 requests per
   hour applies, of which a check costs one and an import one (downloads are not metered).
7. **API** (platform administrators, `api/openapi/admin.yaml`):
   `GET /api/platform/v1/agent-release-source` → 200 `{enabled, repository, url}`, no outbound call;
   `POST /api/platform/v1/agent-release-source/check` → 200 `{latest, published_at, newest_stored, importable, reason}`
   with `reason ∈ {none_found, not_newer}` when `importable` is false, 403 `release_source_disabled`,
   502 `release_source_unavailable`; not audited;
   `POST /api/platform/v1/agent-releases/import` with body `{version}` → 201 `AgentReleaseDetail` and `Location`,
   `x-paddock-audit: agent_release.imported`, step-up required; 400 `invalid_request` (version outside the pattern, or
   a file whose signature does not verify), 403 `step_up_required` | `forbidden` | `release_source_disabled`,
   404 `not_found` (the version is not on the source), 409 `release_not_newer`, 422 `release_incomplete` |
   `release_signature_mismatch`, 502 `release_source_unavailable` | `upstream_unavailable` (artifact store).
   Audit params of `agent_release.imported`: `source` (the repository), `source_url`, `version`, `newest_stored`,
   `files` (on success: the number of files stored). Nothing about the token.
8. **Fail safe.** Any error before the release is created leaves the control plane unchanged. An error after the
   creation (the artifact store fails mid-way) leaves a draft with the files stored so far, as the host command does;
   the import event records the failure, and the next import of the same version continues the draft. The import
   never starts a rollout.
9. **Tests.** Unit tests of `githubreleases` against `httptest` servers (selection, filters, host and redirect rules,
   size and time bounds, rate-limit mapping); unit tests of `agentrelease.ValidateSourceVersion` and the selection
   rule; an app integration test with a fake `ReleaseSource`; handler tests with an `httptest` source; the acceptance
   gate `TestAgentReleaseImport` and the A3 cases of the import operation import from a Caddy file server the gate
   starts on the network `cp` under the alias `github-fixture` (the OSV fixture pattern), signed with the development
   release key. No test contacts GitHub; CI holds no GitHub token for the stack.

## Consequences

- + One click and a step-up replace the five manual steps; the imported release is byte-for-byte what the host
  command would have stored, with the same audit trail plus one import event.
- + No new Go module, npm package or container image; no new role, database role or secret.
- − The control plane makes an outbound request to a third party for the first time (the worker's OSV download is
  the only precedent): `docs/compliance/privacy.md` and `docs/architecture.md` §3.2 name it; the request carries the
  installation's public IP and no device, organization or inventory data.
- − The import is bounded by 90 s; a slow or filtered uplink fails it without side effects and the host command
  remains the fallback. If this bounds real installations, the follow-up is an asynchronous import job in the worker
  with a status endpoint — not a longer timeout.
- − Residual risk **RR-84** (RR-74 to RR-76 belong to M8b, RR-77 to RR-83 are reserved by plan M13a): *The import
  trusts the release public key alone.* A party that controls the GitHub
  repository and the release key secret of its `release` environment can publish an agent the import accepts; the
  Sigstore bundle is not verified. Mitigation: the key's protected environment with required approval (ADR 0006
  amendment 2026-10-11), the staged rollout with automatic halt, the step-up on the import, the supervisor's own
  verification; the operator may switch the source off and import by hand. Revisit when the release key returns
  offline (then the Sigstore provenance is an independent factor worth the dependency).
- Follow-ups: PDK-427 (server, API, gate, docs) and PDK-428 (portal). Rotation of the release key continues to need a
  new supervisor package and a changed `PADDOCK_RELEASE_PUBLIC_KEY_FILE`; the import inherits the new key with it.
