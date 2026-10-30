# 0015 — Portal frontend
Status: Proposed

## Context
F8 portal for administrators; C7 localizable from the start with ICU MessageFormat; stateless API nodes.

## Options
- **Vue 3 + TypeScript SPA with BFF session.** + Mature i18n, generated typed client, product owner preference.
- **React + TypeScript.** + Native FormatJS. − No advantage that outweighs the preference.
- **Server-rendered Go templates + htmx.** + Fewer moving parts. − Weaker ICU tooling, less rich UI.

## Decision
Vue 3, TypeScript, Vite, Pinia, Vue Router, **Vuetify (MIT)** — amended 2026-10-03: PrimeVue was replaced because PrimeVue 5 is under a commercial license (C8); Vuetify's runtime theme styles are permitted through a per-response CSP nonce. Composition API only. `vue-i18n` with an `intl-messageformat` message compiler.
API client generated from `api/openapi/admin.yaml`. Authentication via BFF in the `api` role: OIDC code + PKCE, tokens
never in the browser, encrypted HttpOnly SameSite=Strict cookie. Tests: Vitest, Playwright with axe.

## Consequences
+ One typed contract from server to UI. − Second toolchain (Node) in CI.

## Amendment 2026-10-28 — Node line of the portal toolchain

**Context.** Node is a build and tooling image only: `NODE_IMAGE` in `deploy/compose/versions.env` runs the portal
build in the `web` stage of `deploy/compose/Dockerfile` and every `npm` call of the Makefile (`NODE_RUN`: `make web`,
`lint-web`, `typecheck`, the portal unit tests in `make test`, the license gate). Nothing ships Node to operators. The
upstream version watch (ADR 0037 amendment 2026-10-17) opened issue #99: `node 24.21.0-trixie-slim →
26.12.1-trixie-slim`, a major. Release v0.1.0-alpha.4 (PR #110) took minors and patches only and deferred majors
without a rule for when to take them. Facts on 2026-10-28 (nodejs/Release `schedule.json`): Node 26 enters Active
LTS on 2026-10-28; Node 24 has been in Maintenance since 2026-10-20 (end 2028-04-30). Every portal devDependency
admits Node 26: Vite 8 (`^20.19.0 || >=22.12.0`), Vitest 5 (`^22.12.0 || ^24.0.0 || >=26.0.0`), jsdom 30 (same),
ESLint 10 (`^20.19.0 || ^22.13.0 || >=24`), typescript-eslint 8 (`>=21.1.0`), Playwright 1.64 (`>=20`),
license-checker-rseidelsohn 5 (`>=24`); vue-tsc and openapi-typescript declare no engines. The Playwright image
`mcr.microsoft.com/playwright:v1.64.1-noble`, which runs `npm ci` and the end-to-end tests (`make e2e`), ships
Node 24 (`ARG NODE_VERSION=24` in its Dockerfile).

**Options.**
- **Stay on Node 24 until its end of life (2028-04-30).** + No work now. − Eighteen months on a line that receives
  security fixes only, while the toolchain already names 26 as a first-class line; the watch issue stays open the
  whole time, which trains everyone to ignore it.
- **Follow the Current release (every major, odd and even).** + Always newest. − Odd majors live eight months; two
  bumps a year of the image that gates every CI run, for a build tool that gains nothing from new runtime features.
- **Follow the Active LTS line; adopt a new even major in the first release after its Active LTS date (chosen).**
  + One bump a year, on the line Node itself recommends for production; a rule that answers the next major (Node 28,
  October 2028) without a new decision. − The bump lands in the same month as the LTS transition, before the
  ecosystem has soaked on it; mitigated by the gates below and by the image being tooling only.

**Decision.**
1. `NODE_IMAGE` follows the Node **Active LTS** line. A new even major is pinned in the first release after its
   Active LTS date, provided every portal devDependency's `engines.node` admits it; an odd (Current) major is never
   pinned. Within the line, patches and the Debian base follow the watch as before. Node 26 is adopted in
   v0.1.0-alpha.7 (ticket PDK-346).
2. `engines.node` in `server/web/package.json` is `>=M`, where M is the lowest Node major among the pinned images
   that run the portal's npm scripts: `NODE_IMAGE` and `PLAYWRIGHT_IMAGE`. It is a claim about where the scripts are
   verified, so it never excludes an image CI actually runs them in. With Playwright v1.64.1-noble on Node 24 it
   stays `>=24`; it moves to `>=26` with the first `PLAYWRIGHT_IMAGE` whose Node is 26.
3. CI follows `versions.env` and nothing else: no `actions/setup-node`, no host `npm`; every npm invocation runs in
   `NODE_IMAGE` (`NODE_RUN`, the Dockerfile `web` stage) or in `PLAYWRIGHT_IMAGE`. A Node bump is complete when
   `versions.env` changes.
4. Gates of a Node major: `make web`, `make lint` (`lint-web`, `lint-image`, `lint-licenses`), `make typecheck`, the
   portal unit tests in the new image, `npm ci` without an `EBADENGINE` warning, an unchanged `package-lock.json`,
   the server image build, and the CI acceptance shards of the pull request (they run the image built from the
   Dockerfile). `make e2e` runs at the release's regression gate.

**Consequences.** + The portal builds on Node's recommended line within weeks of every LTS transition; the watch's
next Node major has an answer. − One build-image bump a year that touches every CI job. − `engines.node` lags the
build image while the Playwright image's Node lags; a wider `engines` than the build image is accepted because it is
true. Follow-up: when the watch proposes a `PLAYWRIGHT_IMAGE` whose Node is 26, raise `engines.node` to `>=26` in
that bump.
