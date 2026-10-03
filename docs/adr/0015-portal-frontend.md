# 0015 — Portal frontend
Status: Proposed

## Context
F8 portal for administrators; C7 localizable from the start with ICU MessageFormat; stateless API nodes.

## Options
- **Vue 3 + TypeScript SPA with BFF session.** + Mature i18n, generated typed client, product owner preference.
- **React + TypeScript.** + Native FormatJS. − No advantage that outweighs the preference.
- **Server-rendered Go templates + htmx.** + Fewer moving parts. − Weaker ICU tooling, less rich UI.

## Decision
Vue 3, TypeScript, Vite, Pinia, Vue Router, PrimeVue (MIT). `vue-i18n` with an `intl-messageformat` message compiler.
API client generated from `api/openapi/admin.yaml`. Authentication via BFF in the `api` role: OIDC code + PKCE, tokens
never in the browser, encrypted HttpOnly SameSite=Strict cookie. Tests: Vitest, Playwright with axe.

## Consequences
+ One typed contract from server to UI. − Second toolchain (Node) in CI.
