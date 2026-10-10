# 0023 — Portal design system: tokens, two themes, self-hosted fonts and vendored icons
Status: Accepted (product owner and architect, 2026-10-09)

## Context
The portal (ADR 0015: Vue 3, Vuetify, strict CSP with a style nonce) rendered as default Vuetify in one light theme
with the browser's default font and no icons. The UX review of 2026-10-09 found no overview, status as plain text,
an undifferentiated device page and a squeezed mobile layout. The product owner chose the design direction "Command"
with a light and a dark theme and requires that every font and icon is under an open-source licence (OFL-1.1,
Apache-2.0 or MIT; ISC accepted for icons), self-hosted, with no third-party request at runtime (GDPR, CSP
`default-src 'self'`). CLAUDE.md forbids new dependencies without architect approval.

## Options
- **Theme:** Vuetify themes only (+ stock components follow; − the portal's own components need semantic tokens
  Vuetify does not define: status fg/bg/mark, danger zone, severity) vs. **Vuetify themes plus `--pd-*` custom
  properties from one TypeScript source, checked by a test (chosen)**.
- **Theme preference:** localStorage only (+ no API; − not portable between browsers, unlike the language) vs.
  **account field `theme` with `system|light|dark`, localStorage as early-paint cache (chosen)**.
- **Fonts:** `@fontsource/*` npm packages (− a dependency, subsets are "Modified Versions" under the OFL with Plex's
  Reserved Font Name) vs. Google Fonts (− third-party request, leaks admin IPs, CSP) vs. **upstream woff2 files
  vendored unmodified with their licence texts, checksums in a manifest and in the third-party notice, checked by
  lint (chosen)**.
- **Icons:** `@mdi/js` (− 7 MB dependency, Apache-2.0 fine but bulk) vs. icon font (− CSP, flash of unstyled icon)
  vs. **Lucide SVG files vendored per icon (ISC), compiled by a script into typed path data and rendered by a tiny
  component without `v-html` (chosen)**.
- **Severity:** reuse the status scale (− "high" and "warn" would be the same amber) vs. **a separate severity
  scale with orange "high" (chosen)**.

## Decision
`server/web/src/plugins/theme.ts` is the single source of the Vuetify themes `paddockLight`/`paddockDark` and the
`--pd-*` tokens; `styles/tokens.css` mirrors them under `[data-theme]` and a `prefers-color-scheme` fallback, checked
by a Vitest test. The theme preference is an account field (`Me.theme`, `PATCH /api/v1/me`), default `system`.
IBM Plex Sans and JetBrains Mono (OFL-1.1) and Lucide icons (ISC) are vendored under `server/web/src/assets/` with
licence texts; `assets/vendored.json` holds release tags and SHA-256 per file; `scripts/check-vendored.ts` (part of
`npm run lint`) fails on any unlisted, changed or wrongly licensed file and when `docs/compliance/third-party.md`
lacks the record. Status is always a chip with dot and label (never colour alone); CVE severity uses its own scale.
Keyboard: command palette and navigation shortcuts; no shortcut and no palette entry for destructive or
security-relevant actions; confirm dialogs keep Cancel as default focus (ADR 0018 unchanged).

## Consequences
+ One token vocabulary for both themes; stock Vuetify and own components agree. + No runtime third-party request,
no new npm dependency; licences auditable per file. + Accessibility gates run in both themes.
− Vendored binaries in git (~500 KB). − Font and icon updates are manual (download, checksum, notice).
− The light `warn` mark is below 3:1 on white by design and relies on its label.
Follow-ups: toast component; bulk actions with row selection; per-organization branding (not planned).
