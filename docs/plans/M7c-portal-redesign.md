# Implementierungsplan: M7c — Portal redesign "Command" (light and dark)

Status: Ready for implementation (after M6b; independent of M7a and M7b, see §2) · 2026-10-09 · Author: architect
Basis: architecture v1.7 §18 (portal, i18n, accessibility, CSP), §22 (test strategy); ADR 0015 (Vuetify, CSP nonce),
ADR 0018 (lists and dialogs); plan M5b decision 11 (attention list), M5c decision 5 (severity chips), M6b decisions
2, 3 and 6 (German catalog, license gate, README screenshots); UX review of 2026-10-09 (top 10 problems) and the design
spec "Direction A — Command" (tokens and component spec, boards A1/A2 dark and light); product-owner decisions of
2026-10-09 (Direction A, two themes, open-source fonts only, severity scale, keyboard model); CLAUDE.md "General"
(no new dependency without architect approval; configuration via environment only).

Binding language: **MUST** / **MUST NOT** / **SHOULD** / **MAY**.

## 1. Goal

An organization administrator opens the portal and sees a real overview (fleet KPIs, attention grouped by device,
vulnerability severity bar, updates and agent rollout, recent audit activity), reads status as chips instead of plain
text everywhere, works a device in a list/detail split view whose destructive actions sit in a separate danger zone,
and can do all of it from the keyboard (command palette, `j`/`k`, `g`-shortcuts) on a 390 px phone as well as on a
1920 px screen — in a light or dark theme that follows the system by default and is stored on the account.

## 2. Context

- **Current portal (code is the truth):** Vue 3.5 + Vuetify 4.2.3 + vue-i18n with ICU messages; one theme
  `paddock` (`server/web/src/plugins/vuetify.ts`, light only); Roboto is not loaded, the browser default sans is
  used; `server/web/src/styles.css` holds ad-hoc colours (`--danger`, `--muted`, `--focus`) and layout classes. The
  shell (`server/web/src/App.vue`) has a dark green `v-app-bar`, a `v-navigation-drawer` with the seven groups of
  `server/web/src/lib/navigation.ts` (no icons; hidden or shown by `nav-toggle`, state in localStorage key
  `paddock.navigation.hidden`), an unlabelled attention badge, and a user menu with a language submenu stored on the
  account through `PATCH /api/v1/me {locale}` (`server/internal/app/accounts.go: UpdateLocale`, `MeUpdate` requires
  `locale`). Lists use `server/web/src/components/DataList.vue` (ADR 0018; state in the route query via
  `server/web/src/lib/listQuery.ts`). Confirmations use `ConfirmDialog.vue` through `composables/useConfirm.ts`
  (title, message, confirm label, destructive, typed text; no reason field). `Home.vue` only shows "Loading…" and the
  router sends org admins to `/attention` while it has rows, else to `/device-groups` (`router.ts`,
  `e2e/checks.ts: expectAdminStartPage`). The vulnerability tile (`VulnerabilityTile.vue`) sits on the Device groups
  page. `DeviceDetail.vue` is one column: identity table, `LocalAdminCard`, `DiskEncryptionCard`, `UpdatesCard`,
  `RevocationCard` (shared Reason field, Lock/Destroy buttons, step-up, then typed confirmation), commands, groups,
  login, sudo, reports, effective configuration; `Retire` floats next to the h1; `DeviceTabs.vue` links Details /
  Software / Vulnerabilities. `Attention.vue` lists one row per condition from `GET /api/v1/attention` (view
  `attention_condition`, migration `00027`). `Audit.vue` renders the sentence `audit.<code>` with `target.display`
  or `target.id` when `hostname` is not a param (`lib/format.ts: auditText`), so device UUIDs appear in sentences of
  events whose target display is empty; timestamps are `Intl.DateTimeFormat` medium/medium and wrap.
- **Server:** admin API from `api/openapi/admin.yaml` (oapi-codegen → `adminapi.gen.go`, sqlc → `pgstore`,
  `npm run gen` → `schema.d.ts`; all through `make gen`). List contract enforced by `listing.Spec` +
  `listspec_test.go` (every collection GET needs an entry) + the acceptance gate `test/acceptance/list_contract_test.go`;
  isolation gate `test/acceptance/isolation_fixtures.go` (every GET below `/api/v1/` needs a fixture; every collection
  GET an entry in `listIsolationQueries`). Audit events live in the separate audit database (`db.AuditReader`,
  `auditstore`), `target` and `actor` are jsonb; device events carry `hostname` in params only where the code
  registry lists it (`server/internal/domain/audit/codes.go`). `device_status.health` (jsonb) carries
  `disk.state` and `reboot_required`; `device_status.login_state` carries the latest `updates_security` and
  `updates_regular` reports; staleness alerts are rows of `device_alert` (kinds `stale_warning`, `stale_critical`,
  `cleared_at IS NULL` while open) and `device_status.presumed_lost_at`. The vulnerability summary query is
  `VulnerabilitySummary` in `server/internal/adapters/postgres/queries/inventory.sql`. The current agent release is
  `paddock_current_agent_version()`.
- **Static files:** the api role serves `server/web/dist` with `http.FileServerFS` (`static.go`); the CSP is
  `default-src 'self'; style-src 'self' 'nonce-…'` (fonts from the same origin are covered by `default-src`). Go's
  built-in MIME table has no entry for `.woff2`, and the distroless image has no `/etc/mime.types`.
- **Gates that exist and stay green:** acceptance (`make acceptance`), e2e (`make e2e`, `server/web/e2e/*.spec.ts`
  with `expectAccessible` = axe serious/critical), `make lint` (ESLint incl. no-raw-text and no-v-html, message
  catalog check, license gate), Vitest.
- **ADRs touched:** new **ADR 0023** (§6.8, text verbatim; 0021 is M7a, 0022 is M7b). ADR 0015 and 0018 stay as
  they are and remain binding. Plan M6b decision 6 and `e2e/screenshots.spec.ts` are amended (§6.9): screenshots in
  light **and** dark again; the architect note of 2026-10-08 ("light only") is superseded by this plan.
- **Order with M7a/M7b:** independent. M7a adds a page `/platform/ip-allowlist` and a nav item `nav.ipAllowlist`;
  if M7a lands first, that item gets the icon `globe-lock` (§3.3) and the empty state of §3.10; if this plan lands
  first, M7a's coding agent uses the components of this plan.

## 3. Binding decisions

### 3.1 Theme preference on the account (server)

1. **Migration** `server/migrations/paddock/00036_account_theme.sql` (forward-only, `-- +goose Up` only, empty
   Down like `00027`):
   ```sql
   ALTER TABLE admin_account  ADD COLUMN theme text NOT NULL DEFAULT 'system' CHECK (theme IN ('system','light','dark'));
   ALTER TABLE platform_admin ADD COLUMN theme text NOT NULL DEFAULT 'system' CHECK (theme IN ('system','light','dark'));
   ```
   No RLS change (both tables keep their policies; the column is organization data of the account row).
2. **Contract:** `Me.theme` (required, enum `system|light|dark`); `MeUpdate` becomes a patch of two optional
   fields `locale` and `theme` with `minProperties: 1` and `additionalProperties: false` (§6.1). `GET /api/v1/me`
   for an API token answers `theme: system`. `PATCH /api/v1/me` with an API token stays 403 (as today for locale).
3. **Use case:** `app.Accounts.UpdateLocale` is replaced by `app.Accounts.UpdateSettings(ctx, AccountSettings{Locale *string;
   Theme *string}) (Me, error)`: validates each present field against `SupportedLocales` / `SupportedThemes =
   []string{"system","light","dark"}` (400 `invalid_request` with detail `unsupported locale` / `unsupported theme`),
   requires at least one field (400 `invalid_request`), updates in one statement per table
   (`UpdateAdminAccountSettings` / `UpdatePlatformAdminSettings` with `coalesce(sqlc.narg(locale), locale)` and
   `coalesce(sqlc.narg(theme), theme)`), returns `GetMe`. Not a privileged action (no audit, as today for locale).
4. **Session cookie:** unchanged (`Session.Loc` stays; the theme is not needed server-side).

### 3.2 Design tokens, two Vuetify themes, fonts, icons (portal)

5. **Single source of truth** `server/web/src/plugins/theme.ts` exports `paddockLight` and `paddockDark`
   (`ThemeDefinition`, exactly the `colors` and `variables` of the design spec §7) and `pdTokens: Record<'light' |
   'dark', Record<string, string>>` with every `--pd-*` token of the spec §1 (surfaces, borders, text, accent, status
   ok/warn/critical/info/neutral with `fg`/`bg`/`mark`, severity §3.2 item 7, danger zone, focus, scrim, shadow).
   `server/web/src/styles/tokens.css` declares the same values under `:root, :root[data-theme="light"]`,
   `:root[data-theme="dark"]` and `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { … } }`, plus
   the theme-independent block (fonts, radii, spacing, motion, `--pd-row-pad`). A Vitest test parses `tokens.css`
   and asserts that the three blocks contain exactly the tokens of `pdTokens.light` / `pdTokens.dark` with equal
   values; the test fails on any drift. `styles.css` is rewritten to use tokens only: no hex colour outside
   `theme.ts` and `tokens.css` (a Vitest test greps `src/**/*.{vue,css,ts}` except these two files for
   `#[0-9a-f]{3,8}\b` inside `style` blocks and `.css` files and fails on a match).
6. **Theme names and switching:** Vuetify themes `paddockLight` and `paddockDark` (the old `paddock` theme is
   removed). `server/web/src/lib/theme.ts`:
   ```ts
   export type ThemePreference = 'system' | 'light' | 'dark'
   export type ResolvedTheme = 'light' | 'dark'
   export const themeCacheKey = 'paddock.theme'                 // localStorage: the preference, early-paint cache only
   export function cachedPreference(): ThemePreference         // localStorage, try/catch, default 'system'
   export function resolveTheme(pref: ThemePreference, systemDark: boolean): ResolvedTheme
   export function vuetifyThemeName(resolved: ResolvedTheme): 'paddockLight' | 'paddockDark'
   export function applyTheme(pref: ThemePreference): void     // sets theme.global.name, <html data-theme>, caches pref
   ```
   `applyTheme` subscribes once to `matchMedia('(prefers-color-scheme: dark)')` changes and re-resolves while the
   preference is `system`. `plugins/vuetify.ts` sets `defaultTheme: vuetifyThemeName(resolveTheme(cachedPreference(),
   matchMedia(...).matches))` so the first paint already has the right theme (no inline script, CSP unchanged).
   `main.ts` sets `document.documentElement.dataset.theme` before `mount`. The session store applies `me.theme` after
   `load()` and offers `setTheme(pref): Promise<boolean>` (PATCH `/api/v1/me {theme}`, mirrors `setLocale`).
   `:root[data-theme]` sets `color-scheme: light` / `dark` so form controls and scrollbars follow. Theme switching
   is instant (Vuetify `change(name, false)`, no cross-fade).
7. **Severity scale** (separate from the status scale; CVE chips, severity bar, KPI dots), tokens
   `--pd-sev-<level>-fg|bg|mark`:

   | Level | Light fg / bg / mark | Dark fg / bg / mark | Contrast fg on bg |
   | --- | --- | --- | --- |
   | critical | `#a8201a` / `#fde8e6` / `#c4382d` (= status critical) | `#ff9a93` / `#341a1c` / `#ff9a93` | 6.2 / 7.9 |
   | high | `#9a3b00` / `#fde9d9` / `#e2711d` (orange) | `#ffb27a` / `#3a2416` / `#f0945a` (orange) | 5.9 / 8.2 |
   | medium | `#7d4f00` / `#fcefd3` / `#e3bd3c` | `#f5c56b` / `#30271a` / `#d9c25a` | 6.2 / 9.1 |
   | low | `#1f4fa6` / `#e3ecfa` / `#6f93c4` | `#9cbcf5` / `#1a2436` / `#6f8fb3` | 6.5 / 8.1 |
   | unknown | = status neutral | = status neutral | 6.7 / 8.2 |
   | none (bar only) | mark `#bfe3cf` | mark `#2b4a3c` | – |

   The light status `warn` mark stays `#e0a526` as specified (always paired with its label).
8. **Fonts:** IBM Plex Sans (400, 500, 600; upstream split Latin1 woff2, unmodified) and JetBrains Mono (400, 500;
   upstream woff2, unmodified), both OFL-1.1, vendored under `server/web/src/assets/fonts/ibm-plex-sans/` and
   `server/web/src/assets/fonts/jetbrains-mono/` with the upstream licence texts (`LICENSE.txt` for Plex, `OFL.txt`
   for JetBrains Mono, verbatim). Latin Extended-A coverage: Plex ships a `Latin2` split; it is vendored too
   (`IBMPlexSans-{Regular,Medium,SemiBold}-Latin2.woff2`) and scoped with `unicode-range: U+0100-017F, U+0180-024F`
   so names with ł, ő, č render in Plex (product owner: Latin and Latin-ext). JetBrains Mono's full woff2 covers
   Latin-ext already. `@font-face` rules live in `server/web/src/styles/fonts.css` (`font-display: swap`, `src:
   url("../assets/fonts/…")`). The download is done once from the official GitHub releases (`IBM/plex`, package
   `plex-sans`; `JetBrains/JetBrainsMono`), the release tags are pinned in the manifest of item 10. **MUST NOT:** an
   npm font package, a font CDN, `pyftsubset` or any font-processing build plugin, italics, other weights.
   `font-src` needs no CSP change (`default-src 'self'`). `server/internal/transport/http/admin/static.go` MUST
   register `mime.AddExtensionType(".woff2", "font/woff2")` at init, with a test in `static_test.go` that a request
   for a `.woff2` file under `/assets/` answers `Content-Type: font/woff2`.
9. **Icons:** Lucide (ISC), the newest tagged release at implementation time, vendored as SVG files under
   `server/web/src/assets/icons/lucide/<name>.svg` with `LICENSE` verbatim. Only the icons of §3.3 and §3.4 are
   vendored (no bulk copy). `server/web/scripts/gen-icons.ts` (run by `npm run gen:icons`, checked by `npm run
   gen:icons -- --check` inside `npm run lint`) reads the files and writes `server/web/src/lib/icons.gen.ts`:
   ```ts
   export type IconNode = [tag: 'path' | 'circle' | 'rect' | 'line' | 'polyline' | 'polygon' | 'ellipse', attrs: Record<string, string>]
   export const icons = { 'layout-dashboard': [...], ... } as const satisfies Record<string, readonly IconNode[]>
   export type IconName = keyof typeof icons
   ```
   The generator accepts only those elements and the attributes `d cx cy r x y width height rx ry x1 x2 y1 y2 points`
   and fails on anything else (no `<script>`, no `style`, no `href`). `server/web/src/components/PdIcon.ts` is a
   `defineComponent` render function (no `v-html`): `<svg viewBox="0 0 24 24" width/height=size fill="none"
   stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">` + the nodes; props
   `name: IconName`, `size?: number` (default 16), `label?: string` (absent → `aria-hidden="true"`, present →
   `role="img"` + `aria-label`). Registered as Vuetify icon set `pd` (`icons.sets.pd = { component: PdIcon }`) so
   `icon="pd:laptop"` works in Vuetify props; `aliases` and `mdi` stay for Vuetify's internal icons.
10. **Vendored-asset manifest and gate:** `server/web/src/assets/vendored.json`:
    ```json
    { "sets": [ { "name": "IBM Plex Sans", "license": "OFL-1.1", "source": "https://github.com/IBM/plex",
                  "release": "<tag>", "dir": "fonts/ibm-plex-sans", "license_file": "LICENSE.txt",
                  "files": { "IBMPlexSans-Regular-Latin1.woff2": "<sha256>", ... , "LICENSE.txt": "<sha256>" } },
                { "name": "JetBrains Mono", ... "dir": "fonts/jetbrains-mono", "license_file": "OFL.txt", ... },
                { "name": "Lucide", "license": "ISC", "source": "https://github.com/lucide-icons/lucide",
                  "release": "<tag>", "dir": "icons/lucide", "license_file": "LICENSE", "files": { "laptop.svg": "<sha256>", ... } } ] }
    ```
    `server/web/scripts/check-vendored.ts` (run by `npm run lint`, so by `make lint-web`) fails when: a file under
    `src/assets/fonts/**` or `src/assets/icons/**` is not listed; a listed file is missing or its SHA-256 differs; a set
    has no licence file or its licence is not one of `OFL-1.1`, `Apache-2.0`, `MIT`, `ISC`; or
    `docs/compliance/third-party.md` does not contain, for every font file, its SHA-256, and for every set, its
    release tag. `docs/compliance/third-party.md` gets a section "Vendored fonts and icons (checked by
    `check-vendored.ts`)" with one table per set (file, weight/subset, SHA-256) and the provenance sentence. The npm
    allow list and `make lint-licenses` are unchanged (fonts and icons are not packages).
11. **Typography and density:** the type scale of the spec §2 as CSS classes `pd-type-title`, `pd-type-title-mono`,
    `pd-type-section`, `pd-type-body`, `pd-type-table`, `pd-type-label`, `pd-type-caption`, `pd-type-overline`,
    `pd-type-kpi`, `pd-type-data`, `pd-type-kbd` in `styles/typography.css`; `body` uses `--pd-font-sans` 13/19;
    `.mono`, hostnames, IDs, versions, CVE ids, timestamps and audit codes use `--pd-font-mono`; numbers in tables
    `font-variant-numeric: tabular-nums`. Density is a viewer preference (`localStorage` key `paddock.density`,
    `compact` default, `comfortable`), switched in the user menu, applied through `<v-defaults-provider>` at the app
    root (`VBtn`, `VTextField`, `VSelect`, `VTextarea`, `VAutocomplete`, `VDataTableServer`, `VListItem` get
    `density: 'compact' | 'comfortable'`) and `<html data-density>` (`--pd-row-pad` 6 px / 10 px). Vuetify defaults:
    `VBtn { rounded: 'sm', variant: 'outlined' }`, `VTextField/VSelect/VTextarea/VAutocomplete { variant: 'outlined' }`,
    `VChip { size: 'small', rounded: 'sm' }`, `VNavigationDrawer { width: 220, railWidth: 52 }`. Touch targets below
    600 px are at least 44 px regardless of density (`@media (max-width: 599.98px)` raises button and row heights).
12. **Motion:** tokens `--pd-motion-fast|base|exit|toast` as in the spec §6; `@media (prefers-reduced-motion: reduce)`
    sets every `--pd-motion-*` duration to `0ms` and Vuetify transitions to none (`.v-overlay__content,
    .v-dialog > .v-overlay__content { transition-duration: 0ms !important }` and `transition="false"` on the palette
    and the help dialog when `matchMedia('(prefers-reduced-motion: reduce)').matches`). No animated counters, bars or
    skeleton shimmer; loading placeholders are static `--pd-surface-3` blocks.

### 3.3 Shell: app bar, navigation drawer, command palette, keyboard

13. **App bar** (`App.vue`): 44 px, `--pd-surface-1`, bottom `--pd-border`; left to right: `nav-toggle` (keeps its
    testid and `aria-controls="main-navigation"`; label "Collapse the navigation" / "Expand the navigation" from
    1280 px, "Show/Hide the navigation" below), logo mark (existing `/paddock-symbol-*.svg`, 20 px), "Paddock",
    `/`, organization name (`org-name`), the command field (`data-testid="command-field"`, a real `<input>` with
    visually hidden label `app.commandField` = "Search or run a command", `kbd` hint `Ctrl K` or `⌘ K` by platform;
    below 600 px replaced by an icon button `pd:search` with the same label), the **attention pill**
    (`data-testid="app-bar-attention"`, a `RouterLink` to `/attention` styled as a critical status chip with dot and
    label `nav.attentionPill` = "{count, plural, one {# needs attention} other {# need attention}}"; hidden when 0 or
    when the role may not read it), the **theme toggle** (`data-testid="theme-toggle"`, icon `pd:sun` in dark /
    `pd:moon` in light, `aria-label` `app.themeToggle.toDark` = "Switch to the dark theme" / `toLight`; sets the
    explicit preference `dark` or `light` on the account), and the account button (`user-menu`: avatar initial, display
    name, role in muted caption; below 600 px avatar only). The old `v-badge` counters are removed.
14. **User menu:** items in this order: signed-in-as (name, role), Language (submenu, as today), **Theme** (submenu
    `data-testid="theme-menu"`, options `theme-system|theme-light|theme-dark`, labels `app.themes.system|light|dark` =
    "System" / "Light" / "Dark", current option `active`), **Density** (submenu `density-menu`, options
    `density-compact|density-comfortable`, labels `app.densities.compact|comfortable` = "Compact" / "Comfortable"),
    **Keyboard shortcuts** (`shortcuts-help`, opens the help dialog), Sign out. Saving a theme that fails shows the
    existing snackbar pattern with `app.themeFailed` = "The theme could not be saved."
15. **Navigation drawer:** `<nav aria-label="Main navigation">` (label unchanged for the e2e helper `mainNav`),
    `--pd-surface-2`, 220 px expanded, 52 px rail. Group headers are `<h2 class="pd-type-overline">` (not focusable,
    `aria-hidden` in rail mode where they are replaced by a divider). Items are `RouterLink`s with
    `aria-current="page"` on the active item, a 16 px `PdIcon`, the label, and the `g`-shortcut hint (muted
    `pd-type-kbd`, `aria-hidden`) for the six items that have one. Rail mode shows the icon only with a `v-tooltip`
    and `aria-label` = label. Keyboard: roving tabindex (one Tab stop; Up/Down move, Home/End jump, Enter follows);
    `[` toggles collapse (also a visible button: `nav-toggle`). States: ≥ 1280 px expanded by default, collapsible to
    rail; 600–1279 px rail by default, expandable; < 600 px temporary modal drawer (closes on navigation, as today).
    Stored per viewer in localStorage key `paddock.navigation.collapsed` (`true|false`; the old key
    `paddock.navigation.hidden` is read once for migration and then removed). The drawer scrolls independently
    (`overflow-y: auto`). `navigation.ts` gets `icon: IconName` and `shortcut?: string` per item:

    | Item | Icon | Shortcut |
    | --- | --- | --- |
    | `/` Overview (label `nav.overview` = "Overview"; replaces `nav.start`) | `layout-dashboard` | `g o` |
    | `/attention` | `bell` | `g a` |
    | `/devices` | `laptop` | `g d` |
    | `/device-groups` | `folder` | – |
    | `/enrollment-tokens` | `ticket` | – |
    | `/permission-profiles` | `shield-check` | – |
    | `/managed-files` | `file-text` | – |
    | `/managed-units` | `cog` | – |
    | `/package-holds` | `package` | – |
    | `/change-sets` | `diff` | – |
    | `/revocations` | `lock` | – |
    | `/settings/dms` | `timer` | – |
    | `/settings/login` | `log-in` | – |
    | `/software` | `package-search` | `g s` |
    | `/vulnerabilities` | `bug` | `g v` |
    | `/users` | `user` | – |
    | `/user-groups` | `users` | – |
    | `/api-tokens` | `key` | – |
    | `/settings/updates` | `refresh-cw` | – |
    | `/audit` | `scroll-text` | `g l` |
    | `/platform/organizations` | `building-2` | – |
    | `/platform/agent-releases` | `rocket` | – |
    | `/platform/ip-allowlist` (M7a, if present) | `globe-lock` | – |

    Chrome and component icons to vendor additionally: `menu`, `panel-left`, `search`, `sun`, `moon`, `monitor`,
    `x`, `chevron-left`, `chevron-right`, `chevron-down`, `ellipsis`, `triangle-alert`, `circle-check`, `circle-x`,
    `info`, `copy`, `keyboard`, `filter`, `external-link`, `inbox`, `circle-help`, `arrow-left`, `hard-drive`,
    `check`. The Lucide names above are those of the pinned release; if the release names a glyph differently, the
    coding agent uses the release's name, keeps the same glyph, and records both names in `vendored.json`
    (`"aliases": {"planned": "actual"}`).
16. **Command palette** (`server/web/src/components/CommandPalette.vue`, state in `lib/commands.ts`): opened by the
    command field, `Ctrl K` / `⌘ K` (also inside inputs, not inside an open dialog) and `/` (outside inputs). A
    `v-dialog` (640 px, `--pd-radius-lg`, `--pd-shadow-overlay`, `role="dialog"` + `aria-modal`) with an `<input
    role="combobox" aria-expanded aria-controls aria-activedescendant>` and a `<ul role="listbox">` of grouped
    `<li role="option">` entries (group headings `role="presentation"`): **Pages** (the visible navigation items,
    matched by label substring, case-insensitive; empty query lists them all), **Devices** (`GET
    /api/v1/devices?q=<text>&page_size=10&sort=hostname`, from 2 characters, 150 ms debounce, roles that may read
    devices), **Device groups** (`GET /api/v1/device-groups?q=…&page_size=5&sort=name`), **CVE** (text matching
    `^CVE-\d{4}-\d{4,}$` case-insensitive → "Open CVE-…" → `/vulnerabilities/<CVE>`), **Actions** (static,
    non-destructive: "Switch to the dark/light theme", "Use the system theme", "Switch to Deutsch/English", "Collapse/Expand the
    navigation", "Keyboard shortcuts", "Compact/Comfortable density"; and on a device page "Go to the danger zone of
    <hostname>" which scrolls to and focuses the danger-zone heading). Up/Down move, Enter opens, Esc closes; the
    active option is announced via `aria-activedescendant` and gets the focus ring. **MUST NOT:** any entry that
    performs or starts a destructive or security-relevant action (Lock, Destroy, Retire, reveal, rotate, suspend,
    revoke, approve, install).
17. **Global shortcuts** (`server/web/src/composables/useShortcuts.ts`, installed once in `App.vue`):

    | Keys | Action |
    | --- | --- |
    | `Ctrl K` / `⌘ K`, `/` | open the palette |
    | `Esc` | close palette / help dialog (dialogs and menus keep Vuetify's handling) |
    | `g o`, `g a`, `g d`, `g s`, `g v`, `g l` | go to Overview, Attention, Devices, Software, Vulnerabilities, Audit log (sequence, 1 s timeout; only items the role may see) |
    | `j` / `k` | row cursor down / up in the active DataList (§3.4 item 21) |
    | `Enter` / `o` | open the cursor row |
    | `[` | collapse / expand the navigation |
    | `?` | shortcut help dialog |
    | `Alt+1…9` | device tabs on a device page |

    Rules: single-key shortcuts (everything but `Ctrl/⌘ K` and `Esc`) are ignored while focus is in `input`,
    `textarea`, `select`, `[contenteditable]`, or while a `.v-overlay--active` exists; `Alt+digit` is ignored in
    inputs too. The modifier is `⌘` when `navigator.platform` starts with `Mac` (or `navigator.userAgentData.platform
    === 'macOS'`), else `Ctrl`; the hint texts use it. A viewer switch "Single-key shortcuts" in the help dialog
    (`localStorage` key `paddock.shortcuts.singleKey`, default on) turns all single-key and sequence shortcuts off
    (WCAG 2.1.4); `Ctrl/⌘ K` and `Esc` always work. **No shortcut ever triggers a destructive or security-relevant
    action**; every shortcut has a visible on-screen equivalent.
18. **Shortcut help dialog** (`components/ShortcutHelpDialog.vue`): `v-dialog` with `role="dialog"`, title
    `shortcuts.title` = "Keyboard shortcuts", a table of the shortcuts above (keys in `kbd`, descriptions translated),
    the single-key switch, Close button (default focus). Opened by `?`, the user menu and the palette.

### 3.4 Shared components

19. **`StatusChip.vue`** props `status: 'ok' | 'warn' | 'critical' | 'info' | 'neutral'`, `label: string`,
    `title?: string` (tooltip, absolute time or explanation). Renders `<span class="pd-chip pd-chip--<status>">` with
    a 6 px dot (`aria-hidden`) and the label; never colour alone; not a button. Mappings in
    `server/web/src/lib/status.ts` (pure functions, unit-tested):

    | Function | Input → status, label key |
    | --- | --- |
    | `deviceStatus(d: { state, contact })` | retired → neutral `devices.states.retired`; rejected → neutral; pending → info `devices.states.pending`; quarantined → critical; active+contact `presumed_lost` → critical `devices.contact.presumed_lost` = "Presumed lost"; `stale_critical` → critical "Silent (critical)"; `stale_warning` → warn "Silent"; `never` → neutral "Never contacted"; `ok` → ok "Online" |
    | `encryptionStatus(diskState)` | `compliant` → ok "Encrypted"; `escrow_pending` → warn "Being set up"; `unmanaged`, `tpm_missing`, `tpm_pin_missing` → warn with their existing labels; `not_encrypted` → critical; `''`/null → neutral "Not reported" |
    | `outcomeStatus(outcome)` | success → ok; failure → warn; denied → critical; unknown → neutral |
    | `attentionStatus(kind)` | presumed_lost, stale_critical, quarantined, revocation_expired → critical; stale_warning, disk_not_compliant, agent_outdated, login_apply_failed, sudo_apply_failed → warn; revocation_pending → info |
    | `commandStatus(status)` | pending, delivered → info; succeeded → ok; failed → critical; expired → warn; cancelled → neutral |
    | `revocationStatus(status)` | requested, approved, issued, delivered → info; confirmed → ok; failed → critical; expired → warn; rejected, cancelled → neutral (every value of `RevocationStatus`: requested, approved, issued, delivered, confirmed, failed, rejected, cancelled, expired) |
    | `tokenStatus(status)` | active → ok; expired → warn; revoked → neutral; exhausted → neutral (enrollment tokens) |
    | `rolloutStatus(status)` | running → info; halted → critical; completed → ok |
    | `userLockStatus(locked: boolean)` | locked → critical "Locked"; else ok "Active" |

    `SeverityChip.vue` is reworked to `<span class="pd-chip pd-chip--sev-<severity>">` with dot and label (tokens of
    §3.2 item 7); `ok`-style chips are replaced on every page listed in §3.9 item 33.
20. **`TimeCell.vue`** (`lib/time.ts`): `<time :datetime="iso" :title="absolute">` in mono, `white-space: nowrap`.
    Props `iso: string`, `mode: 'absolute' | 'relative'` (default `absolute`), `precision: 'minute' | 'second'`
    (default `minute`). Absolute format (browser time zone): `YYYY-MM-DD HH:MM` (`HH:MM:SS` with `precision:
    second`); when the instant is today, `HH:MM` / `HH:MM:SS` only, with the full value in the tooltip. Relative
    uses `Intl.RelativeTimeFormat(locale, { numeric: 'always', style: 'narrow' })` with the largest unit ≥ 1 (s, min,
    h, d, mo, y) and the absolute value in the tooltip. `formatDateTime` in `lib/format.ts` stays for prose (dialogs,
    alerts).
21. **`DataList.vue` extensions** (existing behaviour and testids unchanged: `list-search`, `list-filter-<key>`,
    `list-page-size`, `list-range`, `list-pagination`):
    - `ListColumn` gets `role?: 'primary' | 'status' | 'meta' | 'actions'` and `mono?: boolean`, `align?: 'start' |
      'end'`, `hideBelow?: 'sm' | 'md'` (column hidden on narrower viewports in table layout).
    - prop `layout?: 'table' | 'cards'` (default `table`; `cards` forced below 600 px): a card per row —
      line 1: the `primary` cell and the `status` cells; line 2: `meta` cells as "label: value" joined by " · "; the
      `actions` cell right-aligned. Cards keep the `item.<key>` slots.
    - prop `queryPrefix?: string`: all route-query keys of this list are prefixed (`pane.page`, `pane.q`, …) so two
      lists coexist on one page.
    - prop `emptyTitle?: string`, `emptyDescription?: string` (message keys) and slot `#empty-action`: the
      unfiltered empty state renders `EmptyState` (item 22) inside the table panel; the filtered empty state renders
      `list.noResults` plus a button `list.clearFilters` = "Clear filters" that resets `q` and every filter.
    - prop `expandable?: boolean` and slot `#expanded="{ item }"`: a per-row toggle button (`aria-expanded`,
      `aria-label` `list.toggleDetails` = "Show details of row {n}") that reveals the slot in a full-width row.
    - **Row cursor:** rows get `tabindex="-1"`; `j`/`k` (through `useShortcuts`, targeting the DataList that
      contains `document.activeElement`, else the first DataList in DOM order) move a cursor, focus the row element
      and add class `pd-row-cursor` (focus ring inset); `Enter`/`o` emit `row-click` when the page listens, else
      follow the first link in the row. Also usable with the mouse: a click on a row sets the cursor.
    - Filters below 600 px: the filter controls move into a `v-dialog` (full-screen sheet, `role="dialog"`, title
      `list.filters`) opened by a button `list.filtersCount` = "Filters ({count})" with the number of active filters;
      the search field stays visible. Nothing in the list is wider than the viewport (`overflow-x: hidden` on the
      cards, `table-layout: auto` with wrapping on tables ≥ 600 px).
    - Table styling per spec §4: header `pd-type-label` 500 on `#f8fafb`-equivalent token (`--pd-surface-2` light,
      transparent dark), `--pd-border-subtle` row dividers, hover `--pd-surface-3` at 50 %, primary column mono link
      without underline (underline on hover/focus), density padding `--pd-row-pad`.
22. **`EmptyState.vue`** props `icon: IconName`, `title: string`, `description: string`; slot `default` for the
    action button. Layout: 24 px muted icon, title `pd-type-section`, one sentence, the action when the role may
    act (the page decides and passes nothing otherwise).
23. **`ConfirmDialog.vue`** (ADR 0018 kept; e2e testids `confirm-dialog`, `confirm-typed`, `confirm-cancel`,
    `confirm-accept` unchanged): 480 px, `--pd-radius-lg`; title "verb + target"; consequence paragraph; new
    optional **reason** field (`options.reason?: { label: string; hint?: string; required: boolean; maxLength: 500 }`
    → `v-textarea` `data-testid="confirm-reason"`, `counter`, `maxlength`); typed confirmation with the visible label
    "Type `<name>` to confirm" (name in mono); confirm button disabled until the typed text matches exactly **and** a
    required reason is non-empty after trim; Enter in the typed field or the reason does **not** submit; Cancel on the
    left with default focus; Esc cancels. `useConfirm()` resolves `Promise<false | { reason: string }>`; existing
    callers that pass no reason keep working through an overload returning `Promise<boolean>` (implementation:
    `confirm(options)` returns `boolean` when `options.reason` is absent, `false | { reason }` otherwise; typed so
    callers cannot misread it).
24. **`DangerZone.vue`** (replaces `RevocationCard.vue`; testids `revocation`, `revocation-lock`,
    `revocation-destroy`, `revocation-requested`, `revocation-timeline`, `revocation-disabled`,
    `presumed-self-locked`, `revocation-incomplete`, `revocation-volumes`, `revocation-skipped`, `device-retire`
    kept): the **last** section of the device Overview tab, `--pd-danger-surface`, 1 px `--pd-danger-border`,
    `--pd-radius-md`, `id="danger-zone"`, heading `<h2 tabindex="-1">` `devices.danger.title` = "Danger zone —
    revocation" with `pd:triangle-alert`, caption `devices.danger.caption` = "Separately signed path. Every action
    opens a confirm dialog and is recorded in the audit log." Rows (each: title, own explanation, own button):
    - **Lock** — `devices.danger.lock.explanation` = the first sentence of today's `devices.revocation.hint` up to
      "...Encrypted volumes without an escrowed header are not erased by a Lock."; button `devices.danger.lock.label`
      = "Lock device…" (solid `--pd-danger-solid`). Flow: click → step-up (as today, `startStepUp('revocation-lock',
      deviceId, {})`) → on return `ConfirmDialog` with reason (required, label `devices.revocation.reason`, hint
      `devices.revocation.reasonHint`) and typed hostname → `requestRevocation`.
    - **Destroy** — explanation = "Destroy erases every encrypted volume and deletes the escrow, so the data cannot be
      recovered. Requires typing the hostname; a second organization administrator must approve it."; button
      `devices.danger.destroy.label` = "Request destroy…" (outlined `--pd-danger-outline-text`). Same flow with
      `revocation-destroy`.
    - **Retire** — explanation = today's `devices.actions.retire.confirm` consequence without the question; button
      `devices.actions.retire.label` + "…" (outlined). Flow: ConfirmDialog with typed hostname (no step-up, as
      today), `runDeviceAction('retire')`.
    - The revocation timeline table stays below the rows (unchanged content). The `revocable` / `canDelete` /
      `revocation_enabled` conditions of today's `RevocationCard` apply unchanged; when revocation is disabled, the
      Lock and Destroy rows show the existing `revocations.disabled` alert instead of buttons; Retire stays.
    - No shared Reason field on the card. `Approve`, `Reject`, `Release quarantine` are **not** danger-zone actions:
      they stay in the header band (item 29) as today's `device-<action>` buttons (`Reject` keeps its destructive
      confirm).
25. **Settings forms** (`UpdateSettings.vue`, `LoginSettings.vue`, `DMSSettings.vue`): fields constrained to content
    width (`max-width: 12rem` for times/numbers, `24rem` for text), helper text under its own field
    (`persistent-hint`), one `v-card` per fieldset with `pd-type-section` legend. No behaviour change.

### 3.5 Overview API and page

26. **`GET /api/v1/overview`** (operationId `getOverview`, tag `overview`, roles org_admin, org_operator,
    org_auditor; platform admins 403; schema §6.3). Use case `app.Overview.Get` in `server/internal/app/overview.go`,
    one `InOrg` transaction, sqlc queries in `server/internal/adapters/postgres/queries/overview.sql`:
    - `devices`: counts over `device` by state; `online|silent|silent_critical|presumed_lost|never_contacted` over
      **active** devices with the same predicates as `attention_condition` (`device_alert` open rows of kind
      `stale_warning`/`stale_critical`, `device_status.presumed_lost_at IS NOT NULL`, `last_contact_at IS NULL`); a
      device counts once, in the most severe bucket (presumed_lost > silent_critical > silent > never > online).
    - `encryption` over active devices by `health -> 'disk' ->> 'state'`: `encrypted` (= compliant), `not_encrypted`,
      `partial` (unmanaged, tpm_missing, tpm_pin_missing, escrow_pending), `not_reported` (NULL).
    - `vulnerabilities.by_highest_severity`: devices (active or quarantined) grouped by their highest finding severity
      (`critical > high > medium > low > unknown(NULL)`), plus `none` = those devices without findings;
      `vulnerabilities.top`: at most 5 CVEs ordered by severity rank then device count desc then cve, each with
      `cve`, `severity`, `devices` (distinct), `packages` (up to 3 distinct `software_name`, sorted).
    - `updates.security_overdue`: active devices with `last_contact_at IS NOT NULL` whose
      `login_state -> 'updates_security'` is absent, or has `params ->> 'result' <> 'ok'`, or `occurred_at < now() -
      interval '48 hours'`; `updates.reboot_required`: active devices with `health ->> 'reboot_required' = 'true'`;
      `updates.agent.current_version` = `paddock_current_agent_version()` (nullable), `on_current`, `outdated`
      (active devices with `agent_version` equal / different and not NULL), `unknown` (NULL agent_version);
      `updates.os_releases`: active devices grouped by `os_release ->> 'VERSION_ID'` (NULL → `"unknown"`), sorted by
      release desc.
    - `attention`: `conditions` = rows of `attention_condition`, `devices` = distinct `device_id`.
    - `generated_at`: server time, UTC.
    Isolation fixture `"GET /api/v1/overview": {kind: isoOwn, …}` (the globex world must yield different counts than
    acme; the fixture asserts alice's counts contain none of globex's devices by comparing `devices.total` with the
    acme device count). Not a list endpoint (no list contract).
27. **`GET /api/v1/attention/devices`** (operationId `listAttentionDevices`, tag `devices`, same roles as
    `listAttention`): the attention list grouped by device, list contract `x-paddock-list: { sort: [severity,
    hostname, since], default_sort: "-severity", search: [hostname], filters: [kind] }`. One item per device that has
    at least one open condition (all of the device's conditions are listed, most severe first, even when the `kind`
    filter matched only one). `severity` is the rank of the most severe condition (critical 2, warn 1, info 0 per
    §3.4 item 19 `attentionStatus`); `-severity` = most severe first, tie-breaker `hostname`, then `device_id`.
    `since` = the newest `since` of the device's conditions. Query `ListAttentionDevices` / `CountAttentionDevices`
    in `attention.sql` over `attention_condition` with `GROUP BY device_id, hostname` and `json_agg(json_build_object(
    'kind', kind, 'since', since, 'detail', detail) ORDER BY rank DESC, since DESC)`; joined with `device` and
    `device_status` for `state`, `last_contact_at`, `os_release`. `listspec_test.go` entry
    `"listAttentionDevices": {attentionDeviceList, "postgres/queries/attention.sql", "ListAttentionDevices", "device_id"}`;
    isolation fixture `isoList` and two `listIsolationQueries` entries (`q` = globex hostname prefix; `kind=presumed_lost`).
    `GET /api/v1/attention` stays unchanged (badge count, e2e helper, gates).
28. **Overview page** `server/web/src/views/Overview.vue` (route `/`, name `home`; `Home.vue` is deleted): the router
    guard sends every role to its start: org_admin and org_operator → `/` (Overview; the "attention list while it
    has entries" redirect of plan M5b decision 11 is removed — the overview shows attention grouped by device
    instead), org_auditor → `/audit`, platform_admin → `/platform/organizations` (`homeFor` updated; `e2e/checks.ts:
    expectAdminStartPage` asserts `/` and the heading "Overview"). Content (`data-testid` in brackets), in order:
    - h1 `overview.title` = "Overview", subtitle "{org} · {count, plural, one {# enrolled device} other {# enrolled
      devices}} · updated {time}" (`overview.subtitle`; `time` = `generated_at` as `HH:MM:SS`).
    - **KPI strip** (`overview-kpis`): one bordered panel, grid `repeat(auto-fit, minmax(160px, 1fr))`, cells are
      `RouterLink`s to the pre-filtered list: Online (`/devices?state=active` — the device list has no contact filter;
      see §12 open point 3), Silent (`/attention?kind=stale_warning&kind=stale_critical`), Presumed lost
      (`/attention?kind=presumed_lost`), Encrypted (`/devices?disk_state=compliant`, note "of {active} active"),
      Not encrypted (`/devices?disk_state=not_encrypted`), Critical/high CVEs (`/vulnerabilities?severity=critical&severity=high`,
      value = `by_highest_severity.critical + high` devices), Security updates overdue (`/attention`, no filter; value
      `updates.security_overdue`), Reboot required (value only, no link target exists → not a link). Each cell: label
      with status dot (`pd-type-label`), value (`pd-type-kpi`, tabular), note (`pd-type-caption`).
    - **Attention** panel (`overview-attention`): heading, caption "grouped by device, most severe first", link
      "Open list" (`g a` hint) to `/attention`; the first 5 items of `GET /api/v1/attention/devices?page_size=10`
      rendered as a compact table (Device mono link + OS caption, condition chips (max 3 + "+n"), last contact
      relative `TimeCell`, one action button by the most severe kind using today's `attention.action.<kind>` labels).
      Empty: `EmptyState` `overview.attention.empty.title` = "Nothing needs attention", description "Every device is
      online, encrypted and running the current agent, or has been retired."
    - **Vulnerabilities** panel (`overview-vulnerabilities`): heading, caption "devices by highest Ubuntu priority";
      a horizontal stacked **severity bar** (`role="img"` with `aria-label` listing every segment with its count;
      segments in order critical, high, medium, low, unknown, none with `--pd-sev-*-mark`; a legend with dot, label
      and count beneath, each a `RouterLink` to `/vulnerabilities?severity=<level>` except `none`); then the `top`
      list (CVE mono link to `/vulnerabilities/<cve>`, packages caption, `SeverityChip`, device count). Empty: "No
      findings yet" / "Findings appear after the first inventory sync of a device."
    - **Updates and agent rollout** panel (`overview-updates`): four rows "Security updates overdue (> 48 h)",
      "Reboot required", "Agent {version}" with "{on_current} / {active} on the current release" (or "No agent
      release published yet"), "Ubuntu releases" with "{release}: {count}" entries; values tabular mono.
    - **Recent audit activity** panel (`overview-audit`, only when `session.canReadAudit`): heading, link "Audit log"
      (`g l` hint) to `/audit`; the first 8 events of `GET /api/v1/audit-events?page_size=10&sort=-occurred_at` as a
      table: time (`TimeCell` absolute, seconds), actor chip (item 34), sentence, code (mono), outcome chip.
    - Footer line `overview.keyboardHint` = "Keyboard: {mod} K palette · j / k move · Enter open · g d devices.
      Destructive actions never have a shortcut; they always open the confirm dialog."
    - Loading: static placeholders (`--pd-surface-3` blocks, `aria-busy="true"` on the page). Error: inline
      `form-error` alert with `problemText`. `VulnerabilityTile.vue` is deleted and removed from `DeviceGroups.vue`;
      `e2e/inventory.spec.ts` asserts the severity legend links on `/` instead (`overview-vulnerabilities`:
      `getByRole('link', { name: /Critical/ })`, `/High/`, `/Unknown/`).

### 3.6 Device split view

29. **Layout** of `/devices/:id` and its tab routes (`DeviceDetail.vue` becomes the frame; `DeviceTabs.vue` grows):
    - Left **list pane** (`device-pane`, 280 px, `--pd-surface-2`, own scroll; hidden below 960 px, where a link
      `devices.back` = "Back to devices" appears above the header): heading "Filter devices" (visually hidden), a
      `DataList` with `layout="cards"`, `queryPrefix="pane"`, `defaultSort="hostname"`, searchable, filters
      `stateFilter` and `groupFilter`, page size 25, columns `hostname` (primary, mono) and `state` (status chip from
      `deviceStatus`); the row of the open device has `aria-current="true"` and class `pd-row-current`; clicking a row
      navigates to the same tab of that device; `j`/`k` move the cursor in the pane when the pane has focus; the
      pane footer shows `list-range` and prev/next pagination (the page-size selector is part of the DataList footer
      and stays). Links from the Devices list carry its `q`, `state`, `device_group_id`, `sort` and `page` into the
      pane query (`pane.q`, …).
    - Right **header band** (`device-header`): breadcrumb "Devices / {hostname}" (`nav` landmark `aria-label`
      `devices.breadcrumb`), h1 hostname (`pd-type-title-mono`), chips: `deviceStatus` (`device-state` testid moves
      onto this chip's label), `encryptionStatus`, "Logins suspended" (info, when `logins_suspended`), "Locked" (info,
      when the device's latest `lock` revocation request has status `issued`, `delivered` or `confirmed`; only loaded
      for `canDelete`); meta line (`pd-type-caption`, mono values): "Ubuntu {VERSION_ID} · agent {agent_version} ·
      last contact {TimeCell absolute} ({relative})" with "never" / "unknown" fallbacks muted; primary actions on the
      right: today's `device-approve` / `device-reject` / `device-release-quarantine` buttons for pending/quarantined
      devices, `install-now` ("Install updates…", from `UpdatesCard`) and `local-admin-rotate` ("Rotate admin
      password…") for active devices — both buttons keep their existing testids, dialogs and handlers; the cards
      they came from keep their content without the buttons. `Retire` moves to the danger zone.
    - **Tabs** (`role="tablist"`, URL-bound, `Alt+1…9`): Overview `/devices/:id` · Software `/devices/:id/software`
      (count from the list total, loaded lazily, muted) · Vulnerabilities `/devices/:id/vulnerabilities` (count in
      `critical.fg` when > 0) · Login & sudo `/devices/:id/access` · Configuration `/devices/:id/configuration` ·
      Commands `/devices/:id/commands` · Audit `/devices/:id/audit` (only `canReadAudit`). Routes `device-access`,
      `device-configuration`, `device-commands`, `device-audit` added to `router.ts`; the frame loads the device once
      and the tab views receive it through `provide/inject` (`deviceDetailKey`).
    - **Overview tab** (two columns ≥ 1100 px: left 7/12, right 5/12; one column below): left — "Health and
      compliance" panel (`device-health`: rows with status chip + label + note for contact, encryption, agent version
      vs current, security updates, reboot required, login configuration, sudo configuration — from `DeviceDetail`,
      `DeviceUpdates` and `login_status`), `DiskEncryptionCard` (volumes table; `local-admin-reveal` and
      `recovery-link` keep their testids), `UpdatesCard` content (`device-updates`, `device-holds`,
      `last-regular-run`); right — "Identity" panel (`device-identity`: state, device ID (mono, copy button with
      `aria-label` "Copy device ID"), hardware UUID, OS, agent version, enrolled, last contact, bundle version
      (muted "0 applied" with tooltip "No report since enrolment — the agent has not connected" when
      `applied_bundle_version` is null), sudo implementation, identity keys), "Device groups" panel (today's
      `device-groups` autocomplete + `save-device-groups`), `LocalAdminCard` content (`local-admin`,
      `local-admin-active`); then full width: "Software and vulnerabilities" summary panel (top 3 findings from
      `GET /devices/:id/vulnerabilities?page_size=10&sort=-severity` with link "All {n} findings"); then
      `DangerZone` (item 24), last.
    - **Login & sudo tab:** today's login assignment form (`login-users`, `login-groups`, `save-login-assignment`,
      `toggle-suspension`, alerts `agent-too-old`, `logins-suspended`), effective sudo table (`effective-sudo`,
      `sudo-root-equivalent`, `sudo-rs-lecture`), latest reports table (`device-reports`, `device-report-<area>`).
    - **Configuration tab:** conflicts alerts (`config-conflict`), effective files (`effective-files`) and units
      (`effective-units`).
    - **Commands tab:** today's command DataList (`command-list`) with status chips (`commandStatus`), `TimeCell`s.
    - **Audit tab:** `DataList` over `GET /api/v1/audit-events` with the new filter `target_id=<device id>` (item 31),
      same columns as the audit page (item 34) without the Device column.
    - **Software / Vulnerabilities tabs:** existing views, rendered inside the frame (they keep `device-software-list`,
      `device-vulnerability-list`, `tab-software`, `tab-vulnerabilities`).

### 3.7 Audit and attention

30. **`AuditEvent.device`** (schema §6.2): resolved at read time, never stored: for events whose `target.type ==
    "device"` the target id, otherwise `params.device_id` when present; `app.AuditLog.List` collects the ids of the
    page, resolves hostnames in one `OrgPool.InOrg` query `ListDeviceHostnames(ids uuid[]) → (id, hostname)` (RLS
    bounds it to the caller's organization), and sets `device: {id, hostname}`; `hostname` is `null` when the device
    is unknown to the organization. The stored event (`code`, `params`, `target`) is not modified or rewritten
    (CLAUDE.md "Audit").
31. **Filter `target_id`** on `GET /api/v1/audit-events` (uuid, exact match on `target->>'id'`; added to
    `x-paddock-list.filters`; audit migration `server/migrations/audit/00003_audit_target_index.sql`: `CREATE INDEX
    audit_event_org_target_idx ON audit_event (organization_id, (target->>'id'), occurred_at DESC);`). Isolation:
    `listIsolationQueries["/api/v1/audit-events"]` gets `{"target_id": {<globex device id>}}` — the fixture world
    exposes `w.globexDevice`, use it.
32. **Audit text:** `auditText` substitutes `hostname` from `ev.device.hostname` when `params.hostname` is absent and
    `ev.device` is set; the UUID fallback remains only when no hostname is known. The audit **page** (`Audit.vue`)
    columns: Time (`TimeCell` absolute, seconds, sortable `occurred_at`), Actor (chip of item 34 + display),
    Event (sentence; primary role), Device (mono link to `/devices/<id>` or "–"; `hideBelow: sm`), Code (mono, sortable
    `code`; `hideBelow: md`), Outcome (`StatusChip` from `outcomeStatus`, sortable `outcome`); `expandable` with
    the expanded row showing `event_id`, `correlation_id`, `source`, `actor.ip`, `actor.step_up`, `error_code` and
    `params` as a `<dl>` with mono values (never translated). Filters unchanged plus nothing new in the UI for
    `target_id` (used by the device tab only).
33. **Attention page** (`Attention.vue`) uses `GET /api/v1/attention/devices`: columns Device (primary: hostname mono
    link to `/devices/<id>`; caption "Ubuntu {VERSION_ID}"), Conditions (status chips from `attentionStatus` with
    labels `attention.kinds.<kind>`, most severe first, at most 3 visible, "+{n}" chip with a tooltip listing the
    rest; `detail` as the chip's tooltip when non-empty), Last contact (`TimeCell` relative; "never" muted), Action
    (one button: `attention.action.<most severe kind>`; `aria-label` `attention.open`); sortable `severity`,
    `hostname`, `since`; filter `kind` (`list-filter-kind` kept); search; default sort `-severity`; summary text
    `attention.summary` = "Devices that need an administrator, grouped by device with their open conditions. Open
    the device to retire, lock or release it." The "Detail" column is removed. Empty state: as the overview panel.
    `e2e/updates.spec.ts` (`nav-attention`, kinds, hostnames) is adapted to the grouped rows: the hostname cell is
    the primary link; the condition is a chip text inside the row.
34. **Actor chip:** `ActorChip.vue` props `actor: AuditActor`: `StatusChip` with status by type (admin → info
    "Administrator"; platform_admin → info "Platform administrator"; api_token → info "API token"; system → neutral
    "System"; device → neutral "Device"; anonymous → neutral "Anonymous"; labels = existing `audit.actorTypes.*`)
    followed by `actor.display` in mono (empty for system).

### 3.8 Mobile (390 px) and accessibility

35. Every page renders at 390 px without page-level horizontal scroll (`document.documentElement.scrollWidth <=
    window.innerWidth`): lists in cards layout, filters behind the sheet, the device split view without the pane,
    panels stacked, the KPI strip wrapping (two per row), the audit expanded row wrapping values with
    `overflow-wrap: anywhere`. Hostnames truncate with a tooltip; everything else wraps.
36. WCAG 2.1 AA in both themes: the contrast ratios of the spec; focus ring `--pd-focus-ring` on every
    `:focus-visible`, never removed; `aria-current`, `role` and labels as specified; the `inert` handling of
    `App.vue` while a dialog is open stays (palette and help dialog are `v-dialog`s and are covered). The axe gate
    (`expectAccessible`) runs in both themes (§8).

### 3.9 Status chips and empty states on every page

37. Status chips replace plain status text in: Devices list (`state` → `deviceStatus`, `disk_state` →
    `encryptionStatus`, timestamps → `TimeCell` relative), Device groups member list, Attention, Audit, Enrollment
    tokens (`tokenStatus`), API tokens (`tokenStatus`), Revocations (`revocationStatus`), Agent releases
    (`rolloutStatus`, `AgentReleaseStatus`: draft → neutral, published → ok), Users (lock state via `userLockStatus`;
    `user-lock-state` testid moves onto the chip label), Commands (`commandStatus`), Vulnerabilities and device
    vulnerabilities (`SeverityChip`), Change sets (`source` as a neutral chip: `session` / `api_token` labels from
    the existing `changeSets.sources.*` keys; a change set has no status field). The CSS classes `.state-*`, `.outcome-*`, `.badge-*`, `.presumed-lost` in
    `styles.css` are removed once no template uses them.
38. Empty states (keys `<area>.empty.title` / `.description`; action = the page's existing create button when the
    role may act, else nothing):

    | Page | Title | Description | Action |
    | --- | --- | --- | --- |
    | Device groups | No device groups yet | Groups scope configuration, package holds and login rules to a set of devices. | Create device group |
    | Devices | No devices yet | Devices appear here after they enroll with an enrollment token. | Create enrollment token (link to `/enrollment-tokens`) |
    | Enrollment tokens | No enrollment tokens yet | A token lets a device enroll; its configuration is shown once when it is created. | Create token |
    | Permission profiles | No permission profiles yet | Profiles grant sudo rights to users or groups on their devices. | Create profile |
    | Managed files | No managed files yet | Managed files are written to every device of their scope and kept unchanged. | Create managed file |
    | Managed units | No managed units yet | Managed units keep systemd services enabled or disabled on their scope. | Create managed unit |
    | Package holds | No package holds yet | A hold keeps a package at its version or out of updates on its scope. | Create hold |
    | Change sets | No change sets yet | Change sets are recorded when `paddockctl` or the API applies a configuration. | – |
    | Revocations | No revocations | Lock and Destroy requests of this organization appear here with their progress. | – |
    | Software | No software inventoried yet | The inventory fills after the first sync of a device with fleetd. | – |
    | Vulnerabilities | No findings yet | Findings appear after the first inventory sync of a device. | – |
    | Users | No users yet | Users are synchronized from the directory or created here. | Create user |
    | Groups | No groups yet | Groups bundle users for login assignment and permission profiles. | Create group |
    | API tokens | No API tokens yet | API tokens let CI and `paddockctl` use the admin API with a role and an expiry. | Create API token |
    | Audit log | No events in this range | Widen the date range or clear the filters. | Clear filters |
    | Organizations | No organizations yet | Create the first organization to onboard its administrators. | Create organization |
    | Agent releases | No agent releases yet | Upload a signed release to start a staged rollout. | Create release |
    | Commands (device tab) | No commands yet | Commands appear when an administrator rotates the password, installs packages or locks the device. | – |
    | Device software / vulnerabilities | No software reported yet / No findings for this device | after the first inventory sync / The device has no CVE matches. | – |
    | Attention / Overview attention | Nothing needs attention | as in item 28 | – |

    "Never", "–", "Not reported yet", "none yet" values are rendered muted (`pd-muted`) with a tooltip explaining the
    cause where one exists (`devices.noReportYet` = "No report since enrolment — the agent has not connected").

### 3.10 Internationalization

39. Every new string is a key in `server/web/src/locales/en.json` and `de.json` (ICU; `check-messages.ts` fails on
    gaps). New key groups: `app.themes.*`, `app.themeToggle.*`, `app.themeFailed`, `app.densities.*`,
    `app.commandField`, `app.breadcrumb`, `nav.overview`, `nav.attentionPill`, `nav.shortcut` ("Shortcut: {keys}"),
    `palette.*` (placeholder, groups "Pages", "Devices", "Device groups", "CVE", "Actions", "No matches", action
    labels), `shortcuts.*` (title, every row, the switch), `status.*` (chip labels that are not already keys:
    `online`, `silent`, `silentCritical`, `presumedLost`, `neverContacted`, `encrypted`, `partial`, `notReported`,
    `locked`, `loginsSuspended`), `time.*` (relative units "never", "now"), `list.filters`, `list.filtersCount`,
    `list.clearFilters`, `list.toggleDetails`, `overview.*`, `devices.contact.*`, `devices.danger.*`,
    `devices.tabs.*` (`overview`, `access` = "Login & sudo", `configuration`, `commands`, `audit`),
    `devices.health.*`, `devices.copyId`, `devices.noReportYet`, `attention.*` (new summary, `more` = "+{count}"),
    `audit.device`, `audit.details.*`, `<area>.empty.*`. German follows `docs/compliance/glossary-de.md`; the glossary
    gets the rows: Overview (page) → Übersicht; Attention pill → "{n} brauchen Aufmerksamkeit"; Command palette →
    Befehlspalette; Danger zone → Gefahrenbereich; Theme → Erscheinungsbild (System / Hell / Dunkel); Density →
    Dichte (Kompakt / Komfortabel); Keyboard shortcut → Tastenkürzel; Online → Online; Silent → Ohne Kontakt;
    Never contacted → Nie verbunden; Encrypted / Not encrypted / Partial → Verschlüsselt / Nicht verschlüsselt /
    Teilweise; Not reported → Nicht gemeldet; Reboot required → Neustart erforderlich; Security updates overdue →
    Sicherheitsupdates überfällig.

## 4. Non-goals

- No toast system: success and error messages stay inline alerts and the existing snackbars (styled by tokens).
- No bulk actions or row selection (`x` shortcut is not implemented).
- No change to the revocation path on the agent (`agent/internal/revoke/`, `agent/cmd/paddock-revoke/`), to the
  step-up protocol, to any privileged action, to the audit event schema in the audit database, or to audit codes.
- No new npm package, Go module or container image. No Google Fonts, no icon font, no `@mdi/js`.
- No change to `docs/architecture.md`, to ADRs 0001–0022, to `api/openapi/` beyond §6, to `.github/`.
- No change to the acceptance gates' semantics (they stay green; new gates are added, none weakened).
- No per-organization theming, no custom logos, no user avatars.
- No rework of forms other than the width constraints of §3.4 item 25.
- The `RevocationRequests.vue` page, `Organizations.vue`, agent release pages: chips and empty states only.

## 5. Affected files

| Path | Action | Purpose |
| --- | --- | --- |
| `server/migrations/paddock/00036_account_theme.sql` | new | theme column on both account tables |
| `server/migrations/audit/00003_audit_target_index.sql` | new | index for the `target_id` filter |
| `api/openapi/admin.yaml` | change | §6: Me.theme, MeUpdate, Device.contact, AuditEvent.device, audit `target_id`, `/overview`, `/attention/devices` |
| `server/internal/transport/http/admin/adminapi/adminapi.gen.go`, `server/web/src/api/schema.d.ts`, `server/internal/adapters/postgres/pgstore/*`, `server/internal/adapters/auditpg/auditstore/*` | regenerate | `make gen` |
| `server/internal/adapters/postgres/queries/accounts.sql` (settings update), `attention.sql` (grouped), `device.sql` (`contact`, `ListDeviceHostnames`), `overview.sql` (new) | change / new | queries |
| `server/internal/adapters/auditpg/queries/audit.sql` | change | `target_id` filter |
| `server/internal/app/accounts.go`, `auditlog.go`, `attention.go`, `devices.go`, `overview.go` (new) | change / new | use cases |
| `server/internal/transport/http/admin/handlers.go`, `handlers_attention.go`, `handlers_devices.go`, `handlers_overview.go` (new), `listspec_test.go`, `static.go`, `static_test.go`, `server.go` (route wiring) | change / new | handlers, list specs, MIME |
| `test/acceptance/isolation_fixtures.go`, `test/acceptance/overview_test.go` (new), `test/acceptance/attention_devices_test.go` (new) | change / new | gates |
| `server/web/package.json` | change | scripts `gen:icons`, `lint` (adds `check-vendored.ts`, `gen:icons --check`) |
| `server/web/index.html` | change | `color-scheme` meta, title unchanged |
| `server/web/src/main.ts`, `plugins/vuetify.ts`, `plugins/theme.ts` (new), `lib/theme.ts` (new), `styles.css`, `styles/tokens.css`, `styles/fonts.css`, `styles/typography.css` (new) | change / new | themes, tokens, fonts |
| `server/web/src/assets/fonts/**`, `server/web/src/assets/icons/lucide/**`, `server/web/src/assets/vendored.json` | new | vendored assets and manifest |
| `server/web/scripts/gen-icons.ts`, `scripts/check-vendored.ts`, `src/lib/icons.gen.ts` | new | icon generation and gate |
| `server/web/src/components/PdIcon.ts`, `StatusChip.vue`, `ActorChip.vue`, `TimeCell.vue`, `EmptyState.vue`, `DangerZone.vue`, `CommandPalette.vue`, `ShortcutHelpDialog.vue`, `SeverityBar.vue`, `KpiStrip.vue`, `DeviceHeader.vue`, `DevicePane.vue` | new | components |
| `server/web/src/components/ConfirmDialog.vue`, `DataList.vue`, `DeviceTabs.vue`, `SeverityChip.vue`, `UpdatesCard.vue`, `LocalAdminCard.vue`, `DiskEncryptionCard.vue` | change | §3.4, §3.6 |
| `server/web/src/components/RevocationCard.vue`, `VulnerabilityTile.vue`, `src/views/Home.vue` | delete | replaced |
| `server/web/src/composables/useConfirm.ts`, `useShortcuts.ts` (new) | change / new | reason option; shortcuts |
| `server/web/src/lib/navigation.ts`, `commands.ts` (new), `status.ts` (new), `time.ts` (new), `overview.ts` (new), `audit.ts`, `updates.ts`, `devices.ts`, `format.ts`, `deviceDetailPage.ts`, `listQuery.ts` | change / new | data and logic |
| `server/web/src/stores/session.ts`, `router.ts`, `App.vue` | change | theme, routes, shell |
| `server/web/src/views/Overview.vue`, `DeviceAccess.vue`, `DeviceConfiguration.vue`, `DeviceCommands.vue`, `DeviceAudit.vue` (new); `DeviceDetail.vue`, `Attention.vue`, `Audit.vue`, `Devices.vue`, `DeviceGroups.vue`, every other view of §3.9 | new / change | screens |
| `server/web/src/locales/en.json`, `de.json`; `docs/compliance/glossary-de.md` | change | strings |
| `server/web/src/__tests__/*` (new tests of §8) | new / change | Vitest |
| `server/web/e2e/checks.ts`, `screenshots.spec.ts`, `portal.spec.ts`, `inventory.spec.ts`, `updates.spec.ts`, `revocation.spec.ts`, `devices.spec.ts`, `german.spec.ts`; new `theme.spec.ts`, `keyboard.spec.ts`, `mobile.spec.ts`, `accessibility.spec.ts` | change / new | e2e |
| `docs/compliance/third-party.md` | change | vendored fonts and icons section |
| `docs/adr/0023-portal-design-system.md` | new | §6.8 verbatim |
| `docs/plans/M6b-release-readiness.md` | change | amendment of §6.9 appended |
| `README.md`, `docs/assets/screenshots/*-{light,dark}.png` | change | overview, devices, device, audit in both themes |
| `CHANGELOG.md` | change | "Portal redesign" entries under the unreleased section |

**MUST NOT touch:** `agent/**`, `docs/architecture.md`, `docs/adr/0001-0022`, `.github/**`, `deploy/**`,
`server/internal/domain/audit/codes.go`, `server/internal/app/action.go`, `server/migrations/paddock/00001–00035`,
`server/migrations/audit/00001–00002`, `test/acceptance/*` other than the files named above, `test/system/**`,
`docs/plans/*` other than M6b.

## 6. Interfaces and data model

### 6.1 Me

```yaml
Me:
  required: [id, username, display_name, role, organization, locale, theme, revocation_enabled]
  properties:
    theme: { type: string, enum: [system, light, dark], description: "Portal theme preference; system follows prefers-color-scheme." }
MeUpdate:
  type: object
  minProperties: 1
  additionalProperties: false
  properties:
    locale: { type: string, enum: [en, de] }
    theme:  { type: string, enum: [system, light, dark] }
```
`PATCH /api/v1/me`: 200 `Me`; 400 `invalid_request` (empty body, unknown value); 401; 403 (API token).

### 6.2 Device and audit

```yaml
DeviceContact:
  type: string
  enum: [never, ok, stale_warning, stale_critical, presumed_lost]
  description: "Derived like the attention conditions stale_warning, stale_critical and presumed_lost; never = no check-in yet; ok otherwise. Devices that are not active report ok or never."
Device:
  required: [..., contact]
  properties:
    contact: { $ref: "#/components/schemas/DeviceContact" }

AuditDeviceRef:
  type: object
  required: [id, hostname]
  properties:
    id: { type: string, format: uuid }
    hostname: { type: string, nullable: true, description: "Current hostname, resolved at read time; null when the organization has no such device." }
AuditEvent:
  required: [..., device]
  properties:
    device:
      allOf: [{ $ref: "#/components/schemas/AuditDeviceRef" }]
      nullable: true
      description: "The device the event concerns (target of type device, else params.device_id); read-time enrichment, the stored event is unchanged."

# GET /api/v1/audit-events: new query parameter
- name: target_id
  in: query
  description: Exact target id (for example a device id).
  schema: { type: string, format: uuid }
# x-paddock-list.filters: [from, to, code, outcome, actor_type, target_id]
```

### 6.3 Overview

```yaml
/api/v1/overview:
  get:
    operationId: getOverview
    tags: [overview]
    description: "Roles: org_admin, org_operator, org_auditor. The numbers of the overview page, computed in one transaction; never cached."
    responses:
      "200": { content: { application/json: { schema: { $ref: "#/components/schemas/Overview" } } } }
      "401": { $ref: "#/components/responses/Problem" }
      "403": { $ref: "#/components/responses/Problem" }
Overview:
  type: object
  required: [generated_at, devices, encryption, vulnerabilities, updates, attention]
  properties:
    generated_at: { type: string, format: date-time }
    devices:
      type: object
      required: [total, active, pending, quarantined, retired, rejected, online, silent, silent_critical, presumed_lost, never_contacted]
      properties: { total: {type: integer, description: "pending + active + quarantined"}, active: {type: integer}, pending: {type: integer}, quarantined: {type: integer}, retired: {type: integer}, rejected: {type: integer}, online: {type: integer}, silent: {type: integer}, silent_critical: {type: integer}, presumed_lost: {type: integer}, never_contacted: {type: integer} }
    encryption:
      type: object
      required: [encrypted, not_encrypted, partial, not_reported]
      properties: { encrypted: {type: integer}, not_encrypted: {type: integer}, partial: {type: integer}, not_reported: {type: integer} }
    vulnerabilities:
      type: object
      required: [by_highest_severity, top]
      properties:
        by_highest_severity:
          type: object
          required: [critical, high, medium, low, unknown, none]
          properties: { critical: {type: integer}, high: {type: integer}, medium: {type: integer}, low: {type: integer}, unknown: {type: integer}, none: {type: integer} }
        top:
          type: array
          maxItems: 5
          items:
            type: object
            required: [cve, severity, devices, packages]
            properties:
              cve: { type: string }
              severity: { $ref: "#/components/schemas/Severity" }
              devices: { type: integer }
              packages: { type: array, maxItems: 3, items: { type: string } }
    updates:
      type: object
      required: [security_overdue, reboot_required, agent, os_releases]
      properties:
        security_overdue: { type: integer, description: "Active devices without a successful security run in the last 48 hours." }
        reboot_required: { type: integer }
        agent:
          type: object
          required: [current_version, on_current, outdated, unknown]
          properties: { current_version: {type: string, nullable: true}, on_current: {type: integer}, outdated: {type: integer}, unknown: {type: integer} }
        os_releases:
          type: array
          items: { type: object, required: [release, devices], properties: { release: {type: string}, devices: {type: integer} } }
    attention:
      type: object
      required: [conditions, devices]
      properties: { conditions: {type: integer}, devices: {type: integer} }
```

### 6.4 Attention grouped by device

```yaml
/api/v1/attention/devices:
  get:
    operationId: listAttentionDevices
    tags: [devices]
    description: "Roles: org_admin, org_operator, org_auditor. The attention list grouped by device: one item per device with an open condition, its conditions most severe first. A kind filter selects devices with at least one matching condition; all conditions of the device are listed."
    x-paddock-list: { sort: [severity, hostname, since], default_sort: "-severity", search: [hostname], filters: [kind] }
    parameters: [Page, PageSize, AttentionDeviceSort, Search, kind (repeatable, AttentionKind)]
    responses: { "200": AttentionDevicePage, "400": Problem, "401": Problem, "403": Problem }
AttentionDeviceSort: { enum: [severity, -severity, hostname, -hostname, since, -since] }
AttentionCondition:
  type: object
  required: [kind, since, detail]
  properties: { kind: { $ref: AttentionKind }, since: { type: string, format: date-time }, detail: { type: string } }
AttentionDevice:
  type: object
  required: [device_id, hostname, state, os_release, last_contact_at, severity, since, conditions]
  properties:
    device_id: { type: string, format: uuid }
    hostname: { type: string }
    state: { $ref: DeviceState }
    os_release: { type: object, additionalProperties: { type: string } }
    last_contact_at: { type: string, format: date-time, nullable: true }
    severity: { type: string, enum: [info, warn, critical], description: "Of the most severe condition." }
    since: { type: string, format: date-time, description: "Newest condition." }
    conditions: { type: array, minItems: 1, items: { $ref: AttentionCondition } }
AttentionDevicePage: { items: [AttentionDevice], page, page_size, total, total_capped, sort }
```

### 6.5 Go signatures

```go
// server/internal/app/accounts.go
type AccountSettings struct{ Locale, Theme *string }
var SupportedThemes = []string{"system", "light", "dark"}
func (a *Accounts) UpdateSettings(ctx context.Context, s AccountSettings) (Me, error)   // replaces UpdateLocale

// server/internal/app/overview.go
type Overview struct { GeneratedAt time.Time; Devices OverviewDevices; Encryption OverviewEncryption; Vulnerabilities OverviewVulnerabilities; Updates OverviewUpdates; Attention OverviewAttention }
func NewOverview(org *db.OrgPool) *Overview
func (o *Overview) Get(ctx context.Context) (OverviewResult, error)                      // RequireOrg(ctx, RolesRead)
const SecurityOverdueWindow = 48 * time.Hour

// server/internal/app/attention.go
type AttentionDeviceQuery struct { Page ListPage; Kinds []string }
func (a *Attention) ListDevices(ctx context.Context, q AttentionDeviceQuery) (Listed[pgstore.ListAttentionDevicesRow], error)

// server/internal/app/auditlog.go
type AuditQuery struct { From, To *time.Time; Codes, Outcomes, ActorTypes []string; TargetID *uuid.UUID; Page ListPage }
type AuditDevice struct { ID uuid.UUID; Hostname *string }
type AuditListed struct { Items []auditstore.AuditEvent; Devices map[uuid.UUID]AuditDevice; Count int }   // Devices keyed by event_id
func (l *AuditLog) List(ctx context.Context, f AuditQuery) (AuditListed, error)
```

### 6.6 Portal signatures

```ts
// src/lib/status.ts
export type Status = 'ok' | 'warn' | 'critical' | 'info' | 'neutral'
export interface StatusView { status: Status; label: string }          // label = message key
export function deviceStatus(d: { state: DeviceState; contact: DeviceContact }): StatusView
export function encryptionStatus(state: DiskState | '' | null | undefined): StatusView
export function outcomeStatus(o: AuditOutcome): StatusView
export function attentionStatus(kind: AttentionKind): StatusView
export function attentionRank(kind: AttentionKind): 0 | 1 | 2
export function commandStatus(s: DeviceCommandStatus): StatusView
export function revocationStatus(s: RevocationStatus): StatusView
export function tokenStatus(s: 'active' | 'expired' | 'revoked' | 'exhausted'): StatusView
export function rolloutStatus(s: AgentRolloutStatus): StatusView

// src/lib/time.ts
export function formatAbsolute(iso: string, now: Date, precision: 'minute' | 'second'): string
export function formatRelative(iso: string, now: Date, locale: string): string

// src/composables/useConfirm.ts
export interface ConfirmReason { label: string; hint?: string; required: boolean; maxLength: 500 }
export interface ConfirmOptions { title: string; message: string; confirmLabel: string; destructive?: boolean; requireTypedText?: string; reason?: ConfirmReason }
export function useConfirm(): {
  (options: ConfirmOptions & { reason: ConfirmReason }): Promise<false | { reason: string }>
  (options: Omit<ConfirmOptions, 'reason'>): Promise<boolean>
}

// src/composables/useShortcuts.ts
export interface ShortcutHandlers { openPalette(): void; openHelp(): void; toggleNav(): void; go(to: string): void; list(action: 'down' | 'up' | 'open'): void; tab(index: number): void }
export function useShortcuts(handlers: ShortcutHandlers): void    // installs keydown on window; disposes on unmount
export function singleKeyShortcutsEnabled(): boolean               // localStorage paddock.shortcuts.singleKey
export function modifierLabel(): 'Ctrl' | '⌘'

// src/lib/commands.ts
export type PaletteEntry = { id: string; group: 'pages' | 'devices' | 'groups' | 'cve' | 'actions'; label: string; hint?: string; run: () => void }
export async function paletteEntries(query: string, ctx: PaletteContext): Promise<PaletteEntry[]>

// src/lib/navigation.ts
export interface NavigationItem { to: string; label: string; icon: IconName; shortcut?: string; visible: (a: NavigationAccess) => boolean; testid?: string }
```

### 6.7 localStorage keys (viewer convenience only, every access in try/catch)

| Key | Values | Meaning |
| --- | --- | --- |
| `paddock.theme` | `system|light|dark` | early-paint cache of the account preference; overwritten from `GET /me` |
| `paddock.navigation.collapsed` | `true|false` | drawer collapsed to the rail (≥ 600 px) |
| `paddock.density` | `compact|comfortable` | density |
| `paddock.shortcuts.singleKey` | `true|false` | single-key and sequence shortcuts enabled |

### 6.8 ADR 0023 (add verbatim as `docs/adr/0023-portal-design-system.md`)

```markdown
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
```

### 6.9 Amendment to `docs/plans/M6b-release-readiness.md` (append verbatim)

```markdown
## Amendment 2026-10-09 (architect, plan M7c)
- Decision 6: the portal has a light and a dark theme (ADR 0023). README screenshots are written in both themes by
  `e2e/screenshots.spec.ts` with `PADDOCK_E2E_SCREENSHOTS=1`: `docs/assets/screenshots/<name>-light.png` and
  `<name>-dark.png` for `overview`, `devices`, `device`, `audit` at 1440×900. The README shows the light variant with a
  `<picture>` whose `<source media="(prefers-color-scheme: dark)">` points at the dark variant. The amendment of
  2026-10-08 ("light only") is superseded.
```

## 7. Implementation steps

Each step ends in a lint-clean, test-green, committable state; one commit per step (`feat(portal): …` /
`feat(api): …`). Run `make lint test` before each commit; steps 5 and 6 also `make acceptance`; from step 3 on
`make e2e` for the affected specs.

1. **Theme preference on the account.** Do: migration `00036`; OpenAPI §6.1; `make gen`; `UpdateSettings`;
   handler `UpdateMe` passes both fields; `GetMe`/`tokenMe` set `Theme`; sqlc queries; unit tests in
   `server/internal/app` (unsupported theme → 400; empty patch → 400; locale-only patch keeps theme); handler test.
   Result: `PATCH /api/v1/me {"theme":"dark"}` answers 200 with `theme: dark`; `GET /api/v1/me` carries it.
   Check: `cd server && go test ./internal/app/... ./internal/transport/...`; `make acceptance T=TestIsolation`.
2. **Tokens, themes, fonts, icons.** Do: vendor fonts and icons with `vendored.json`; `check-vendored.ts`,
   `gen-icons.ts`, `icons.gen.ts`, `PdIcon.ts`; `plugins/theme.ts`, `lib/theme.ts`, `styles/{tokens,fonts,typography}.css`;
   `styles.css` rewritten on tokens; `plugins/vuetify.ts` with both themes, defaults and the `pd` icon set;
   `main.ts` early theme; session store `setTheme`; MIME registration in `static.go`; `third-party.md` section;
   `package.json` scripts; ADR 0023 file; M6b amendment. Result: the portal renders in Plex/JetBrains Mono, follows
   `prefers-color-scheme`, every page still works. Check: `npm run lint` (incl. new checks), `npm test`
   (tokens test, hex-colour test, icon allow-list test, vendored manifest test with a temp file), `go test
   ./internal/transport/http/admin/ -run TestStatic`.
3. **Shell.** Do: `App.vue` app bar, user menu (theme, density, shortcuts), drawer with icons/rail/roving tabindex,
   `navigation.ts` icons and shortcuts, attention pill, `CommandPalette.vue`, `lib/commands.ts`, `useShortcuts.ts`,
   `ShortcutHelpDialog.vue`, density provider. Result: `Ctrl K` opens the palette, `g d` opens Devices, `[` collapses
   the drawer, the theme toggle persists on the account. Check: Vitest (`navigation.test.ts` extended: every item has
   an icon that exists in `icons.gen.ts`; `commands.test.ts`; `shortcuts.test.ts`: ignored in inputs and while a
   dialog is open, sequence timeout, switch off); e2e `theme.spec.ts`, `keyboard.spec.ts`, `portal.spec.ts`,
   `german.spec.ts`.
4. **Shared components.** Do: `StatusChip`, `ActorChip`, `TimeCell`, `EmptyState`, `SeverityChip` rework,
   `lib/status.ts`, `lib/time.ts`, `ConfirmDialog` reason + `useConfirm` overload, `DataList` extensions (roles,
   layouts, prefix, empty, expandable, cursor, filter sheet), `DangerZone.vue` (not yet mounted). Result: components
   exist with tests; no page changed yet except where `ConfirmDialog` is shared. Check: Vitest per component
   (`statusChip`, `status`, `time`, `timeCell`, `emptyState`, `confirmDialog` (reason required disables confirm; Enter
   does not submit; focus on Cancel), `dataList` (cards layout renders primary/status/meta; prefix query keys; cursor
   moves with j/k and skips when focus is in the search input; clear filters resets the query; expanded row toggles
   `aria-expanded`), `dangerZone` (rows, labels end with "…", no reason field on the card, Lock disabled with
   `revocation_enabled=false`)).
5. **Overview and attention API, audit enrichment.** Do: OpenAPI §6.2–§6.4; `make gen`; `overview.sql`, grouped
   attention queries, `ListDeviceHostnames`, device `contact`, audit `target_id` + index; use cases and handlers;
   `listspec_test.go` entry; isolation fixtures and list queries; acceptance gates `overview_test.go` (seed: acme has
   devices in known states via the existing devicesim helpers; assert `devices.total`, `by_highest_severity` and
   `attention.devices` match independent API counts; a globex principal sees globex numbers only) and
   `attention_devices_test.go` (a device with two conditions appears once with both, most severe first; `kind`
   filter keeps all conditions; sorts honoured). Result: endpoints documented, gates green. Check: `make acceptance
   T='TestListContract|TestIsolation|TestOverview|TestAttentionDevices|TestAuditExactlyOnce'`; `go test ./...` in
   `server`.
6. **Overview page.** Do: `Overview.vue`, `KpiStrip.vue`, `SeverityBar.vue`, `lib/overview.ts`, router `home`
   handling and `homeFor`, delete `Home.vue` and `VulnerabilityTile.vue`, `DeviceGroups.vue` without the tile,
   `e2e/checks.ts: expectAdminStartPage` (asserts `/` + heading), `e2e/inventory.spec.ts` adapted. Result: alice
   lands on the overview with live numbers. Check: Vitest `overview.test.ts` (KPI links, severity bar aria-label,
   empty states, audit panel hidden for operators); e2e `portal.spec.ts`, `inventory.spec.ts`, `german.spec.ts`
   (German headings of the overview).
7. **Device split view.** Do: `DeviceDetail.vue` frame, `DevicePane.vue`, `DeviceHeader.vue`, `DeviceTabs.vue`,
   new tab views, `DangerZone` mounted, `RevocationCard.vue` deleted, `UpdatesCard`/`LocalAdminCard` buttons moved to
   the header, routes, Devices list links carrying the pane query, `deviceDetailPage.ts` (retire via the danger
   zone; reason-less confirms unchanged). Result: every existing device e2e passes with the adapted locators;
   `revocation.spec.ts` fills `confirm-reason` and `confirm-typed` in the dialog. Check: Vitest `deviceControl.test.ts`,
   `revocationCard.test.ts` → `dangerZone.test.ts`, `deviceHeader.test.ts`; e2e `devices.spec.ts`, `revocation.spec.ts`,
   `localAdmin.spec.ts`, `updates.spec.ts`, `identity.spec.ts`, `inventory.spec.ts`.
8. **Audit and attention pages.** Do: `Audit.vue` columns, expansion, `ActorChip`, `auditText` device fallback;
   `Attention.vue` on the grouped endpoint; `lib/audit.ts` (`target_id`), `lib/updates.ts` (`listAttentionDevices`);
   `DeviceAudit.vue` tab. Result: no UUID in an audit sentence of a device event whose device exists; attention shows
   one row per device. Check: Vitest `audit.test.ts` (device fallback, no rewrite of params), `attention.test.ts`;
   e2e `portal.spec.ts` (audit assertions unchanged), `updates.spec.ts` (grouped rows), `german.spec.ts`.
9. **Chips, empty states, settings widths, mobile, accessibility in both themes.** Do: §3.9 on every page listed;
   §3.4 item 25; §3.8; `e2e/mobile.spec.ts` (390×844: `/`, `/devices`, `/devices/<id>`, `/attention`, `/audit`,
   `/vulnerabilities`, `/settings/updates`: `scrollWidth <= innerWidth`, filter sheet opens and applies, cards show
   hostname + chip); `e2e/accessibility.spec.ts` (the same pages plus the palette and a confirm dialog, in `light`
   and `dark` set through the user menu, with `expectAccessible`). Result: all gates green in both themes and both
   languages. Check: `make e2e`, `make lint test`.
10. **Screenshots, README, CHANGELOG, docs, regression.** Do: `screenshots.spec.ts` per §6.9 plus a visual set
    (not committed) to `server/web/test-results/visual/<page>-<width>-<theme>.png` for widths 390, 1280, 1920 and both
    themes of `/`, `/devices`, `/devices/<id>`, `/attention`, `/audit`; README `<picture>` blocks for overview, devices,
    device, audit; CHANGELOG; glossary rows; `docs/compliance/third-party.md` final. Result: README shows the new
    portal. Check: `PADDOCK_E2E_SCREENSHOTS=1 make e2e`, `make acceptance`, `make e2e`, `make lint test`; the visual
    set reviewed by the architect and the UX designer (reported in the hand-over message with the paths).

## 8. Tests

| Level | New / changed | What |
| --- | --- | --- |
| Go unit | `app/accounts_test.go`, `app/overview_test.go` (pure helpers), `transport/http/admin/handlers_test.go`, `static_test.go`, `listspec_test.go` | theme validation, MIME, list spec of `listAttentionDevices`, overview handler roles (platform admin 403) |
| Go integration | `app/overview_integration_test.go`, `app/attention_integration_test.go`, `app/auditlog_integration_test.go` | counts with seeded devices in every bucket (one device per bucket plus one device in two buckets counted once); grouped attention ordering and filter semantics; audit device resolution (known device, unknown id, event without device); `target_id` filter |
| Acceptance | `isolation_test.go` (fixtures), `list_contract_test.go` (automatic), `overview_test.go`, `attention_devices_test.go` | §7 step 5 |
| Vitest | `theme.test.ts` (tokens.css ↔ theme.ts; resolveTheme; cached preference fallback), `noHexColors.test.ts`, `icons.test.ts` (allow-list; every nav icon exists; `--check` of the generator), `vendored.test.ts` (manifest logic against fixtures), `statusChip.test.ts`, `status.test.ts` (every enum value mapped — exhaustive switch via `satisfies`), `time.test.ts` (today vs other day, seconds, relative units, locale de), `confirmDialog.test.ts`, `dataList.test.ts`, `emptyState.test.ts`, `dangerZone.test.ts`, `commandPalette.test.ts` (grouping, no destructive entries: a test asserts no entry label matches /lock|destroy|retire|revoke|reveal|rotate|suspend/i), `shortcuts.test.ts`, `navigation.test.ts`, `overview.test.ts`, `deviceHeader.test.ts`, `audit.test.ts`, `attention.test.ts`, `session.test.ts` (setTheme), `router.test.ts` (homeFor) | component and logic behaviour, edge cases: zero counts, null agent version, device without status row, hostnames of 63 chars, German lengths |
| e2e (both languages where the spec runs in German) | `theme.spec.ts`: preference persists (`GET /me` returns it; `html[data-theme]`; emulate `colorScheme: dark` with `system` → dark; reload keeps it; reset to `system` in `finally`); `keyboard.spec.ts`: `Ctrl+K` palette lists pages and a seeded device, Enter opens it; `g a`; `j`/`k` + Enter on the device list; `?` dialog; shortcuts inert in the search field; switch off disables `g d`; `mobile.spec.ts`; `accessibility.spec.ts`; existing specs adapted | user flows, axe in both themes, no horizontal scroll at 390 px, no CSP violation (`watchCSP` in every new spec) |
| Visual | `screenshots.spec.ts` | README set (committed) and visual set at 390/1280/1920 × light/dark (reviewed, not committed) |

Never weaken an existing assertion; where a locator changes because the DOM changed (chip instead of text, grouped
rows), the assertion keeps its meaning.

## 9. Acceptance criteria

| # | Given / When / Then | Req. | Observed by |
| --- | --- | --- | --- |
| AC1 | Given an org admin signs in, then `/` shows the overview with KPI strip, attention grouped by device, severity bar, updates/agent panel and recent audit, and every KPI value equals the corresponding list's `total` | review 1 | Org admin |
| AC2 | Given the user menu, when the admin picks Dark, then the portal switches instantly, `GET /api/v1/me` returns `theme: dark`, a new browser on the same account opens dark; with System, the OS preference decides | PO decision 1 | Org admin, platform admin |
| AC3 | Given any page in light or dark, then axe reports no serious or critical violation and every text pair meets AA | PO decision 7 | Everyone (gate) |
| AC4 | Given the network panel, then no request leaves the portal origin for fonts or icons; `Content-Type` of woff2 is `font/woff2` | PO decision 2 | Platform operator |
| AC5 | Given a changed or added font/icon file without a manifest or notice update, then `make lint` fails naming the file | PO decision 2 | Reviewer (CI) |
| AC6 | Given the device list, attention, audit and token pages, then every state is a chip with dot and label; critical/high/medium/low/unknown CVE chips use the severity scale with orange high in both themes | review 2, PO decision 3 | Org admin |
| AC7 | Given a device page, then the header band shows hostname, chips and primary actions; Overview/Software/Vulnerabilities/Login & sudo/Configuration/Commands/Audit are tabs with URLs; the danger zone is the last section with Lock, Destroy and Retire each with its own explanation, button and dialog reason field; no shared Reason field exists | review 3 | Org admin |
| AC8 | Given a device with two open conditions, then the attention page and the overview show it once with both conditions, most severe first, and one action | review 4 | Org admin, operator |
| AC9 | Given a device event in the audit log, then the sentence names the hostname, the Device column links to the device, the timestamp is one mono line, the actor has a type chip, and the expanded row shows the stored params unchanged | review 5, CLAUDE.md Audit | Org auditor |
| AC10 | Given a 390 px viewport, then no page scrolls horizontally, lists render as cards and filters open in a sheet | review 6 | Org admin on a phone |
| AC11 | Given the keyboard only, then `Ctrl/⌘ K` opens the palette and reaches any page, device or group; `j`/`k`/Enter work in lists; `g`-shortcuts navigate; `?` lists everything; no shortcut or palette entry locks, destroys, retires, reveals, rotates, suspends or revokes; every confirm dialog opens with focus on Cancel | PO decision 4, ADR 0018 | Org admin |
| AC12 | Given the drawer, then it has icons, overline group headers, a labelled attention pill, collapses to a 52 px rail with tooltips and scrolls independently at 900 px height | review 9, 10 | Org admin |
| AC13 | Given an empty list, then the page says what the list is for and offers the next step when the role may act | review 8 | Org admin, auditor |
| AC14 | Given `prefers-reduced-motion: reduce`, then dialogs, palette and drawer open without transition | PO decision 7 | Everyone |
| AC15 | Given the German locale, then every new screen is German, uses the glossary and still passes AC3 and AC10 | M6b decision 2 | German-speaking admin |
| AC16 | Given `make acceptance` and `make e2e` after step 10, then every pre-existing gate is green | CLAUDE.md DoD | Reviewer |
| AC17 | Given a second organization, then `/overview` and `/attention/devices` never include its devices (isolation gate) | CLAUDE.md isolation | Reviewer (gate) |

## 10. Freedoms

- Internal names of CSS classes beyond those named here, helper functions, the split of `styles.css` into further
  files, the order of imports.
- Exact pixel values inside the ranges of the spec (panel padding 12–16 px, gaps), the KPI cell order after the
  first four, which three findings the device summary shows when severities tie.
- Whether the KPI strip and panels are their own components or inline in `Overview.vue` (the testids are fixed).
- The debounce of the palette search within 100–200 ms; the exact relative-time thresholds between units.
- The implementation of the roving tabindex (own composable or Vuetify's `v-list` with `nav` — as long as the DOM
  contract of §3.3 item 15 holds).
- The icon glyph for "Overview" and "Attention" may be swapped for `gauge` / `bell-ring` if the designer prefers,
  recorded in `vendored.json`.
- Preloading `IBMPlexSans-Regular-Latin1.woff2` through a `<link rel="preload">` in `index.html` (only if the built
  `dist/index.html` carries the hashed URL; otherwise omit).
- Test fixture data and helper names.

## 11. Stop conditions

Stop and report (no silent workaround) when:
1. A Lucide, IBM Plex or JetBrains Mono release file cannot be downloaded from the official GitHub release, or its
   licence text differs from OFL-1.1 / ISC.
2. A spec contrast pair measures below 4.5:1 in a real render (report the pair; do not change a token on your own).
3. Vuetify 4.2.3 cannot register a component icon set or cannot switch themes without a transition (report the
   API).
4. `listspec_test.go`, `isolation_test.go` or `audit_once_test.go` require a classification for the new GETs that
   this plan does not name.
5. The audit index lacks `organization_id` on `audit_event` for the new index, or the audit reader role lacks a
   needed grant.
6. `device_status.login_state -> 'updates_security'` does not carry `occurred_at` and `params.result` as assumed in
   §3.5 item 26 (report the actual shape).
7. A page-level horizontal scroll at 390 px cannot be removed without hiding information the spec requires.
8. An e2e assertion can only pass by weakening it.
9. A new dependency would be needed (any `npm install`, Go module or image).
10. M7a's `/platform/ip-allowlist` page exists and uses components this plan replaces in an incompatible way.

## 12. Risks and open points (defaults chosen)

**Risks**
- *Large diff, long-running branch.* Mitigation: ten committable steps; steps 1–5 are backend/foundation and can be
  merged before the views; feature parity is asserted by the unchanged e2e specs.
- *Attention page semantics change (grouped) could break operator habits.* Mitigation: the per-condition API stays;
  the `kind` filter stays; the summary explains the grouping.
- *Overview query cost on large organizations.* Mitigation: one transaction, indexed predicates
  (`device_status_org_contact_idx`, `device_status_disk_state_idx`, `device_alert` open rows); measured in the
  acceptance gate with the dev seed (88 devices) and reported; if `/overview` exceeds 300 ms p95 on the reference
  machine, M7d adds a materialized summary refreshed by the worker.
- *Read-time hostname resolution in the audit list adds one organization query per page.* Bounded by `page_size ≤ 100`.
- *Vendored fonts in git (~500 KB).* Accepted (ADR 0023).
- *Roving tabindex changes the Tab order of the navigation.* The e2e specs use `getByRole('link')` clicks, not Tab
  counts; `keyboard.spec.ts` covers Up/Down.

**Open points (defaults chosen)**
1. *Where does the KPI "Online" link?* Default: `/devices?state=active` (no contact filter exists on the device
   list). A `contact` filter on `GET /api/v1/devices` (repeatable enum) is **in scope as a SHOULD** in step 5 if it
   costs less than an hour; then the KPIs link to `/devices?contact=ok` etc. and the device list offers the filter.
2. *Security-overdue window.* Default 48 h, a constant; not configurable in this milestone.
3. *Palette actions for Lock/Destroy.* Default: none (the spec's "navigate to the danger zone" entry is implemented
   as a plain "Go to the danger zone" navigation without opening a dialog).
4. *Theme toggle semantics.* Default: the app-bar button sets an explicit `light`/`dark`; `system` is chosen in the
   user menu only.
5. *Audit tab on the device page for org_operator.* Default: hidden (the API answers 403 for operators).
6. *Density stored on the account like the theme?* Default: no, viewer-only (localStorage); can become an account
   field later without a migration of existing behaviour.
7. *Latin-ext for JetBrains Mono.* Default: the full upstream woff2 (covers it); no subset.
8. *README picture element with dark source.* Default: yes (§6.9); GitHub renders `<picture>` with media sources.
