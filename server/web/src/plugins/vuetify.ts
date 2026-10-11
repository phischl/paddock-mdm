import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg'
import { createVueI18nAdapter } from 'vuetify/locale/adapters/vue-i18n'
import { useI18n } from 'vue-i18n'
import 'vuetify/styles'
import { i18n } from '../i18n'
import { pdIconSet } from '../components/PdIconSet'
import { cachedPreference, installThemeSwitcher, resolveTheme, systemPrefersDark, vuetifyThemeName } from '../lib/theme'
import { paddockDark, paddockLight } from './theme'

const noncePlaceholder = '__CSP_NONCE__'

/** Viewport width from which the navigation drawer is expanded by default; 600–1279 px starts as a rail. */
export const navigationBreakpoint = 1280
/** Below this width the drawer is a temporary overlay, lists render as cards and filters open in a sheet. */
export const mobileBreakpoint = 600

/**
 * The per-response CSP style nonce the server writes into <meta name="csp-nonce">; undefined if the tag is
 * missing or still holds the placeholder (not served through the api role, e.g. unit tests).
 */
export function cspNonce(): string | undefined {
  const nonce = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content')
  return nonce && nonce !== noncePlaceholder ? nonce : undefined
}

/**
 * Vuetify with the two Paddock themes (ADR 0023; tokens in plugins/theme.ts), the vendored Lucide icons as the
 * icon set "pd" (icon="pd:laptop"), Vuetify's own icon paths for its internals, and Vuetify's strings from the
 * shared vue-i18n instance ($vuetify.*). The theme style sheet is the only <style> element Vuetify injects; it
 * carries the CSP nonce.
 */
export const vuetify = createVuetify({
  theme: {
    cspNonce: cspNonce(),
    // The first paint already uses the cached preference resolved against the system: no inline script, the CSP
    // stays unchanged.
    defaultTheme: vuetifyThemeName(resolveTheme(cachedPreference(), systemPrefersDark())),
    themes: { paddockLight, paddockDark },
  },
  icons: { defaultSet: 'mdi', aliases, sets: { mdi, pd: pdIconSet } },
  locale: { adapter: createVueI18nAdapter({ i18n, useI18n }) },
  defaults: {
    VBtn: { rounded: 'sm', variant: 'outlined', density: 'compact' },
    VTextField: { variant: 'outlined', density: 'compact' },
    VTextarea: { variant: 'outlined', density: 'compact' },
    VSelect: { variant: 'outlined', density: 'compact' },
    VAutocomplete: { variant: 'outlined', density: 'compact' },
    VDataTableServer: { density: 'compact' },
    VListItem: { density: 'compact' },
    VChip: { size: 'small', rounded: 'sm' },
    VNavigationDrawer: { width: 220, railWidth: 52 },
  },
})

installThemeSwitcher((name) => void vuetify.theme.change(name, false))
