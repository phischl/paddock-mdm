import { createVuetify } from 'vuetify'
import { aliases, mdi } from 'vuetify/iconsets/mdi-svg'
import { createVueI18nAdapter } from 'vuetify/locale/adapters/vue-i18n'
import { useI18n } from 'vue-i18n'
import 'vuetify/styles'
import { i18n } from '../i18n'

const noncePlaceholder = '__CSP_NONCE__'

/**
 * The per-response CSP style nonce the server writes into <meta name="csp-nonce">; undefined if the tag is
 * missing or still holds the placeholder (not served through the api role, e.g. unit tests).
 */
export function cspNonce(): string | undefined {
  const nonce = document.querySelector('meta[name="csp-nonce"]')?.getAttribute('content')
  return nonce && nonce !== noncePlaceholder ? nonce : undefined
}

/**
 * Vuetify with the Paddock theme (WCAG 2.1 AA contrast), the icon paths bundled with Vuetify (no icon font) and
 * Vuetify's own strings from the shared vue-i18n instance ($vuetify.*). The theme style sheet is the only <style>
 * element Vuetify injects; it carries the CSP nonce.
 */
export const vuetify = createVuetify({
  theme: {
    cspNonce: cspNonce(),
    defaultTheme: 'paddock',
    themes: {
      paddock: {
        dark: false,
        // Vuetify's default (0.60) leaves field labels below 4.5:1 contrast.
        variables: { 'medium-emphasis-opacity': 0.7 },
        colors: {
          background: '#f6f7f5',
          surface: '#ffffff',
          primary: '#1f5135',
          secondary: '#4a5551',
          error: '#a4161a',
          success: '#1d5d2f',
          warning: '#7a4b00',
        },
      },
    },
  },
  icons: { defaultSet: 'mdi', aliases, sets: { mdi } },
  locale: { adapter: createVueI18nAdapter({ i18n, useI18n }) },
  defaults: {
    VTextField: { variant: 'outlined', density: 'comfortable' },
    VTextarea: { variant: 'outlined', density: 'comfortable' },
    VSelect: { variant: 'outlined', density: 'comfortable' },
    VBtn: { variant: 'flat' },
  },
})
