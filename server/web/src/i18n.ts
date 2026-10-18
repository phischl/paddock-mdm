import { createI18n, type MessageCompiler, type MessageContext } from 'vue-i18n'
import IntlMessageFormat from 'intl-messageformat'
import { de as vuetifyDe, en as vuetifyEn } from 'vuetify/locale'
import en from './locales/en.json'
import de from './locales/de.json'

/**
 * All messages are ICU MessageFormat, compiled with intl-messageformat (architecture §18). The compiler never
 * evaluates code, so the strict CSP needs no 'unsafe-eval'. Vuetify's own strings ($vuetify.*) use positional
 * arguments ({0}), which are valid ICU arguments.
 */
export const messageCompiler: MessageCompiler = (message, { locale, key }) => {
  if (typeof message === 'string') {
    const formatter = new IntlMessageFormat(message, locale)
    return (ctx: MessageContext) => {
      const out = formatter.format(ctx.values as Record<string, string | number | boolean | Date>)
      return Array.isArray(out) ? out.join('') : String(out)
    }
  }
  // Precompiled message ASTs are not used; render the key so the gap is visible.
  return () => key
}

export type MessageSchema = typeof en & { $vuetify: typeof vuetifyEn }

/** The portal's catalogs (plan M6b decision 2); the administrator's choice is stored on the account. */
export const portalLocales = ['en', 'de'] as const
export type PortalLocale = (typeof portalLocales)[number]

export function isPortalLocale(value: string): value is PortalLocale {
  return (portalLocales as readonly string[]).includes(value)
}

/** The portal locale a browser asks for: the first of languages whose primary subtag is a portal locale, else en. */
export function browserLocale(languages: readonly string[]): PortalLocale {
  for (const language of languages) {
    const primary = language.split('-')[0]?.toLowerCase() ?? ''
    if (isPortalLocale(primary)) {
      return primary
    }
  }
  return 'en'
}

export function createPortalI18n(initial: PortalLocale = 'en') {
  return createI18n<[MessageSchema], string, false>({
    legacy: false,
    locale: initial,
    fallbackLocale: 'en',
    messages: { en: { ...en, $vuetify: vuetifyEn }, de: { ...de, $vuetify: vuetifyDe } },
    messageCompiler,
    missingWarn: false,
    fallbackWarn: false,
  })
}

/**
 * The portal's i18n instance, shared with Vuetify's locale adapter. It starts in the browser's language, so that
 * public pages without a session (the sign-in refusal) speak it; the account's stored language replaces it once
 * GET /api/v1/me has answered (stores/session.ts).
 */
export const i18n = createPortalI18n(browserLocale(navigator.languages ?? [navigator.language]))

/** Switches the portal to locale; an unknown locale falls back to English. */
export function applyLocale(locale: string): void {
  const next: PortalLocale = isPortalLocale(locale) ? locale : 'en'
  i18n.global.locale.value = next
  document.documentElement.lang = next
}
