import { createI18n, type MessageCompiler, type MessageContext } from 'vue-i18n'
import IntlMessageFormat from 'intl-messageformat'
import en from './locales/en.json'

/**
 * All messages are ICU MessageFormat, compiled with intl-messageformat (architecture §18). The compiler never
 * evaluates code, so the strict CSP needs no 'unsafe-eval'.
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

export type MessageSchema = typeof en

export function createPortalI18n() {
  return createI18n<[MessageSchema], 'en'>({
    legacy: false,
    locale: 'en',
    fallbackLocale: 'en',
    messages: { en },
    messageCompiler,
    missingWarn: false,
    fallbackWarn: false,
  })
}
