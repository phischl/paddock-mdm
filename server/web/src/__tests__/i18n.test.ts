import { afterEach, describe, expect, it } from 'vitest'
import IntlMessageFormat from 'intl-messageformat'
import { de as vuetifyDe, en as vuetifyEn } from 'vuetify/locale'
import { applyLocale, createPortalI18n, i18n } from '../i18n'
import { catalogProblems, type Catalog } from '../lib/catalogCheck'
import { auditCodes } from '../lib/auditCodes.gen'
import en from '../locales/en.json'
import de from '../locales/de.json'
import { cspNonce } from '../plugins/vuetify'

describe('ICU message compiler', () => {
  const i18n = createPortalI18n()
  const { t } = i18n.global

  it('formats plurals', () => {
    expect(t('deviceGroups.count', { count: 0 })).toBe('No device groups')
    expect(t('deviceGroups.count', { count: 1 })).toBe('1 device group')
    expect(t('deviceGroups.count', { count: 1234 })).toBe('1,234 device groups')
  })

  it('interpolates named arguments', () => {
    expect(t('audit.device_group.created', { actor: 'alice@acme.test', name: 'Laptops' })).toBe(
      'alice@acme.test created the device group Laptops',
    )
  })

  it('does not evaluate code in arguments', () => {
    expect(t('app.signedInAs', { name: '{constructor}' })).toBe('Signed in as {constructor}')
  })
})

describe('German catalog (plan M6b decision 2)', () => {
  const { t } = createPortalI18n().global

  it('formats plurals and numbers the German way', () => {
    expect(t('deviceGroups.count', { count: 0 }, { locale: 'de' })).toBe('Keine Gerätegruppen')
    expect(t('deviceGroups.count', { count: 1 }, { locale: 'de' })).toBe('1 Gerätegruppe')
    expect(t('deviceGroups.count', { count: 1234 }, { locale: 'de' })).toBe('1.234 Gerätegruppen')
  })

  it('displays audit events in German from the stored English code', () => {
    expect(t('audit.device_group.created', { actor: 'alice@acme.test', name: 'Laptops' }, { locale: 'de' })).toBe(
      'alice@acme.test hat die Gerätegruppe Laptops angelegt',
    )
    expect(t('audit.revocation.issued', { action: 'self_lock', hostname: 'laptop-1' }, { locale: 'de' })).toBe(
      'Die Selbstsperre von laptop-1 wurde ausgestellt',
    )
  })

  it('is complete: every English key, valid ICU, the same arguments, every audit code', () => {
    expect(catalogProblems(en, de, 'de', auditCodes)).toEqual([])
  })
})

describe('catalogProblems', () => {
  const source: Catalog = { a: { one: 'One {name}', two: 'Two' }, audit: { x: { done: '{actor} did it' } } }

  it('reports missing, extra, invalid and mismatched messages and audit codes without a message', () => {
    const translated: Catalog = { a: { one: 'Eins {nom}', three: 'Drei' }, audit: { x: { done: '{actor' } } }
    expect(catalogProblems(source, translated, 'de', ['x.done', 'x.undone'])).toEqual([
      'en: audit.x.undone: no display message for the audit code',
      'de: a.one: arguments {nom} differ from en {name}',
      'de: a.two: missing',
      expect.stringMatching(/^de: audit\.x\.done: not valid ICU MessageFormat/),
      'de: a.three: not in en.json',
    ])
  })

  it('finds arguments inside plural and select branches', () => {
    const plural: Catalog = { p: '{count, plural, one {# {thing}} other {# {thing}s}}' }
    expect(catalogProblems(plural, { p: '{count, plural, other {#}}' }, 'de', [])).toEqual([
      'de: p: arguments {count} differ from en {count, thing}',
    ])
    expect(catalogProblems(plural, { p: '{count, plural, one {# {thing}} other {# {thing}}}' }, 'de', [])).toEqual([])
  })
})

describe('applyLocale', () => {
  afterEach(() => applyLocale('en'))

  it('switches the shared instance and the document language', () => {
    applyLocale('de')
    expect(i18n.global.locale.value).toBe('de')
    expect(document.documentElement.lang).toBe('de')
    expect(i18n.global.t('app.logout')).toBe('Abmelden')
  })

  it('falls back to English for an unknown locale', () => {
    applyLocale('fr')
    expect(i18n.global.locale.value).toBe('en')
    expect(document.documentElement.lang).toBe('en')
  })
})

describe('Vuetify messages', () => {
  const { t } = createPortalI18n().global

  function leaves(value: unknown, path: string): [string, string][] {
    if (typeof value === 'string') return [[path, value]]
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => leaves(v, path + '.' + k))
  }

  it('all compile as ICU messages', () => {
    for (const [locale, messages] of [['en', vuetifyEn], ['de', vuetifyDe]] as const) {
      for (const [key, message] of leaves(messages, '$vuetify')) {
        expect(() => new IntlMessageFormat(message, locale), locale + ' ' + key).not.toThrow()
      }
    }
  })

  it('are reachable under $vuetify with positional arguments', () => {
    // Vuetify's keys are not in src/locales, so they are built at runtime (no-missing-keys checks literals).
    const vuetifyKey = (key: string) => '$vuetify.' + key
    expect(t(vuetifyKey('dataFooter.pageText'), [1, 10, 100])).toBe('1-10 of 100')
    expect(t(vuetifyKey('noDataText'))).toBe(vuetifyEn.noDataText)
  })
})

describe('cspNonce', () => {
  afterEach(() => document.head.querySelectorAll('meta[name="csp-nonce"]').forEach((m) => m.remove()))

  function setMeta(content: string): void {
    const meta = document.createElement('meta')
    meta.name = 'csp-nonce'
    meta.content = content
    document.head.append(meta)
  }

  it('is undefined without the meta tag or with the placeholder', () => {
    expect(cspNonce()).toBeUndefined()
    setMeta('__CSP_NONCE__')
    expect(cspNonce()).toBeUndefined()
  })

  it('reads the nonce written by the server', () => {
    setMeta('q83vEjRWeJq83vEjRWeJqw==')
    expect(cspNonce()).toBe('q83vEjRWeJq83vEjRWeJqw==')
  })
})
