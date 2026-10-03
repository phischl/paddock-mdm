import { afterEach, describe, expect, it } from 'vitest'
import IntlMessageFormat from 'intl-messageformat'
import { en as vuetifyEn } from 'vuetify/locale'
import { createPortalI18n } from '../i18n'
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

describe('Vuetify messages', () => {
  const { t } = createPortalI18n().global

  function leaves(value: unknown, path: string): [string, string][] {
    if (typeof value === 'string') return [[path, value]]
    return Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => leaves(v, path + '.' + k))
  }

  it('all compile as ICU messages', () => {
    for (const [key, message] of leaves(vuetifyEn, '$vuetify')) {
      expect(() => new IntlMessageFormat(message, 'en'), key).not.toThrow()
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
