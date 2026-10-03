import { describe, expect, it } from 'vitest'
import { createPortalI18n } from '../i18n'

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
