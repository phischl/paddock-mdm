import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { applyLocale, i18n } from '../i18n'
import { useSessionStore } from '../stores/session'

const me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice', role: 'org_admin',
  organization: null, locale: 'de', revocation_enabled: false,
}
const GET = vi.fn()
const PATCH = vi.fn()
vi.mock('../api/client', () => ({ api: { GET: (...a: unknown[]) => GET(...a), PATCH: (...a: unknown[]) => PATCH(...a) } }))

describe('session locale (plan M6b decision 2)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    GET.mockReset()
    PATCH.mockReset()
  })
  afterEach(() => applyLocale('en'))

  it('switches the portal to the language stored on the account', async () => {
    GET.mockResolvedValue({ data: me })
    await useSessionStore().load()
    expect(i18n.global.locale.value).toBe('de')
  })

  it('stores a new language on the account and switches to it', async () => {
    GET.mockResolvedValue({ data: { ...me, locale: 'en' } })
    PATCH.mockResolvedValue({ data: { ...me, locale: 'de' } })
    const session = useSessionStore()
    await session.load()
    expect(i18n.global.locale.value).toBe('en')
    expect(await session.setLocale('de')).toBe(true)
    expect(PATCH).toHaveBeenCalledWith('/api/v1/me', { params: { header: { 'X-Paddock-CSRF': '1' } }, body: { locale: 'de' } })
    expect(i18n.global.locale.value).toBe('de')
    expect(session.me?.locale).toBe('de')
  })

  it('keeps the language when the account cannot be updated', async () => {
    GET.mockResolvedValue({ data: { ...me, locale: 'en' } })
    PATCH.mockResolvedValue({ error: { code: 'internal' } })
    const session = useSessionStore()
    await session.load()
    expect(await session.setLocale('de')).toBe(false)
    expect(i18n.global.locale.value).toBe('en')
    expect(session.me?.locale).toBe('en')
  })
})
