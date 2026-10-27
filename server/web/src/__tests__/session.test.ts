import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { applyLocale, i18n } from '../i18n'
import { useSessionStore } from '../stores/session'

const me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice', role: 'org_admin',
  organization: null, locale: 'de', theme: 'system', revocation_enabled: false,
}
const GET = vi.fn()
const PATCH = vi.fn()
const POST = vi.fn()
vi.mock('../api/client', () => ({
  api: { GET: (...a: unknown[]) => GET(...a), PATCH: (...a: unknown[]) => PATCH(...a), POST: (...a: unknown[]) => POST(...a) },
}))

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

describe('session theme (plan M7c decision 6)', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    GET.mockReset()
    PATCH.mockReset()
  })
  afterEach(() => applyLocale('en'))

  it('stores the theme on the account and applies it', async () => {
    GET.mockResolvedValue({ data: { ...me, locale: 'en', theme: 'light' } })
    PATCH.mockResolvedValue({ data: { ...me, locale: 'en', theme: 'dark' } })
    const session = useSessionStore()
    await session.load()
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(await session.setTheme('dark')).toBe(true)
    expect(PATCH).toHaveBeenCalledWith('/api/v1/me', { params: { header: { 'X-Paddock-CSRF': '1' } }, body: { theme: 'dark' } })
    expect(session.me?.theme).toBe('dark')
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(localStorage.getItem('paddock.theme')).toBe('dark')
  })

  it('keeps the previous theme when the account cannot be updated', async () => {
    GET.mockResolvedValue({ data: { ...me, locale: 'en', theme: 'light' } })
    PATCH.mockResolvedValue({ error: { code: 'internal' } })
    const session = useSessionStore()
    await session.load()
    expect(await session.setTheme('dark')).toBe(false)
    expect(session.me?.theme).toBe('light')
    expect(document.documentElement.dataset.theme).toBe('light')
  })

  it('refuses a value that is not a theme preference without asking the server', async () => {
    GET.mockResolvedValue({ data: { ...me, locale: 'en', theme: 'light' } })
    const session = useSessionStore()
    await session.load()
    expect(await session.setTheme('sepia' as never)).toBe(false)
    expect(PATCH).not.toHaveBeenCalled()
  })
})

describe('session role switch (ADR 0045 decision 3)', () => {
  const assign = vi.fn()
  const original = window.location
  beforeEach(() => {
    setActivePinia(createPinia())
    GET.mockReset()
    POST.mockReset()
    assign.mockReset()
    Object.defineProperty(window, 'location', { value: { ...original, assign }, writable: true })
  })
  afterEach(() => Object.defineProperty(window, 'location', { value: original, writable: true }))

  it('names the alternate role of the session, null for a single-role identity', async () => {
    GET.mockResolvedValue({ data: { ...me, locale: 'en', alternate_role: { role: 'platform_admin' } } })
    const session = useSessionStore()
    await session.load()
    expect(session.alternateRole).toEqual({ role: 'platform_admin' })
    session.me = { ...session.me!, alternate_role: null }
    expect(session.alternateRole).toBeNull()
  })

  it('posts the chosen role with the CSRF header and navigates to the authorization URL', async () => {
    POST.mockResolvedValue({ data: { authorize_url: 'https://auth.test/authorize?state=s' } })
    await useSessionStore().switchRole('platform')
    expect(POST).toHaveBeenCalledWith('/api/auth/switch', {
      params: { header: { 'X-Paddock-CSRF': '1' } },
      body: { role: 'platform' },
    })
    expect(assign).toHaveBeenCalledWith('https://auth.test/authorize?state=s')
  })

  it('rejects with the problem and does not navigate when the server refuses', async () => {
    const problem = { code: 'no_alternate_role', status: 400 }
    POST.mockResolvedValue({ error: problem })
    await expect(useSessionStore().switchRole('organization')).rejects.toBe(problem)
    expect(POST).toHaveBeenCalledWith('/api/auth/switch', expect.objectContaining({ body: { role: 'organization' } }))
    expect(assign).not.toHaveBeenCalled()
  })
})
