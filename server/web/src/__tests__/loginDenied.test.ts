import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import LoginDenied from '../views/LoginDenied.vue'
import { createPortalI18n, type PortalLocale } from '../i18n'

const POST = vi.fn()
vi.mock('../api/client', () => ({ api: { POST: (...a: unknown[]) => POST(...a) } }))

let wrapper: VueWrapper | null = null
const original = window.location

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  POST.mockReset()
  Object.defineProperty(window, 'location', { value: original, writable: true })
})

async function mountView(reason: string, locale: PortalLocale = 'en'): Promise<VueWrapper> {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/login-denied', component: LoginDenied }] })
  await router.push('/login-denied?reason=' + encodeURIComponent(reason))
  wrapper = mount(LoginDenied, { global: { plugins: [createPortalI18n(locale), router] } })
  await flushPromises()
  return wrapper
}

describe('login denied', () => {
  it('names a missing second factor and offers to sign in again (plan M8x decision 6)', async () => {
    const w = await mountView('mfa_required')
    expect(w.get('[data-testid="login-denied-message"]').text()).toBe(
      'Your sign-in did not include a second factor. Sign in again: the portal asks for your password and your authenticator.')
    expect(w.get('a').attributes('href')).toBe('/api/auth/login')
  })

  it('speaks the browser language before a session exists (plan M8f decision 22)', async () => {
    const w = await mountView('mfa_required', 'de')
    expect(w.get('[data-testid="login-denied-message"]').text()).toBe(
      'Ihre Anmeldung enthielt keinen zweiten Faktor. Melden Sie sich erneut an: Das Portal fragt nach Ihrem Passwort und Ihrem Authenticator.')
  })

  it('names a sealed key store (plan M8x decision 28)', async () => {
    const w = await mountView('key_store_sealed')
    expect(w.get('[data-testid="login-denied-message"]').text()).toContain('An operator must unseal OpenBao (docs/operations/openbao.md, section 2).')
  })

  it.each([
    ['no_role', 'one of the groups paddock.<organization>.admins, .operators or .auditors.'],
    ['multiple_organizations', 'Your account holds roles in several organizations.'],
    ['multiple_roles', 'Your account holds several roles in one organization (administrator, operator or auditor).'],
    ['role_not_granted', 'The role you chose is no longer granted'],
    ['organization_inactive', 'Your organization is not active. Ask a platform administrator.'],
    ['not_authorized', 'Your account is not authorized for the Paddock portal.'],
  ])('names the denial reason %s (plan M8x decision 32)', async (reason, text) => {
    const w = await mountView(reason)
    expect(w.get('[data-testid="login-denied-message"]').text()).toContain(text)
  })

  it('explains the passkey and offers to sign out of the identity provider (ADR 0034 amendment 2026-10-29)', async () => {
    const w = await mountView('passkey_required')
    expect(w.get('[data-testid="login-denied-message"]').text()).toBe(
      'Your sign-in did not use a passkey, and every Paddock portal role requires one (a security key or the ' +
      'authenticator built into your device). Sign out of the identity provider, then sign in again and confirm with ' +
      'your passkey. If you have no passkey yet, the sign-in asks you to set one up.')
    expect(w.get('button').text()).toBe('Sign out of the identity provider')
    expect(w.get('a').attributes('href')).toBe('/api/auth/login')
  })

  it('explains the passkey in German', async () => {
    const w = await mountView('passkey_required', 'de')
    expect(w.get('[data-testid="login-denied-message"]').text()).toContain(
      'Melden Sie sich beim Identitätsanbieter ab, melden Sie sich dann erneut an und bestätigen Sie mit Ihrem Passkey.')
    expect(w.get('button').text()).toBe('Beim Identitätsanbieter abmelden')
  })

  it('ends the portal session and goes to the identity provider\'s invalidation flow', async () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', { value: { ...original, origin: 'https://admin.test', assign }, writable: true })
    POST.mockResolvedValue({ data: { end_session_url: 'https://auth.test/flows/-/default/invalidation/' } })
    const w = await mountView('passkey_required')
    await w.get('button').trigger('click')
    await flushPromises()
    expect(POST).toHaveBeenCalledWith('/api/auth/logout', { params: { header: { 'X-Paddock-CSRF': '1' } } })
    expect(assign).toHaveBeenCalledWith('https://auth.test/flows/-/default/invalidation/')
  })

  it('returns to the portal when the identity provider is unknown', async () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', { value: { ...original, origin: 'https://admin.test', assign }, writable: true })
    POST.mockResolvedValue({ data: { end_session_url: 'https://admin.test/' } })
    const w = await mountView('passkey_required')
    await w.get('button').trigger('click')
    await flushPromises()
    expect(assign).toHaveBeenCalledWith('https://admin.test/')
  })

  it('returns to the portal when the logout fails', async () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', { value: { ...original, origin: 'https://admin.test', assign }, writable: true })
    POST.mockRejectedValue(new Error('offline'))
    const w = await mountView('passkey_required')
    await w.get('button').trigger('click')
    await flushPromises()
    expect(assign).toHaveBeenCalledWith('/')
  })

  it('offers the identity provider sign-out only for a missing passkey', async () => {
    const w = await mountView('mfa_required')
    expect(w.find('button').exists()).toBe(false)
  })

  it('falls back to the generic text for an unknown reason', async () => {
    const w = await mountView('something_else')
    expect(w.get('[data-testid="login-denied-message"]').text()).toBe('The sign-in could not be completed.')
  })
})
