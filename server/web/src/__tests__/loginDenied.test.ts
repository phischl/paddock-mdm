import { afterEach, describe, expect, it } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import LoginDenied from '../views/LoginDenied.vue'
import { createPortalI18n, type PortalLocale } from '../i18n'

let wrapper: VueWrapper | null = null

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
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

  it('falls back to the generic text for an unknown reason', async () => {
    const w = await mountView('something_else')
    expect(w.get('[data-testid="login-denied-message"]').text()).toBe('The sign-in could not be completed.')
  })
})
