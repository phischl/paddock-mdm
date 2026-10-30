import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../App.vue'
import { createPortalI18n, type PortalLocale } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore, type RoleChoice } from '../stores/session'
import { settleConfirm } from '../composables/useConfirm'
import type { Me } from '../api/client'

vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  attentionCount: () => Promise.resolve(0),
}))

const admin: Me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice Admin',
  role: 'org_admin', organization: { id: '00000000-0000-0000-0000-0000000000aa', slug: 'acme', name: 'Acme', domains: ['acme.test'] },
  locale: 'en', theme: 'system', revocation_enabled: false, client_ip: '198.51.100.7', step_up_valid_until: null,
  server_version: '0.1.0-alpha.6', alternate_role: null, channel: 'portal', mcp_write_enabled: false,
  mcp_write_enabled_at: null,
}
const platform: Me = { ...admin, role: 'platform_admin', organization: null }

let wrapper: VueWrapper | null = null
let switchRole: Mock<(choice: RoleChoice) => Promise<void>>

beforeEach(() => {
  localStorage.clear()
  Object.defineProperty(window, 'innerWidth', { value: 1920, configurable: true, writable: true })
})

afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
})

async function mountApp(me: Me, locale: PortalLocale = 'en'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const session = useSessionStore()
  session.me = me
  switchRole = vi.fn<(choice: RoleChoice) => Promise<void>>().mockResolvedValue(undefined)
  session.switchRole = switchRole
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:path(.*)*', component: { render: () => null } }] })
  await router.push('/')
  await router.isReady()
  wrapper = mount(App, {
    // Vuetify 4.3 wraps VAlert in a transition; the default stub would carry the alert's attributes instead of the alert.
    global: { plugins: [createPortalI18n(locale), vuetify, router, pinia], stubs: { transition: false } },
    attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

const query = (id: string) => document.querySelector<HTMLElement>(`[data-testid="${id}"]`)

async function openMenu(w: VueWrapper): Promise<void> {
  await w.get('[data-testid="user-menu"]').trigger('click')
  await vi.waitFor(() => expect(query('logout')).not.toBeNull())
}

async function chooseSwitch(): Promise<void> {
  query('switch-role')!.click()
  await vi.waitFor(() => expect(query('confirm-dialog')).not.toBeNull())
}

describe('role switch in the user menu (ADR 0045 decision 3)', () => {
  it('offers no switch to a single-role identity', async () => {
    await openMenu(await mountApp(admin))
    expect(query('switch-role')).toBeNull()
  })

  it('offers the platform role to an organization session and switches after confirmation', async () => {
    await openMenu(await mountApp({ ...admin, alternate_role: { role: 'platform_admin' } }))
    expect(query('switch-role')?.textContent?.trim()).toBe('Switch to Platform administrator')
    expect(query('switch-role')?.nextElementSibling?.getAttribute('data-testid')).toBe('logout')
    await chooseSwitch()
    const dialog = query('confirm-dialog')!
    expect(dialog.textContent).toContain('Switch role')
    expect(dialog.textContent).toContain('Your current session ends and privileged actions need a new step-up.')
    expect(query('confirm-typed')).toBeNull()
    query('confirm-accept')!.click()
    await flushPromises()
    expect(switchRole).toHaveBeenCalledExactlyOnceWith('platform')
  })

  it('offers the organization role with its slug to a platform session', async () => {
    await openMenu(await mountApp({ ...platform, alternate_role: { role: 'org_admin', organization_slug: 'acme' } }))
    expect(query('switch-role')?.textContent?.trim()).toBe('Switch to Organization administrator (acme)')
    await chooseSwitch()
    query('confirm-accept')!.click()
    await flushPromises()
    expect(switchRole).toHaveBeenCalledExactlyOnceWith('organization')
  })

  it('names the role in German', async () => {
    await openMenu(await mountApp({ ...platform, locale: 'de', alternate_role: { role: 'org_admin', organization_slug: 'acme' } }, 'de'))
    expect(query('switch-role')?.textContent?.trim()).toBe('Zu Organisationsadministrator (acme) wechseln')
  })

  it('does not switch when the confirmation is cancelled', async () => {
    await openMenu(await mountApp({ ...admin, alternate_role: { role: 'platform_admin' } }))
    await chooseSwitch()
    query('confirm-cancel')!.click()
    await flushPromises()
    expect(switchRole).not.toHaveBeenCalled()
  })

  it('shows an inline alert in the menu when the server refuses the switch', async () => {
    const w = await mountApp({ ...admin, alternate_role: { role: 'platform_admin' } })
    await openMenu(w)
    expect(query('switch-role-failed')).toBeNull()
    switchRole.mockRejectedValue({ code: 'unauthorized', status: 401 })
    await chooseSwitch()
    query('confirm-accept')!.click()
    await flushPromises()
    await vi.waitFor(() => expect(query('switch-role-failed')).not.toBeNull())
    expect(query('switch-role-failed')?.textContent).toContain('The role could not be switched.')
    expect(query('switch-role-failed')?.closest('[role="alert"], .v-alert')).not.toBeNull()
  })

  it('drops the alert of a refused switch once the menu closes', async () => {
    const w = await mountApp({ ...admin, alternate_role: { role: 'platform_admin' } })
    await openMenu(w)
    switchRole.mockRejectedValue({ code: 'unavailable', status: 503 })
    await chooseSwitch()
    query('confirm-accept')!.click()
    await vi.waitFor(() => expect(query('switch-role-failed')).not.toBeNull())
    await w.get('[data-testid="user-menu"]').trigger('click')
    await vi.waitFor(() => expect(query('switch-role-failed')).toBeNull())
    await openMenu(w)
    expect(query('switch-role-failed')).toBeNull()
  })
})

describe('sign-in fallback to the platform role (ADR 0045 amendment 2026-10-29)', () => {
  const fallback: Me = {
    ...platform, role_fallback: 'organization_inactive', alternate_role: { role: 'org_admin', organization_slug: 'acme' },
  }

  it('tells the administrator why the session is in the platform role', async () => {
    const w = await mountApp(fallback)
    expect(w.text()).toContain('Your organization is not active; you are signed in as platform administrator.')
  })

  it('says so in German', async () => {
    const w = await mountApp({ ...fallback, locale: 'de' }, 'de')
    expect(w.text()).toContain('Ihre Organisation ist nicht aktiv; Sie sind als Plattformadministrator angemeldet.')
  })

  it('shows no notice without a fallback', async () => {
    for (const me of [platform, admin, { ...platform, alternate_role: { role: 'org_admin' as const, organization_slug: 'acme' } }]) {
      const w = await mountApp(me)
      expect(w.text()).not.toContain('Your organization is not active')
      w.unmount()
      wrapper = null
    }
  })
})
