import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../App.vue'
import SetupChecklist from '../components/SetupChecklist.vue'
import { createPortalI18n, type PortalLocale } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { useSetupStore } from '../stores/setup'
import type { SetupAccess, SetupStep } from '../lib/setupChecklist'
import type { Me } from '../api/client'

const admin: Me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice Admin',
  role: 'org_admin', organization: { id: 'o1', slug: 'acme', name: 'Acme', domains: ['acme.test'] },
  locale: 'en', theme: 'system', revocation_enabled: false, client_ip: '198.51.100.7', step_up_valid_until: null,
  server_version: '0.1.0-alpha.6', alternate_role: null, channel: 'portal', mcp_write_enabled: false,
  mcp_write_enabled_at: null,
}
const platform: Me = { ...admin, role: 'platform_admin', organization: null }
const auditor: Me = { ...admin, role: 'org_auditor' }
const key = `paddock.setup.dismissed.${admin.id}`

vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  attentionCount: () => Promise.resolve(0),
}))

let steps: SetupStep[] = []
let accessSeen: SetupAccess | null = null
vi.mock('../lib/setupChecklist', async (original) => ({
  ...(await original<typeof import('../lib/setupChecklist')>()),
  loadSetupSteps: (access: SetupAccess) => {
    accessSeen = access
    return Promise.resolve(steps)
  },
}))

const orgSteps: SetupStep[] = [
  { key: 'breakGlass', label: 'setup.steps.breakGlass', state: 'done', to: { name: 'login-settings' } },
  { key: 'token', label: 'setup.steps.token', state: 'open', to: { name: 'enrollment-tokens' } },
  { key: 'agent', label: 'setup.steps.agent', state: 'manual' },
  { key: 'device', label: 'setup.steps.device', state: 'unknown', to: { name: 'devices' } },
]

let wrapper: VueWrapper | null = null
beforeEach(() => {
  localStorage.clear()
  steps = orgSteps
  accessSeen = null
})
afterEach(() => {
  vi.restoreAllMocks()
  wrapper?.unmount()
  wrapper = null
})

async function mountChecklist(me: Me, locale: PortalLocale = 'en'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = me
  const routes = ['login-settings', 'enrollment-tokens', 'devices'].map((name) => ({
    path: '/' + name, name, component: { render: () => null },
  }))
  const router = createRouter({ history: createMemoryHistory(), routes })
  wrapper = mount(SetupChecklist, { global: { plugins: [createPortalI18n(locale), vuetify, router, pinia] } })
  await flushPromises()
  return wrapper
}

describe('SetupChecklist', () => {
  it('shows every step with its state and links open steps to their page', async () => {
    const w = await mountChecklist(admin)
    expect(w.get('[data-testid="setup-progress"]').text()).toBe('1 of 3 steps done')
    expect(w.get('[data-testid="setup-step-breakGlass"]').find('a').exists()).toBe(false)
    expect(w.get('[data-testid="setup-step-token"] a').attributes('href')).toBe('/enrollment-tokens')
    expect(w.get('[data-testid="setup-step-device"] a').attributes('href')).toBe('/devices')
    expect(w.get('[data-testid="setup-step-token"]').text()).toContain('To do')
  })

  it('shows host-shell steps as text with a link to the guide', async () => {
    const w = await mountChecklist(admin)
    const item = w.get('[data-testid="setup-step-agent"]')
    expect(item.text()).toContain('Install and enroll the agent on a device')
    expect(item.findAll('a')).toHaveLength(1)
    expect(item.get('a').attributes('href')).toMatch(/docs\/operations\/getting-started\.md$/)
  })

  it('renders in German', async () => {
    const w = await mountChecklist(admin, 'de')
    expect(w.get('[data-testid="setup-progress"]').text()).toBe('1 von 3 Schritten erledigt')
    expect(w.text()).toContain('Paddock einrichten')
  })

  it('asks for the steps its role may open', async () => {
    await mountChecklist(auditor)
    expect(accessSeen).toEqual({ isPlatform: false, canWrite: false })
    await mountChecklist(platform)
    expect(accessSeen).toEqual({ isPlatform: true, canWrite: false })
  })

  it('stores the dismissal per account and stays away on the next visit', async () => {
    const w = await mountChecklist(admin)
    await w.get('[data-testid="setup-dismiss"]').trigger('click')
    expect(w.find('[data-testid="setup-checklist"]').exists()).toBe(false)
    expect(localStorage.getItem(key)).toBe('1')
    w.unmount()
    accessSeen = null
    const again = await mountChecklist(admin)
    expect(again.find('[data-testid="setup-checklist"]').exists()).toBe(false)
    expect(accessSeen).toBeNull()
    const other = await mountChecklist({ ...admin, id: 'another-account' })
    expect(other.find('[data-testid="setup-checklist"]').exists()).toBe(true)
  })

  it('works when the storage throws on every access', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('blocked') })
    vi.spyOn(Storage.prototype, 'removeItem').mockImplementation(() => { throw new Error('blocked') })
    const w = await mountChecklist(admin)
    expect(w.find('[data-testid="setup-checklist"]').exists()).toBe(true)
    await w.get('[data-testid="setup-dismiss"]').trigger('click')
    expect(w.find('[data-testid="setup-checklist"]').exists()).toBe(false)
    useSetupStore().reopen()
    await flushPromises()
    expect(w.find('[data-testid="setup-checklist"]').exists()).toBe(true)
  })
})

describe('setup checklist in the user menu', () => {
  const query = (id: string) => document.querySelector<HTMLElement>(`[data-testid="${id}"]`)

  async function mountApp(me: Me): Promise<VueWrapper> {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = me
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', name: 'home', component: { render: () => null } }, { path: '/:path(.*)*', component: { render: () => null } }] })
    await router.push('/devices')
    await router.isReady()
    wrapper = mount(App, {
      global: { plugins: [createPortalI18n('en'), vuetify, router, pinia], stubs: { transition: false } },
      attachTo: document.body,
    })
    await flushPromises()
    await wrapper.get('[data-testid="user-menu"]').trigger('click')
    await vi.waitFor(() => expect(query('logout')).not.toBeNull())
    return wrapper
  }

  it('offers reopening only after a dismissal and then shows the checklist again', async () => {
    await mountApp(admin)
    expect(query('reopen-setup')).toBeNull()
    wrapper?.unmount()
    localStorage.setItem(key, '1')
    await mountApp(admin)
    expect(query('reopen-setup')?.textContent?.trim()).toBe('Show the setup checklist')
    query('reopen-setup')!.click()
    await vi.waitFor(() => expect(useSetupStore().dismissed).toBe(false))
    await flushPromises()
    expect(localStorage.getItem(key)).toBeNull()
  })
})
