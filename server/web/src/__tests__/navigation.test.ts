import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../App.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { navigationGroups, visibleNavigation, type NavigationAccess } from '../lib/navigation'
import type { Me } from '../api/client'

vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  attentionCount: () => Promise.resolve(3),
}))

const admin: Me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice Admin',
  role: 'org_admin', organization: { id: '00000000-0000-0000-0000-0000000000aa', slug: 'acme', name: 'Acme' },
  locale: 'en', revocation_enabled: false,
}

let wrapper: VueWrapper | null = null

beforeEach(() => {
  localStorage.clear()
  resize(1920)
})

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

/** Sets the viewport width Vuetify's display composable reads. */
function resize(width: number): void {
  Object.defineProperty(window, 'innerWidth', { value: width, configurable: true, writable: true })
  window.dispatchEvent(new Event('resize'))
}

function testRouter(): Router {
  const stub = { render: () => null }
  const paths = navigationGroups.flatMap((g) => g.items.map((i) => i.to))
  return createRouter({
    history: createMemoryHistory(),
    routes: [...paths.map((path) => ({ path, component: stub })), { path: '/devices/:id', component: stub }],
  })
}

async function mountApp(me: Me = admin, path = '/devices'): Promise<{ w: VueWrapper; router: Router }> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = me
  const router = testRouter()
  await router.push(path)
  await router.isReady()
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return { w: wrapper, router }
}

const drawer = (w: VueWrapper) => w.find('[data-testid="nav-drawer"]')
const groupLabels = (w: VueWrapper) => drawer(w).findAll('.v-list-subheader').map((s) => s.text())
const linkLabels = (w: VueWrapper) => drawer(w).findAll('a.v-list-item').map((a) => a.find('.v-list-item-title').text())

describe('navigation drawer', () => {
  it('shows the groups in their order with their entries', async () => {
    const { w } = await mountApp()
    expect(drawer(w).element.tagName).toBe('NAV')
    expect(drawer(w).attributes('aria-label')).toBe('Main navigation')
    expect(groupLabels(w)).toEqual(['Overview', 'Devices', 'Configuration', 'Security', 'Inventory', 'Organization'])
    expect(linkLabels(w)).toEqual([
      'Start', 'Attention',
      'Devices', 'Device groups', 'Enrollment tokens',
      'Permission profiles', 'Managed files', 'Managed units', 'Package holds', 'Change sets',
      'Revocations', "Dead man's switch", 'Login & privileges',
      'Software', 'Vulnerabilities',
      'Users', 'Groups', 'API tokens', 'Updates', 'Audit log',
    ])
    const security = w.find('[data-testid="nav-group-security"]')
    expect(security.attributes('role')).toBe('group')
    expect(w.find('#' + security.attributes('aria-labelledby')).text()).toBe('Security')
  })

  it('keeps the attention badge on the drawer entry and in the app bar', async () => {
    const { w } = await mountApp()
    expect(w.find('[data-testid="nav-attention"] [data-testid="attention-count"] .v-badge__badge').attributes('aria-label'))
      .toBe('3 open conditions')
    expect(w.find('[data-testid="app-bar-attention"]').attributes('aria-label')).toBe('3 open conditions')
    expect(w.find('[data-testid="org-name"]').text()).toBe('Acme')
  })

  it('hides entries by role exactly as the app bar did', async () => {
    const operator = await mountApp({ ...admin, role: 'org_operator' })
    expect(linkLabels(operator.w)).toContain('Enrollment tokens')
    expect(linkLabels(operator.w)).not.toContain('Revocations')
    expect(linkLabels(operator.w)).not.toContain('Audit log')
    operator.w.unmount()

    const auditor = await mountApp({ ...admin, role: 'org_auditor' }, '/audit')
    expect(groupLabels(auditor.w)).toEqual(['Overview', 'Devices', 'Configuration', 'Security', 'Inventory', 'Organization'])
    expect(linkLabels(auditor.w)).not.toContain('Enrollment tokens')
    expect(linkLabels(auditor.w)).not.toContain('Revocations')
    expect(linkLabels(auditor.w)).toContain('Audit log')
    auditor.w.unmount()

    const platform = await mountApp({ ...admin, role: 'platform_admin', organization: null }, '/platform/organizations')
    expect(groupLabels(platform.w)).toEqual(['Overview', 'Platform'])
    expect(linkLabels(platform.w)).toEqual(['Start', 'Organizations', 'Agent releases'])
    expect(platform.w.find('[data-testid="app-bar-attention"]').exists()).toBe(false)
    expect(platform.w.find('[data-testid="org-name"]').exists()).toBe(false)
  })

  it('marks the current page with aria-current', async () => {
    const { w, router } = await mountApp(admin, '/managed-files')
    const current = () => drawer(w).findAll('[aria-current="page"]').map((a) => a.text())
    expect(current()).toEqual(['Managed files'])
    await router.push('/settings/dms')
    await flushPromises()
    expect(current()).toEqual(["Dead man's switch"])
  })

  it('keeps every entry in the tab order', async () => {
    const { w } = await mountApp()
    const links = drawer(w).findAll('a')
    expect(links.length).toBe(20)
    expect(links.filter((a) => a.attributes('tabindex') !== undefined && a.attributes('tabindex') !== '0')).toEqual([])
  })

  it('hides and shows the permanent drawer on wide screens and remembers it', async () => {
    const first = await mountApp()
    expect(drawer(first.w).classes()).not.toContain('v-navigation-drawer--temporary')
    expect(drawer(first.w).classes()).toContain('v-navigation-drawer--active')
    const toggle = first.w.find('[data-testid="nav-toggle"]')
    expect(toggle.attributes('aria-label')).toBe('Hide the navigation')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    await toggle.trigger('click')
    expect(drawer(first.w).classes()).not.toContain('v-navigation-drawer--active')
    expect(toggle.attributes('aria-label')).toBe('Show the navigation')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(localStorage.getItem('paddock.navigation.rail')).toBe('true')
    first.w.unmount()

    const second = await mountApp()
    expect(drawer(second.w).classes()).not.toContain('v-navigation-drawer--active')
    await second.w.find('[data-testid="nav-toggle"]').trigger('click')
    expect(drawer(second.w).classes()).toContain('v-navigation-drawer--active')
    expect(localStorage.getItem('paddock.navigation.rail')).toBe('false')
    // An entry chosen on a wide screen leaves the drawer shown.
    await drawer(second.w).find('a[href="/software"]').trigger('click')
    await flushPromises()
    expect(drawer(second.w).classes()).toContain('v-navigation-drawer--active')
  })

  it('starts shown when the storage is unavailable', async () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    try {
      const { w } = await mountApp()
      expect(drawer(w).classes()).toContain('v-navigation-drawer--active')
      await w.find('[data-testid="nav-toggle"]').trigger('click')
      expect(drawer(w).classes()).not.toContain('v-navigation-drawer--active')
    } finally {
      get.mockRestore()
      set.mockRestore()
    }
  })

  it('is a temporary drawer behind a hamburger button below 1280 px', async () => {
    resize(1279)
    const { w, router } = await mountApp()
    const hamburger = w.find('[data-testid="nav-toggle"]')
    expect(hamburger.attributes('aria-label')).toBe('Show the navigation')
    expect(hamburger.attributes('aria-expanded')).toBe('false')
    expect(drawer(w).classes()).toContain('v-navigation-drawer--temporary')
    expect(drawer(w).attributes('inert')).toBeDefined()

    await hamburger.trigger('click')
    expect(hamburger.attributes('aria-expanded')).toBe('true')
    expect(hamburger.attributes('aria-label')).toBe('Hide the navigation')
    expect(drawer(w).classes()).toContain('v-navigation-drawer--active')

    await drawer(w).find('a[href="/software"]').trigger('click')
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/software'))
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--active')

    // Choosing the page already shown closes the drawer as well.
    await hamburger.trigger('click')
    await drawer(w).find('a[href="/software"]').trigger('click')
    await flushPromises()
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--active')

    // Opening and closing on a small screen is not remembered.
    expect(localStorage.getItem('paddock.navigation.rail')).toBeNull()

    resize(1280)
    await flushPromises()
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--temporary')
    expect(drawer(w).classes()).toContain('v-navigation-drawer--active')
  })
})

describe('visibleNavigation', () => {
  const none: NavigationAccess = { isPlatform: false, canWrite: false, canDelete: false, canReadAudit: false, canReadGroups: false }

  it('leaves out groups without a visible entry', () => {
    expect(visibleNavigation(none).map((g) => g.key)).toEqual(['overview'])
  })
})
