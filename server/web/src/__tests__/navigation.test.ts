import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../App.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { navigationGroups, shortcutOf, shortcutRoutes, visibleNavigation, type NavigationAccess, type NavigationGroup } from '../lib/navigation'
import { icons } from '../lib/icons.gen'
import type { Me } from '../api/client'
import { settleConfirm, useConfirm } from '../composables/useConfirm'

vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  attentionCount: () => Promise.resolve(3),
}))

// PATCH /api/v1/me answers with the patched settings; the bodies sent are recorded.
const patched: Record<string, string>[] = []
vi.mock('../api/client', async (original) => {
  const mod = await original<typeof import('../api/client')>()
  return {
    ...mod,
    api: {
      ...mod.api,
      PATCH: (_path: string, init: { body: Record<string, string> }) => {
        patched.push(init.body)
        const store = useSessionStore()
        return Promise.resolve({ data: { ...store.me, ...init.body } })
      },
    },
  }
})

const admin: Me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice Admin',
  role: 'org_admin', organization: { id: '00000000-0000-0000-0000-0000000000aa', slug: 'acme', name: 'Acme', domains: ['acme.test'] },
  locale: 'en', theme: 'system', revocation_enabled: false, client_ip: '198.51.100.7', step_up_valid_until: null,
}

let wrapper: VueWrapper | null = null

beforeEach(() => {
  localStorage.clear()
  patched.length = 0
  delete document.documentElement.dataset.theme
  resize(1920)
})

afterEach(() => {
  settleConfirm(false)
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
const groupLabels = (w: VueWrapper) => drawer(w).findAll('h2.pd-nav-heading').map((s) => s.text())
const linkLabels = (w: VueWrapper) => drawer(w).findAll('a.pd-nav-item').map((a) => a.find('.pd-nav-label').text())

describe('navigation drawer', () => {
  it('shows the groups in their order with their entries, icons and shortcuts', async () => {
    const { w } = await mountApp()
    expect(drawer(w).element.tagName).toBe('NAV')
    expect(drawer(w).attributes('aria-label')).toBe('Main navigation')
    expect(groupLabels(w)).toEqual(['Overview', 'Devices', 'Configuration', 'Security', 'Inventory', 'Organization'])
    expect(linkLabels(w)).toEqual([
      'Overview', 'Attention',
      'Devices', 'Device groups', 'Enrollment tokens',
      'Permission profiles', 'Managed files', 'Managed units', 'Operator roots', 'Package holds', 'Change sets',
      'Security review', 'Revocations', "Dead man's switch", 'Login & privileges',
      'Software', 'Vulnerabilities',
      'Users', 'Groups', 'API tokens', 'Updates', 'Audit log',
    ])
    const security = w.find('[data-testid="nav-group-security"]')
    expect(security.attributes('role')).toBe('group')
    expect(w.find('#' + security.attributes('aria-labelledby')).text()).toBe('Security')
    for (const link of drawer(w).findAll('a.pd-nav-item')) {
      expect(link.find('svg.pd-icon').exists(), link.text()).toBe(true)
    }
    const devices = drawer(w).find('a[href="/devices"]')
    expect(devices.find('kbd').text()).toBe('g d')
    expect(devices.attributes('title')).toBe('Shortcut: g d')
  })

  it('names an icon that exists for every item and the g-shortcuts of six pages', () => {
    for (const item of navigationGroups.flatMap((g) => g.items)) {
      expect(icons, item.to).toHaveProperty(item.icon)
    }
    expect(shortcutRoutes(navigationGroups as NavigationGroup[])).toEqual({
      o: '/', a: '/attention', d: '/devices', s: '/software', v: '/vulnerabilities', l: '/audit',
    })
    expect(shortcutOf('/attention')).toBe('g a')
    expect(shortcutOf('/device-groups')).toBe('')
  })

  it('shows the attention pill in the app bar with a label, not a bare badge', async () => {
    const { w } = await mountApp()
    const pill = w.find('[data-testid="app-bar-attention"]')
    expect(pill.text()).toBe('3 need attention')
    expect(pill.attributes('href')).toBe('/attention')
    expect(pill.find('.pd-chip-dot').attributes('aria-hidden')).toBe('true')
    expect(w.find('.v-badge').exists()).toBe(false)
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
    expect(linkLabels(platform.w)).toEqual(['Overview', 'Organizations', 'Agent releases', 'IP allow list', 'Sessions'])
    expect(platform.w.find('[data-testid="app-bar-attention"]').exists()).toBe(false)
    expect(platform.w.find('[data-testid="org-name"]').exists()).toBe(false)
  })

  it('marks the current page with aria-current', async () => {
    const { w, router } = await mountApp(admin, '/managed-files')
    const current = () => drawer(w).findAll('[aria-current="page"]').map((a) => a.find('.pd-nav-label').text())
    expect(current()).toEqual(['Managed files'])
    await router.push('/settings/dms')
    await flushPromises()
    expect(current()).toEqual(["Dead man's switch"])
  })

  it('is one Tab stop with a roving tabindex: Up/Down move, Home/End jump', async () => {
    const { w } = await mountApp(admin, '/managed-files')
    const links = drawer(w).findAll('a.pd-nav-item')
    expect(links.length).toBe(22)
    const stops = links.filter((a) => a.attributes('tabindex') === '0')
    expect(stops.map((a) => a.attributes('href'))).toEqual(['/managed-files'])
    expect(links.filter((a) => a.attributes('tabindex') === '-1').length).toBe(21)

    ;(stops[0].element as HTMLElement).focus()
    await stops[0].trigger('keydown', { key: 'ArrowDown' })
    expect(document.activeElement?.getAttribute('href')).toBe('/managed-units')
    expect(drawer(w).find('a[href="/managed-units"]').attributes('tabindex')).toBe('0')
    expect(drawer(w).find('a[href="/managed-files"]').attributes('tabindex')).toBe('-1')
    await drawer(w).find('a[href="/managed-units"]').trigger('keydown', { key: 'End' })
    expect(document.activeElement?.getAttribute('href')).toBe('/audit')
    await drawer(w).find('a[href="/audit"]').trigger('keydown', { key: 'Home' })
    expect(document.activeElement?.getAttribute('href')).toBe('/')
    await drawer(w).find('a[href="/"]').trigger('keydown', { key: 'ArrowUp' })
    expect(document.activeElement?.getAttribute('href')).toBe('/audit')
  })

  it('collapses the drawer to a rail on wide screens and remembers it', async () => {
    const first = await mountApp()
    expect(drawer(first.w).classes()).not.toContain('v-navigation-drawer--temporary')
    expect(drawer(first.w).classes()).not.toContain('v-navigation-drawer--rail')
    const toggle = first.w.find('[data-testid="nav-toggle"]')
    expect(toggle.attributes('aria-label')).toBe('Collapse the navigation')
    expect(toggle.attributes('aria-expanded')).toBe('true')
    expect(toggle.attributes('aria-controls')).toBe('main-navigation')
    await toggle.trigger('click')
    expect(drawer(first.w).classes()).toContain('v-navigation-drawer--rail')
    expect(toggle.attributes('aria-label')).toBe('Expand the navigation')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    expect(localStorage.getItem('paddock.navigation.collapsed')).toBe('true')
    // Rail: icons with a label for assistive technology, group headers replaced by dividers.
    expect(drawer(first.w).find('a[href="/devices"]').attributes('aria-label')).toBe('Devices')
    expect(groupLabels(first.w)).toEqual([])
    expect(drawer(first.w).findAll('hr.pd-nav-divider').length).toBe(6)
    first.w.unmount()

    const second = await mountApp()
    expect(drawer(second.w).classes()).toContain('v-navigation-drawer--rail')
    await second.w.find('[data-testid="nav-toggle"]').trigger('click')
    expect(drawer(second.w).classes()).not.toContain('v-navigation-drawer--rail')
    expect(localStorage.getItem('paddock.navigation.collapsed')).toBe('false')
    // An entry chosen on a wide screen leaves the drawer as it is.
    await drawer(second.w).find('a[href="/software"]').trigger('click')
    await flushPromises()
    expect(drawer(second.w).classes()).toContain('v-navigation-drawer--active')
  })

  it('reads the hidden state of the old drawer once and removes it', async () => {
    localStorage.setItem('paddock.navigation.hidden', 'true')
    const { w } = await mountApp()
    expect(drawer(w).classes()).toContain('v-navigation-drawer--rail')
    expect(localStorage.getItem('paddock.navigation.hidden')).toBeNull()
    expect(localStorage.getItem('paddock.navigation.collapsed')).toBe('true')
  })

  it('starts expanded when the storage is unavailable', async () => {
    const get = vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    const set = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    try {
      const { w } = await mountApp()
      expect(drawer(w).classes()).not.toContain('v-navigation-drawer--rail')
      await w.find('[data-testid="nav-toggle"]').trigger('click')
      expect(drawer(w).classes()).toContain('v-navigation-drawer--rail')
    } finally {
      get.mockRestore()
      set.mockRestore()
    }
  })

  it('makes the drawer inert while a dialog is open', async () => {
    const { w } = await mountApp()
    // jsdom has no inert property, so Vue writes the bound value as an attribute.
    const inert = () => drawer(w).attributes('inert')
    expect(inert()).toBe('false')

    const answer = useConfirm()({ title: 'Delete device group', message: 'Delete Laptops?', confirmLabel: 'Delete' })
    await vi.waitFor(() => expect(inert()).toBe('true'))
    expect(w.find('header').attributes('inert')).toBe('true')

    settleConfirm(false)
    await answer
    await vi.waitFor(() => expect(inert()).toBe('false'))
  })

  it('starts as a rail between 600 and 1279 px and expands on request', async () => {
    resize(1279)
    const { w } = await mountApp()
    expect(drawer(w).classes()).toContain('v-navigation-drawer--rail')
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--temporary')
    const toggle = w.find('[data-testid="nav-toggle"]')
    expect(toggle.attributes('aria-label')).toBe('Show the navigation')
    expect(toggle.attributes('aria-expanded')).toBe('false')
    await toggle.trigger('click')
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--rail')
    expect(toggle.attributes('aria-label')).toBe('Hide the navigation')
    expect(localStorage.getItem('paddock.navigation.collapsed')).toBe('false')
  })

  it('is a temporary drawer behind a hamburger button below 600 px', async () => {
    resize(599)
    const { w, router } = await mountApp()
    const hamburger = w.find('[data-testid="nav-toggle"]')
    expect(hamburger.attributes('aria-label')).toBe('Show the navigation')
    expect(hamburger.attributes('aria-expanded')).toBe('false')
    expect(drawer(w).classes()).toContain('v-navigation-drawer--temporary')
    expect(drawer(w).attributes('inert')).toBeDefined()
    expect(w.find('[data-testid="command-field"]').exists()).toBe(false)
    expect(w.find('[data-testid="command-button"]').attributes('aria-label')).toBe('Search or run a command')

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
    expect(localStorage.getItem('paddock.navigation.collapsed')).toBeNull()

    resize(1280)
    await flushPromises()
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--temporary')
    expect(drawer(w).classes()).not.toContain('v-navigation-drawer--rail')
  })
})

describe('app bar', () => {
  it('offers the command field with its hint and opens the palette from it', async () => {
    const { w } = await mountApp()
    const field = w.find('[data-testid="command-field"]')
    expect(field.element.tagName).toBe('INPUT')
    expect(w.find('.pd-command .visually-hidden').text()).toBe('Search or run a command')
    expect(w.find('.pd-command kbd').text()).toBe('Ctrl K')
    await field.trigger('focus')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="command-palette"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="palette-input"]')?.getAttribute('role')).toBe('combobox')
  })

  it('stores the theme chosen with the toggle on the account', async () => {
    const { w } = await mountApp()
    const toggle = w.find('[data-testid="theme-toggle"]')
    expect(toggle.attributes('aria-label')).toBe('Switch to the dark theme')
    await toggle.trigger('click')
    await flushPromises()
    expect(patched).toEqual([{ theme: 'dark' }])
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(w.find('[data-testid="theme-toggle"]').attributes('aria-label')).toBe('Switch to the light theme')
  })

  it('offers theme, density and shortcut help in the user menu', async () => {
    const { w } = await mountApp()
    await w.find('[data-testid="user-menu"]').trigger('click')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="theme-menu"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="theme-menu"]')?.getAttribute('aria-label')).toBe('Choose the theme (current: System)')
    expect(document.querySelector('[data-testid="density-menu"]')?.textContent).toContain('Compact')
    expect(document.querySelector('[data-testid="shortcuts-help"]')?.textContent).toContain('Keyboard shortcuts')
    expect(document.querySelector('[data-testid="logout"]')).not.toBeNull()
    ;(document.querySelector('[data-testid="density-menu"]') as HTMLElement).click()
    await vi.waitFor(() => expect(document.querySelector('[data-testid="density-comfortable"]')).not.toBeNull())
    ;(document.querySelector('[data-testid="density-comfortable"]') as HTMLElement).click()
    await flushPromises()
    expect(localStorage.getItem('paddock.density')).toBe('comfortable')
    expect(document.documentElement.dataset.density).toBe('comfortable')
  })
})

describe('app bar: organization name and step-up freshness (plan M8x decisions 34 and 35)', () => {
  afterEach(() => vi.useRealTimers())

  it('names the whole organization name in the title of the shortened app bar entry', async () => {
    const long = 'Acme Corporation of Very Long Names and Subsidiaries Worldwide'
    const { w } = await mountApp({ ...admin, organization: { ...admin.organization!, name: long } })
    const name = w.get('[data-testid="org-name"]')
    expect(name.text()).toBe(long)
    expect(name.attributes('title')).toBe(long)
  })

  it('gives the organization name tooltip an accessible name before it is ever shown', async () => {
    const { w } = await mountApp()
    const describedBy = w.get('[data-testid="org-name"]').attributes('aria-describedby')
    const tooltip = document.getElementById(describedBy!)
    expect(tooltip?.getAttribute('role')).toBe('tooltip')
    expect(tooltip?.getAttribute('aria-label')).toBe('Acme')
  })

  it('shows no confirmation without a current step-up', async () => {
    const { w } = await mountApp()
    expect(w.find('[data-testid="stepup-chip"]').exists()).toBe(false)
    await w.get('[data-testid="user-menu"]').trigger('click')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="user-stepup"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="user-stepup"]')?.textContent?.trim()).toBe('No current identity confirmation')
  })

  it('shows the end of the step-up window and hides it at the expiry', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'Date'] })
    vi.setSystemTime(new Date('2026-10-17T10:00:00Z'))
    const until = '2026-10-17T10:00:05Z'
    const time = new Intl.DateTimeFormat('en', { timeStyle: 'short' }).format(new Date(until))
    expect(time).toMatch(/^\d{1,2}:\d{2}\s[AP]M$/)
    const { w } = await mountApp({ ...admin, step_up_valid_until: until })
    expect(w.get('[data-testid="stepup-chip"]').text()).toBe(`Confirmed until ${time}`)
    await w.get('[data-testid="user-menu"]').trigger('click')
    await vi.waitFor(() => expect(document.querySelector('[data-testid="user-stepup"]')).not.toBeNull())
    expect(document.querySelector('[data-testid="user-stepup"]')?.textContent?.trim()).toBe(`Identity confirmed until ${time}`)
    vi.advanceTimersByTime(6000)
    await flushPromises()
    expect(w.find('[data-testid="stepup-chip"]').exists()).toBe(false)
    expect(document.querySelector('[data-testid="user-stepup"]')?.textContent?.trim()).toBe('No current identity confirmation')
  })
})

describe('visibleNavigation', () => {
  const none: NavigationAccess = { isPlatform: false, canWrite: false, canDelete: false, canReadAudit: false, canReadGroups: false }

  it('leaves out groups without a visible entry', () => {
    expect(visibleNavigation(none).map((g) => g.key)).toEqual(['overview'])
  })
})
