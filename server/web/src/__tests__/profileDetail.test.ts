import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import PermissionProfileDetail from '../views/PermissionProfileDetail.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import type { PermissionProfile } from '../api/client'

const legacy: PermissionProfile = {
  id: 'p1', name: 'legacy', class: 'restricted', commands: ['/usr/bin/journalctl', '/usr/bin/systemctl ^.*$'],
  require_password: true, timestamp_timeout_min: 5, lecture: 'once', root_equivalent: false, root_equivalent_commands: [],
  invalid_commands: ['/usr/bin/systemctl ^.*$'], created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
let profile = legacy

vi.mock('../lib/profiles', async (original) => ({
  ...(await original<typeof import('../lib/profiles')>()),
  getProfile: () => Promise.resolve(profile),
  listAssignments: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'created_at' }),
}))
vi.mock('../lib/devices', async (original) => ({ ...(await original<typeof import('../lib/devices')>()), allGroups: () => Promise.resolve([]) }))
vi.mock('../lib/userGroups', async (original) => ({ ...(await original<typeof import('../lib/userGroups')>()), allUserGroups: () => Promise.resolve([]) }))
vi.mock('../lib/users', async (original) => ({ ...(await original<typeof import('../lib/users')>()), allUsers: () => Promise.resolve([]) }))

let wrapper: VueWrapper | null = null

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountDetail(): Promise<VueWrapper> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/profiles/:id', name: 'permission-profile', component: PermissionProfileDetail },
      { path: '/profiles', name: 'permission-profiles', component: { render: () => null } },
    ],
  })
  await router.push('/profiles/p1')
  await router.isReady()
  const App = () => h(VApp, null, { default: () => h(RouterView) })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, createPinia()] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('PermissionProfileDetail', () => {
  it('reports a profile stored with commands that are no longer allowed (plan M3.1 decision 1)', async () => {
    profile = legacy
    const w = await mountDetail()
    expect(w.find('[data-testid="invalid-profile"]').text()).toContain('no longer allowed: /usr/bin/systemctl ^.*$.')
  })

  it('shows no report for a valid profile', async () => {
    profile = { ...legacy, commands: ['/usr/bin/journalctl'], invalid_commands: [] }
    const w = await mountDetail()
    expect(w.text()).toContain('legacy')
    expect(w.find('[data-testid="invalid-profile"]').exists()).toBe(false)
  })
})
