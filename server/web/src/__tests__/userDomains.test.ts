import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import Users from '../views/Users.vue'
import UserDetail from '../views/UserDetail.vue'
import type { User } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const base = {
  display_name: 'U', email: '', source: 'synced' as const, locked: false, lock_incomplete: false, locked_at: null,
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const dave: User = { ...base, id: 'u1', username: 'dave@acme.test', domain_match: true }
const lab: User = { ...base, id: 'u2', username: 'lab1234', domain_match: false }

vi.mock('../lib/users', async (original) => ({
  ...(await original<typeof import('../lib/users')>()),
  listUsers: () => Promise.resolve({ items: [dave, lab], page: 1, page_size: 25, total: 2, total_capped: false, sort: 'username' }),
  getUser: (id: string) => Promise.resolve({ ...(id === 'u2' ? lab : dave), groups: [] }),
  getEffectiveProfile: () => Promise.resolve('not_found'),
}))
vi.mock('../lib/devices', async (original) => ({ ...(await original<typeof import('../lib/devices')>()), allDevices: () => Promise.resolve([]) }))
vi.mock('../lib/userGroups', async (original) => ({ ...(await original<typeof import('../lib/userGroups')>()), allUserGroups: () => Promise.resolve([]) }))

let wrapper: VueWrapper | null = null

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountAt(path: string, domains: string[]): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = {
    id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en',
    organization: { id: 'o', slug: 'acme', name: 'Acme', domains },
  } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/users', name: 'users', component: Users }, { path: '/users/:id', name: 'user', component: UserDetail },
      { path: '/user-groups/:id', name: 'user-group', component: { render: () => null } },
    ],
  })
  await router.push(path)
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }),
    { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('directory users without an organization domain (plan M8x decision 47)', () => {
  it('marks a user without an organization domain in the list', async () => {
    const w = await mountAt('/users', ['acme.test'])
    expect(w.find('[data-testid="no-domain-u2"]').text()).toBe('No organization domain')
    expect(w.find('[data-testid="no-domain-u1"]').exists()).toBe(false)
    expect(w.find('[data-testid="org-no-domains"]').exists()).toBe(false)
  })

  it('shows the banner when the organization has no domain', async () => {
    const w = await mountAt('/users', [])
    expect(w.get('[data-testid="org-no-domains"]').text()).toContain('This organization has no domain yet.')
  })

  it('explains the missing domain on the user page', async () => {
    const w = await mountAt('/users/u2', ['acme.test', 'corp.example'])
    expect(w.get('[data-testid="no-domain-detail"]').text()).toContain(
      "The username lab1234 does not end with one of the organization's domains (acme.test, corp.example).")
  })

  it('shows no alert for a user with an organization domain', async () => {
    const w = await mountAt('/users/u1', ['acme.test'])
    expect(w.find('[data-testid="no-domain-detail"]').exists()).toBe(false)
  })
})
