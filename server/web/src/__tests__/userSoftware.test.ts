import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import UserDetail from '../views/UserDetail.vue'
import type { UserSoftware } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const items: UserSoftware[] = [
  { assignment_id: 'a1', catalog_entry_id: 'e1', name: 'GIMP', intent: 'available', user_group_id: 'ug1', user_group_name: 'Designers', reason: '' },
  { assignment_id: 'a2', catalog_entry_id: 'e2', name: 'Editor', intent: 'required', user_group_id: null, user_group_name: '', reason: 'Team standard' },
]
const requested = vi.hoisted(() => ({ users: [] as string[], params: [] as Record<string, unknown>[] }))

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  listUserSoftware: (id: string) => (p: Record<string, unknown>) => {
    requested.users.push(id)
    requested.params.push(p)
    return Promise.resolve({ items, page: 1, page_size: 25, total: items.length, total_capped: false, sort: 'name' })
  },
}))
vi.mock('../lib/users', async (original) => ({
  ...(await original<typeof import('../lib/users')>()),
  getUser: () => Promise.resolve({
    id: 'u1', username: 'dave@acme.test', display_name: 'Dave', email: '', source: 'local', locked: false, lock_incomplete: false,
    locked_at: null, domain_match: true, groups: [], created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
  }),
  getEffectiveProfile: () => Promise.resolve('not_found'),
  listOwnedDevices: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'hostname' }),
}))
vi.mock('../lib/devices', async (original) => ({ ...(await original<typeof import('../lib/devices')>()), allDevices: () => Promise.resolve([]) }))
vi.mock('../lib/userGroups', async (original) => ({ ...(await original<typeof import('../lib/userGroups')>()), allUserGroups: () => Promise.resolve([]) }))

let wrapper: VueWrapper | null = null
let router: Router

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountAt(path: string, role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/users/:id', name: 'user', component: UserDetail },
      { path: '/users', name: 'users', component: { render: () => null } },
      { path: '/user-groups/:id', name: 'user-group', component: { render: () => null } },
      { path: '/software-catalog/:id', name: 'software-catalog-entry', component: { render: () => null } },
      { path: '/devices/:id', name: 'device', component: { render: () => null } },
    ],
  })
  await router.push(path)
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

function rows(): HTMLElement[] {
  return [...document.body.querySelectorAll<HTMLElement>('[data-testid="user-software"] tbody tr')]
}

describe('the Software section of a user (plan M13b decision 19)', () => {
  it.each(['org_operator', 'org_auditor'])('lists direct and group assignments for %s, read-only', async (role) => {
    await mountAt('/users/u1', role)
    expect(requested.users.at(-1)).toBe('u1')
    const [gimp, editor] = rows()
    expect(gimp.textContent).toContain('Available')
    expect(gimp.querySelector('a[href="/user-groups/ug1"]')?.textContent).toContain('Designers')
    expect(gimp.querySelector('a[href="/software-catalog/e1"]')?.textContent).toContain('GIMP')
    expect(editor.textContent).toContain('Directly')
    expect(editor.textContent).toContain('Team standard')
    expect(document.body.querySelector('[data-testid="user-software"] button[aria-label^="Delete"]')).toBeNull()
  })

  it('reads its list state from its own prefix of the URL query', async () => {
    await mountAt('/users/u1?s.sort=-intent&s.intent=available&s.q=gi', 'org_operator')
    expect(requested.params.at(-1)).toMatchObject({ sort: '-intent', intent: ['available'], q: 'gi' })
  })
})
