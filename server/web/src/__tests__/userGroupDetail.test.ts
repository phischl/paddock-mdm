import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import UserGroupDetail from '../views/UserGroupDetail.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const addMember = vi.fn<(group: string, user: string) => Promise<string | null>>()
vi.mock('../lib/userGroups', async (original) => ({
  ...(await original<typeof import('../lib/userGroups')>()),
  getUserGroup: () => Promise.resolve({ id: 'g1', slug: 'ops', name: 'Ops', source: 'local', authentik_name: 'x', members: 0 }),
  addMember: (group: string, user: string) => addMember(group, user),
}))
vi.mock('../lib/users', async (original) => ({
  ...(await original<typeof import('../lib/users')>()),
  allUsers: () => Promise.resolve([]),
  listGroupMembers: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'username' }),
}))

let wrapper: VueWrapper | null = null

beforeEach(() => {
  sessionStorage.clear()
  addMember.mockReset()
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountDetail(search: string): Promise<VueWrapper> {
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign: vi.fn(), href: 'https://admin.test/user-groups/g1' + search, search }, writable: true,
  })
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: '/user-groups/:id', name: 'user-group', component: UserGroupDetail },
    { path: '/user-groups', name: 'user-groups', component: { render: () => null } },
  ] })
  await router.push('/user-groups/g1')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('UserGroupDetail (plan M8s decision 7g)', () => {
  it('repeats a membership the server refused with step_up_required once after the step-up', async () => {
    addMember.mockResolvedValueOnce(null)
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'group-member-add', target: 'g1', payload: 'u1', at: Date.now() }))
    await mountDetail('')
    expect(addMember).toHaveBeenCalledWith('g1', 'u1')
    expect(sessionStorage.getItem('paddock.stepup')).toBeNull()
  })

  it('reports a refused step-up and does not add the member', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'group-member-add', target: 'g1', payload: 'u1', at: Date.now() }))
    const w = await mountDetail('?stepup=failed')
    expect(addMember).not.toHaveBeenCalled()
    expect(w.text()).toContain('identity confirmation failed')
  })
})
