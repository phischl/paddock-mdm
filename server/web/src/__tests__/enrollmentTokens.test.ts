import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import EnrollmentTokens from '../views/EnrollmentTokens.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

vi.mock('../lib/enrollmentTokens', async (original) => ({
  ...(await original<typeof import('../lib/enrollmentTokens')>()),
  listEnrollmentTokens: () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-created_at' }),
}))
vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  allGroups: () => Promise.resolve([]),
}))
vi.mock('../lib/loginSettings', async (original) => ({
  ...(await original<typeof import('../lib/loginSettings')>()),
  getLoginSettings: () => Promise.resolve({ local_admin_username: 'paddock-admin' }),
}))

let wrapper: VueWrapper | null = null

afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function openDialog(domains: string[]): Promise<HTMLElement> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = {
    id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en',
    organization: { id: 'o', slug: 'acme', name: 'Acme', domains },
  } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/enrollment-tokens', component: EnrollmentTokens },
      { path: '/settings/login', component: { render: () => null } },
    ],
  })
  await router.push('/enrollment-tokens')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }),
    { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  await wrapper.get('[data-testid="create-token"]').trigger('click')
  await flushPromises()
  const alert = document.querySelector<HTMLElement>('[data-testid="break-glass-guidance"]')
  if (!alert) throw new Error('no break-glass guidance in the dialog')
  return alert
}

describe('enrollment token dialog: break-glass guidance (plan M8x decision 14)', () => {
  it('warns when the organization has no domain', async () => {
    const alert = await openDialog([])
    expect(alert.textContent).toContain('This organization has no domain')
    expect(alert.querySelector('a')?.getAttribute('href')).toBe('/settings/login')
    expect(alert.querySelector('a')?.textContent?.trim()).toBe('Break-glass accounts')
  })

  it('names the managed local administrator when the organization has a domain', async () => {
    const alert = await openDialog(['acme.test'])
    expect(alert.textContent).toContain('keep only the managed local administrator (paddock-admin)')
    expect(alert.textContent).not.toContain('no domain')
    expect(alert.querySelector('a')?.getAttribute('href')).toBe('/settings/login')
  })
})
