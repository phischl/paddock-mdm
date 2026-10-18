import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { Device } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import Devices from '../views/Devices.vue'

const now = '2026-10-10T12:00:00Z'
const base = {
  state: 'active', contact: 'ok', hardware_uuid: null, machine_id: null, os_release: {}, enrollment_token_id: null,
  enrolled_at: now, state_changed_at: now, bundle_version: 1, last_contact_at: now, applied_bundle_version: 1, agent_version: '1.0.0',
}
const items = [
  { ...base, id: 'd1', hostname: 'ubuntu', name: 'lap-0421', name_state: 'pending' },
  { ...base, id: 'd2', hostname: 'lap-0422', name: 'lap-0422', name_state: 'applied' },
  { ...base, id: 'd3', hostname: 'desk-07', name: null, name_state: 'unmanaged' },
] as Device[]

vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  allGroups: () => Promise.resolve([]),
  listDevices: () => Promise.resolve({ items, page: 1, page_size: 25, total: 3, total_capped: false, sort: 'hostname' }),
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

describe('device list', () => {
  it('marks a device whose managed name is pending, with the name as tooltip (plan M8h decision 18)', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null } as never
    const empty = { render: () => null }
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/devices', name: 'devices', component: Devices },
        { path: '/devices/:id', name: 'device', component: empty },
        { path: '/enrollment-tokens', name: 'enrollment-tokens', component: empty },
      ],
    })
    await router.push('/devices')
    await router.isReady()
    const App = () => h(VApp, null, { default: () => h(RouterView) })
    wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
    await flushPromises()
    const chips = [...document.querySelectorAll<HTMLElement>('[data-testid="device-name-pending"]')]
    expect(chips).toHaveLength(1)
    expect(chips[0].textContent?.trim()).toBe('Name pending')
    expect(chips[0].getAttribute('title')).toBe('Managed name: lap-0421')
    expect(chips[0].closest('tr')?.textContent).toContain('ubuntu')
  })
})
