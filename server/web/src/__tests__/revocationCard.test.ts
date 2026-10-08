import { describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { RevocationRequest } from '../api/client'
import RevocationCard from '../components/RevocationCard.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const base = {
  device_id: 'd1', hostname: 'lt-1', action: 'lock' as const, requested_at: '2026-10-07T10:00:00Z', reason: '',
  approvals: [], confirmed_at: '2026-10-07T10:01:03Z',
}
const requests: RevocationRequest[] = [
  {
    ...base, id: 'r1', status: 'failed', result: {
      erased: false, slots_before: 5, slots_after: 3, unresolved: ['UUID=0000-gone'], volumes: [
        { device: '/dev/sdb1', slots_before: 3, slots_after: 3, erased: false },
        { device: '/dev/sdc1', slots_before: 1, slots_after: -1, erased: false },
        { device: '/dev/sda3', slots_before: 2, slots_after: 0, erased: true },
      ],
    },
  },
  { ...base, id: 'r2', status: 'confirmed', result: { erased: true, slots_before: 2, slots_after: 0 } },
]

vi.mock('../lib/revocations', async (original) => ({
  ...(await original<typeof import('../lib/revocations')>()),
  listRevocations: () => () => Promise.resolve({ items: requests, page: 1, page_size: 10, total: 2, total_capped: false, sort: '-requested_at' }),
}))

describe('revocation card', () => {
  it('lists the erasure of every volume and the unresolved crypttab entries (plan M4c.1 decision 4)', async () => {
    const pinia = createPinia()
    setActivePinia(pinia)
    useSessionStore().me = {
      id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null, revocation_enabled: true,
    } as never
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id', component: { render: () => null } }] })
    await router.push('/devices/d1')
    const App = () => h(VApp, null, {
      default: () => h(RevocationCard, { deviceId: 'd1', hostname: 'lt-1', revocable: true, presumedSelfLockedAt: null }),
    })
    const wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
    await flushPromises()
    const lists = document.querySelectorAll('[aria-label="Encrypted volumes"]')
    // A confirmation from before M4c.1 has no volumes and shows no list.
    expect(lists).toHaveLength(1)
    expect([...lists[0].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sdb1: not erased, 3 keyslots left',
      '/dev/sdc1: not erased, the remaining keyslots are unknown',
      '/dev/sda3: 2 keyslots erased',
      'UUID=0000-gone: listed in /etc/crypttab but not found on the device, not erased',
    ])
    wrapper.unmount()
  })
})
