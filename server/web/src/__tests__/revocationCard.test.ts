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
  {
    // A device that reports the same device twice must not break the list.
    ...base, id: 'r3', status: 'failed', result: {
      erased: false, slots_before: 2, slots_after: 0, unresolved: ['/etc/crypttab', '/etc/crypttab'], volumes: [
        { device: '/dev/sda3', slots_before: 1, slots_after: 0, erased: true },
        { device: '/dev/sda3', slots_before: 1, slots_after: 0, erased: true },
      ],
    },
  },
  { ...base, id: 'r2', status: 'confirmed', result: { erased: true, slots_before: 2, slots_after: 0 } },
  {
    // PDK-009: a Lock leaves the volumes without an escrowed header alone; it is complete all the same.
    ...base, id: 'r4', status: 'confirmed', result: {
      erased: true, slots_before: 2, slots_after: 0,
      volumes: [{ device: '/dev/sda3', uuid: '0d8f4c62-0000-4000-8000-0000000000aa', slots_before: 2, slots_after: 0, erased: true }],
      skipped_not_escrowed: [{ device: '/dev/sdb1', uuid: '0d8f4c62-0000-4000-8000-0000000000bb' }, { device: '/dev/sdc1' }, { bogus: 1 }],
    },
  },
]

vi.mock('../lib/revocations', async (original) => ({
  ...(await original<typeof import('../lib/revocations')>()),
  listRevocations: () => () => Promise.resolve({ items: requests, page: 1, page_size: 10, total: 3, total_capped: false, sort: '-requested_at' }),
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
    expect(lists).toHaveLength(3)
    expect([...lists[0].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sdb1: not erased, 3 keyslots left',
      '/dev/sdc1: not erased, the remaining keyslots are unknown',
      '/dev/sda3: 2 keyslots erased',
      'UUID=0000-gone: listed in /etc/crypttab but not erased with certainty',
    ])
    expect([...lists[1].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sda3: 1 keyslot erased', '/dev/sda3: 1 keyslot erased',
      '/etc/crypttab: listed in /etc/crypttab but not erased with certainty',
      '/etc/crypttab: listed in /etc/crypttab but not erased with certainty',
    ])
    expect([...lists[2].querySelectorAll('li')].map((li) => li.textContent?.trim())).toEqual([
      '/dev/sda3: 2 keyslots erased',
      '/dev/sdb1: not erased, its header was not escrowed (the volume stays readable)',
      '/dev/sdc1: not erased, its header was not escrowed (the volume stays readable)',
    ])
    // Both failed requests are marked incomplete; the M4c confirmation and the Lock with skipped volumes are not.
    const incomplete = [...document.querySelectorAll('p')].filter((p) => p.textContent?.includes('Incomplete: not every encrypted volume'))
    expect(incomplete).toHaveLength(2)
    wrapper.unmount()
  })
})
