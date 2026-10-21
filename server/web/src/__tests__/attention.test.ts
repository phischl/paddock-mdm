import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { AttentionDevice } from '../api/client'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import AttentionView from '../views/Attention.vue'

const queries: unknown[] = []
const item: AttentionDevice = {
  device_id: 'd1', hostname: 'acme-lt-0142', state: 'active', os_release: { VERSION_ID: '24.04' }, last_contact_at: null,
  severity: 'critical', since: '2026-10-09T10:00:00Z',
  conditions: [
    { kind: 'presumed_lost', since: '2026-10-09T10:00:00Z', detail: '' },
    { kind: 'stale_critical', since: '2026-10-08T10:00:00Z', detail: '' },
    { kind: 'disk_not_compliant', since: '2026-10-08T10:00:00Z', detail: 'not_encrypted' },
    { kind: 'agent_outdated', since: '2026-10-08T10:00:00Z', detail: '' },
  ],
}
let items: AttentionDevice[] = [item]
vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  listAttentionDevices: (p: unknown) => {
    queries.push(p)
    return Promise.resolve({ items, page: 1, page_size: 25, total: items.length, total_capped: false, sort: '-severity' })
  },
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  items = [item]
  queries.length = 0
})

async function mountAttention(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const stub = { render: () => null }
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/attention', component: stub }, { path: '/devices/:id', name: 'device', component: stub }] })
  await router.push('/attention')
  wrapper = mount(() => h(VApp, null, { default: () => h(AttentionView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

describe('attention page grouped by device (plan M7c decision 33)', () => {
  it('lists a device once with its conditions most severe first, at most three plus +n, and one action', async () => {
    const w = await mountAttention()
    expect(queries[0]).toMatchObject({ sort: '-severity' })
    const rows = w.findAll('[data-testid="attention-list"] tbody tr')
    expect(rows).toHaveLength(1)
    expect(rows[0].find('a.mono').text()).toBe('acme-lt-0142')
    const chips = rows[0].findAll('.pd-chip')
    expect(chips.map((c) => c.text())).toEqual(['Presumed lost', 'Silent (critical)', 'Disk encryption not compliant', '+1'])
    expect(chips[2].attributes('title')).toBe('not_encrypted')
    expect(chips[3].attributes('title')).toBe('Agent outdated')
    expect(rows[0].findAll('a.v-btn').map((b) => b.text())).toEqual(['Retire, lock or keep'])
    expect(rows[0].text()).toContain('never')
  })

  it('labels a failed in-place encryption with its stage and reason (plan M8e decision 25)', async () => {
    items = [{ ...item, severity: 'warn', conditions: [{ kind: 'disk_conversion_failed', since: '2026-10-21T10:00:00Z', detail: 'init:on_battery' }] }]
    const w = await mountAttention()
    const chip = w.find('[data-testid="attention-list"] tbody tr .pd-chip')
    expect(chip.text()).toBe('In-place encryption failed')
    expect(chip.attributes('title')).toBe('init:on_battery')
  })

  it('explains the empty list', async () => {
    items = []
    const w = await mountAttention()
    expect(w.text()).toContain('Nothing needs attention')
  })
})
