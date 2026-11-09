import { afterEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { VApp } from 'vuetify/components'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import DeviceManagedSoftware from '../views/DeviceManagedSoftware.vue'
import type { DeviceManagedSoftware as Row } from '../api/client'

const rows: Row[] = [
  { catalog_entry_id: 'e1', name: 'Editor', package: 'nano', intent: 'required', state: 'installed', version: '7.2', reason: '', error: '', scope: 'system', reported_at: '2026-10-02T00:00:00Z' },
  { catalog_entry_id: 'e2', name: 'Chat', package: '', intent: 'required', state: 'not_applicable', version: '', reason: '', error: '', scope: 'system', reported_at: null },
  { catalog_entry_id: 'e3', name: 'Browser', package: 'browser', intent: 'forbid', state: 'unknown', version: '', reason: '', error: '', scope: 'system', reported_at: null },
  { catalog_entry_id: 'e4', name: 'Tool', package: 'tool', intent: 'required', state: 'failed', version: '', reason: 'no_candidate', error: 'E: no such package', scope: 'system', reported_at: '2026-10-02T00:00:00Z' },
]
const truncated = vi.hoisted(() => ({ value: false }))

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  listDeviceManagedSoftware: (_id: string, onTruncated: (v: boolean) => void) => () => {
    onTruncated(truncated.value)
    return Promise.resolve({ items: rows, page: 1, page_size: 25, total: rows.length, total_capped: false, sort: 'name' })
  },
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountTab(): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/devices/:id/managed-software', component: { render: () => null } },
      { path: '/software-catalog/:id', name: 'software-catalog-entry', component: { render: () => null } },
    ],
  })
  await router.push('/devices/d1/managed-software')
  wrapper = mount(() => h(VApp, null, { default: () => h(DeviceManagedSoftware) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

describe('DeviceManagedSoftware', () => {
  it('lists every row including the derived not_applicable and unknown states', async () => {
    truncated.value = false
    await mountTab()
    const text = document.body.textContent ?? ''
    for (const expected of ['Editor', 'Installed', 'Chat', 'Not applicable', 'Browser', 'No report yet', 'Failed']) expect(text).toContain(expected)
    expect(document.body.querySelector('[data-testid="managed-software-truncated"]')).toBeNull()
  })

  it('says so when the last report left items out', async () => {
    truncated.value = true
    await mountTab()
    expect(document.body.querySelector('[data-testid="managed-software-truncated"]')?.textContent).toContain('left some entries out')
  })
})
