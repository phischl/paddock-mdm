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
const keyed = [...rows, { ...rows[0], scope: 'user' as const, state: 'pending' as const, reported_at: null }].map((r) => ({ ...r, row_key: r.catalog_entry_id + ':' + r.scope }))
const warnings = [
  { id: 'w1', device_id: 'd1', hostname: 'lap', assignment_id: 'a1', catalog_entry_id: 'e5', code: 'flatpak_users_truncated', params: { users: 230, kept: 200, flatpak_ref: 'org.gimp.GIMP' }, created_at: '2026-10-02T00:00:00Z' },
  { id: 'w2', device_id: 'd1', hostname: 'lap', assignment_id: null, catalog_entry_id: null, code: 'brand_new', params: {}, created_at: '2026-10-02T00:00:00Z' },
]
const warningFilter = vi.hoisted(() => ({ value: {} as unknown }))
const truncated = vi.hoisted(() => ({ value: false }))

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  listDeviceManagedSoftware: (_id: string, onTruncated: (v: boolean) => void) => () => {
    onTruncated(truncated.value)
    return Promise.resolve({ items: keyed, page: 1, page_size: 25, total: keyed.length, total_capped: false, sort: 'name' })
  },
  listCompileWarnings: (filter: unknown) => () => {
    warningFilter.value = filter
    return Promise.resolve({ items: warnings, page: 1, page_size: 25, total: warnings.length, total_capped: false, sort: '-created_at' })
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

  it('shows the system and the user-scope row of an entry with their scope', async () => {
    truncated.value = false
    await mountTab()
    const editor = [...document.body.querySelectorAll('[data-testid="managed-software-list"] tbody tr')].filter((r) => r.textContent?.includes('Editor'))
    expect(editor.map((r) => r.textContent)).toEqual([expect.stringContaining('System'), expect.stringContaining('User')])
  })

  it('shows the compile warnings of the device localized, an unknown code with its code', async () => {
    truncated.value = false
    await mountTab()
    expect(warningFilter.value).toEqual({ deviceID: 'd1' })
    const shown = document.body.querySelector('[data-testid="device-compile-warning-list"]')?.textContent ?? ''
    expect(shown).toContain('org.gimp.GIMP targets 230 users on this device; the configuration carries the first 200 by user name.')
    expect(shown).toContain('The server shortened the configuration of this device (brand_new).')
    expect(shown).toContain('Open the application')
  })
})
