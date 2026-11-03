import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import SoftwareCatalogDetail from '../views/SoftwareCatalogDetail.vue'
import { useSessionStore } from '../stores/session'
import type { SoftwareCatalogDevice, SoftwareCatalogEntry } from '../api/client'

const entry: SoftwareCatalogEntry = {
  id: 'e1', name: 'Editor', description: 'Text editor', category: 'Tools', source_id: null, source_slug: '', has_icon: false,
  packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', package: 'nano' }], assignment_count: 1,
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const device = (over: Partial<SoftwareCatalogDevice>): SoftwareCatalogDevice => ({
  device_id: 'd1', hostname: 'lap-0421', name: '', device_group_ids: [], package: 'nano', intent: 'required', state: 'installed', version: '7.2',
  reason: '', error: '', reported_at: '2026-10-02T00:00:00Z', ...over,
})
const setIcon = vi.hoisted(() => vi.fn())
const rows = [device({ name: 'Anna laptop' }), device({ device_id: 'd2', hostname: 'lap-0500' })]

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  getCatalogEntry: () => Promise.resolve(entry),
  setCatalogIcon: setIcon,
  allSoftwareSources: () => Promise.resolve([]),
  listSoftwareAssignments: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: '-created_at' }),
  listSoftwareCatalogDevices: () => () => Promise.resolve({ items: rows, page: 1, page_size: 25, total: 2, total_capped: false, sort: 'hostname' }),
}))
vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  allGroups: () => Promise.resolve([{ id: 'g1', name: 'Laptops' }]),
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountDetail(role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/software-catalog/:id', name: 'software-catalog-entry', component: { render: () => null } },
      { path: '/software-catalog', name: 'software-catalog', component: { render: () => null } },
      { path: '/devices/:id/managed-software', name: 'device-managed-software', component: { render: () => null } },
    ],
  })
  await router.push('/software-catalog/e1')
  wrapper = mount(() => h(VApp, null, { default: () => h(SoftwareCatalogDetail) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

describe('SoftwareCatalogDetail devices list', () => {
  it('shows the device name and falls back to the hostname, with state chips and a device group filter', async () => {
    await mountDetail('org_operator')
    const list = document.body.querySelector('[data-testid="catalog-device-list"]')?.textContent ?? ''
    expect(list).toContain('Anna laptop')
    expect(list).toContain('lap-0500')
    expect(list).toContain('Installed')
    expect(list).toContain('Device group')
  })

  it('offers no write control to an auditor', async () => {
    await mountDetail('org_auditor')
    expect(document.body.querySelector('[data-testid="edit-entry"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="delete-entry"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="create-assignment"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="icon-file"]')).toBeNull()
    expect(document.body.textContent).toContain('Editor')
  })

  async function pick(file: File): Promise<void> {
    const input = document.querySelector('[data-testid="icon-file"]') as HTMLInputElement
    Object.defineProperty(input, 'files', { value: [file], configurable: true })
    input.dispatchEvent(new Event('change'))
    await flushPromises()
  }

  it('refuses a non-PNG icon with the error text and sends nothing', async () => {
    setIcon.mockReset()
    await mountDetail('org_operator')
    await pick(new File(['x'], 'icon.jpg', { type: 'image/jpeg' }))
    expect(document.querySelector('[data-testid="icon-error"]')?.textContent).toContain('The icon must be a PNG file.')
    expect(setIcon).not.toHaveBeenCalled()
  })

  it('shows the problem text when the server refuses the icon', async () => {
    setIcon.mockReset()
    setIcon.mockResolvedValue('invalid_request')
    await mountDetail('org_operator')
    await pick(new File(['x'], 'icon.png', { type: 'image/png' }))
    expect(setIcon).toHaveBeenCalledTimes(1)
    expect(document.querySelector('[data-testid="icon-error"]')?.textContent).toContain('The request was not valid.')
  })
})
