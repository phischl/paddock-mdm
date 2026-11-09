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
import type { CompileWarning, SoftwareAssignment, SoftwareCatalogDevice, SoftwareCatalogEntry } from '../api/client'

const entry: SoftwareCatalogEntry = {
  id: 'e1', name: 'Editor', description: 'Text editor', category: 'Tools', source_id: null, source_slug: '', has_icon: false, approval: 'none',
  packages: [{ distribution: 'ubuntu', release: '*', architecture: '*', package: 'nano' }], assignment_count: 1,
  created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
}
const device = (over: Partial<SoftwareCatalogDevice>): SoftwareCatalogDevice => ({
  device_id: 'd1', hostname: 'lap-0421', name: '', device_group_ids: [], package: 'nano', intent: 'required', state: 'installed', version: '7.2',
  reason: '', error: '', scope: 'system', reported_at: '2026-10-02T00:00:00Z', ...over,
})
const setIcon = vi.hoisted(() => vi.fn())
const saveAssignment = vi.hoisted(() => vi.fn())
const deviceFetch = vi.hoisted(() => vi.fn())
const saveEntry = vi.hoisted(() => vi.fn())
const rows = [
  device({ name: 'Anna laptop' }), device({ device_id: 'd2', hostname: 'lap-0500' }), device({ device_id: 'd2', hostname: 'lap-0500', scope: 'user' }),
].map((d) => ({ ...d, row_key: d.device_id + ':' + d.scope }))
const assignment = (over: Partial<SoftwareAssignment>): SoftwareAssignment => ({
  id: 'a1', app_name: 'Editor', catalog_entry_id: 'e1', device_group_id: null, user_id: null, user_group_id: null, intent: 'available',
  update_rule: 'latest', version: null, reason: '', urgent: false, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', ...over,
})
const assignments = [
  assignment({ id: 'a1', user_id: 'u1' }), assignment({ id: 'a2', user_group_id: 'ug1' }), assignment({ id: 'a3', device_group_id: 'g1', intent: 'required' }),
  assignment({ id: 'a4', intent: 'forbid' }),
]
const warnings: CompileWarning[] = [
  { id: 'w1', device_id: 'd1', hostname: 'lap-0421', assignment_id: 'a2', catalog_entry_id: 'e1', code: 'audience_truncated', params: { users: 250, kept: 200 }, created_at: '2026-10-02T00:00:00Z' },
  { id: 'w2', device_id: 'd2', hostname: 'lap-0500', assignment_id: 'a1', catalog_entry_id: 'e1', code: 'flatpak_forbidden', params: { flatpak_ref: 'org.gimp.GIMP' }, created_at: '2026-10-02T00:00:00Z' },
]
const page = <T>(items: T[], sort: string) => Promise.resolve({ items, page: 1, page_size: 25, total: items.length, total_capped: false, sort })
const confirmed = vi.hoisted(() => ({ options: [] as { message: string }[] }))

vi.mock('../lib/software', async (original) => ({
  ...(await original<typeof import('../lib/software')>()),
  getCatalogEntry: () => Promise.resolve(entry),
  setCatalogIcon: setIcon,
  saveCatalogEntry: saveEntry,
  allSoftwareSources: () => Promise.resolve([]),
  listSoftwareAssignments: () => () => page(assignments, '-created_at'),
  allSoftwareAssignments: () => Promise.resolve(assignments),
  listCompileWarnings: () => () => page(warnings, '-created_at'),
  saveSoftwareAssignment: saveAssignment,
  listSoftwareCatalogDevices: () => () => {
    deviceFetch()
    return page(rows, 'hostname')
  },
}))
vi.mock('../lib/users', async (original) => ({
  ...(await original<typeof import('../lib/users')>()),
  allUsers: () => Promise.resolve([{ id: 'u1', username: 'alice@acme.test' }]),
}))
vi.mock('../lib/userGroups', async (original) => ({
  ...(await original<typeof import('../lib/userGroups')>()),
  allUserGroups: () => Promise.resolve([{ id: 'ug1', name: 'Designers' }]),
}))
vi.mock('../composables/useConfirm', async (original) => ({
  ...(await original<typeof import('../composables/useConfirm')>()),
  useConfirm: () => (options: { message: string }) => {
    confirmed.options.push(options)
    return Promise.resolve(false)
  },
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

  it('sends one request when the edit form is submitted twice while the save is pending', async () => {
    saveEntry.mockReset()
    let release: (v: string | null) => void = () => {}
    saveEntry.mockReturnValue(new Promise<string | null>((resolve) => { release = resolve }))
    await mountDetail('org_operator')
    ;(document.querySelector('[data-testid="edit-entry"]') as HTMLButtonElement).click()
    await flushPromises()
    const form = document.querySelector('[data-testid="save-entry"]')?.closest('form') as HTMLFormElement
    form.dispatchEvent(new Event('submit', { cancelable: true }))
    form.dispatchEvent(new Event('submit', { cancelable: true }))
    await flushPromises()
    expect(saveEntry).toHaveBeenCalledTimes(1)
    release(null)
    await flushPromises()
  })

  it('reloads the devices list after an assignment is saved', async () => {
    saveAssignment.mockReset()
    saveAssignment.mockResolvedValue(null)
    deviceFetch.mockReset()
    await mountDetail('org_operator')
    const before = deviceFetch.mock.calls.length
    ;(document.querySelector('[data-testid="create-assignment"]') as HTMLElement).click()
    await flushPromises()
    ;(document.querySelector('.v-dialog form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(saveAssignment).toHaveBeenCalledTimes(1)
    expect(deviceFetch.mock.calls.length).toBeGreaterThan(before)
  })

  it('lists a device once per scope with the scope column and filter (plan M13b decision 17)', async () => {
    await mountDetail('org_operator')
    const list = document.body.querySelector('[data-testid="catalog-device-list"]')
    expect(list?.querySelectorAll('tbody tr')).toHaveLength(3)
    expect(list?.textContent).toContain('System')
    expect(list?.textContent).toContain('User')
    expect(list?.textContent).toContain('Scope')
  })
})

describe('SoftwareCatalogDetail assignment targets (plan M13b decision 19)', () => {
  it('names every kind of target in the list and in the action labels', async () => {
    await mountDetail('org_operator')
    const list = document.body.querySelector('[data-testid="assignment-list"]')
    const text = list?.textContent ?? ''
    for (const expected of ['User alice@acme.test', 'User group Designers', 'Laptops', 'All devices', 'Available']) expect(text).toContain(expected)
    expect(list?.querySelector('[aria-label="Delete User group Designers"]')).not.toBeNull()
    expect(list?.querySelector('[aria-label="Edit User alice@acme.test"]')).not.toBeNull()
  })

  it('names the user group in the delete confirmation', async () => {
    confirmed.options.length = 0
    await mountDetail('org_operator')
    ;(document.body.querySelector('[aria-label="Delete User group Designers"]') as HTMLElement).click()
    await flushPromises()
    expect(confirmed.options[0].message).toContain('User group Designers')
  })

  it('shows the compile warnings of the entry localized, with the device and the assignment they concern', async () => {
    await mountDetail('org_auditor')
    const rowsShown = [...document.body.querySelectorAll('[data-testid="compile-warning-list"] tbody tr')].map((r) => r.textContent ?? '')
    expect(rowsShown).toHaveLength(2)
    expect(rowsShown[0]).toContain('lap-0421')
    expect(rowsShown[0]).toContain('offered to 250 users on this device; the configuration carries the first 200')
    expect(rowsShown[0]).toContain('User group Designers')
    expect(rowsShown[1]).toContain('org.gimp.GIMP is left out on this device')
    expect(rowsShown[1]).toContain('User alice@acme.test')
  })
})
