import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h, provide, ref } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DeviceDetail } from '../api/client'
import { createPortalI18n } from '../i18n'
import { deviceDetailKey, type DevicePage } from '../lib/deviceDetailPage'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import DeviceOverview from '../views/DeviceOverview.vue'

const setDeviceName = vi.hoisted(() => vi.fn())
vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  setDeviceName,
}))

vi.mock('../lib/inventory', async (original) => ({
  ...(await original<typeof import('../lib/inventory')>()),
  listDeviceVulnerabilities: () => () => Promise.resolve({ items: [], total: 0 }),
}))

const now = '2026-10-10T12:00:00Z'
const device = {
  id: 'd1', hostname: 'acme-lt-0142', name: null, name_state: 'unmanaged', state: 'active', contact: 'ok',
  hardware_uuid: null, machine_id: null,
  os_release: { VERSION_ID: '24.04' }, enrollment_token_id: null, enrolled_at: now, state_changed_at: now, bundle_version: 3,
  last_contact_at: now, applied_bundle_version: 3, agent_version: '1.9.1', groups: [], identity_keys: [], logins_suspended: false,
  login_assignment: { users: [], groups: [] }, schema_versions: [], login_management: true, login_status: { login: null, sudo: null },
  sudo_flavor: null, presumed_self_locked_at: null, presumed_lost_at: null, owners: [], hardware: null, components: [], components_outdated: [],
} as DeviceDetail

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  setDeviceName.mockReset()
})

async function mountOverview(opts: { device?: Partial<DeviceDetail>; role?: string } = {}) {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: opts.role ?? 'org_admin', locale: 'en', theme: 'system', organization: null, revocation_enabled: true } as never
  const selectedGroups = ref<string[]>(['g1'])
  const saved = ref(false)
  const savedSelections: string[][] = []
  const saveGroups = vi.fn(async () => {
    savedSelections.push([...selectedGroups.value])
    saved.value = true
  })
  const page = {
    device: ref({ ...device, ...opts.device }), groups: ref([{ id: 'g1', name: 'Laptops' }, { id: 'g2', name: 'Finance' }]), selectedGroups, saved,
    diskState: ref(null), diskTpm: ref(false), updates: ref(null), conditions: ref([]), refresh: ref(0), actions: ref([]), saveGroups, changed: vi.fn(),
    run: vi.fn(),
  } as unknown as DevicePage
  const Frame = defineComponent({
    setup() {
      provide(deviceDetailKey, page)
      return () => h(VApp, null, { default: () => h(DeviceOverview) })
    },
  })
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/', component: { render: () => null } }] })
  await router.push('/')
  wrapper = mount(Frame, {
    global: {
      plugins: [createPortalI18n(), vuetify, router, pinia],
      stubs: { DiskEncryptionCard: true, UpdatesCard: true, LocalAdminCard: true, DangerZone: true },
    },
    attachTo: document.body,
  })
  await flushPromises()
  return { saveGroups, savedSelections, page }
}

describe('device overview hardware (PDK-221)', () => {
  it('shows the hardware facts in the identity panel with GiB and GB', async () => {
    await mountOverview({ device: {
      hardware: { vendor: 'LENOVO', model: '21HD003LGE', serial: 'PF4XK2QZ', cpu_brand: 'i7-1365U', cpu_cores: 10,
        memory_bytes: 33328349184, disk_total_bytes: 510440000000 },
    } })
    const value = (key: string) => document.querySelector(`[data-testid="hardware-${key}"] dd`)?.textContent?.trim()
    expect(value('manufacturer')).toBe('LENOVO')
    expect(value('serial')).toBe('PF4XK2QZ')
    expect(value('cpu')).toBe('i7-1365U (10 cores)')
    expect(value('memory')).toBe('31.0 GiB')
    expect(value('disk')).toBe('510.4 GB')
  })

  it('shows a dash while the inventory has not reported the device', async () => {
    await mountOverview()
    const cell = document.querySelector('[data-testid="hardware-serial"] dd')
    expect(cell?.textContent?.trim()).toBe('–')
    expect(cell?.getAttribute('title')).toBe('Not reported by the inventory yet')
  })
})

describe('device overview groups', () => {
  it('saves the group picked last when Save is clicked right after picking it, without leaving the field', async () => {
    const { saveGroups, savedSelections } = await mountOverview()
    const field = document.querySelector('[data-testid="device-groups"] input[role="combobox"]') as HTMLInputElement
    field.focus()
    field.value = 'Fin'
    field.dispatchEvent(new Event('input'))
    const finance = () => [...document.querySelectorAll<HTMLElement>('[role="option"]')].find((o) => o.textContent?.includes('Finance'))
    await vi.waitFor(() => expect(finance()).toBeTruthy())
    const option = finance()!
    option.click()
    await flushPromises()
    ;(document.querySelector('[data-testid="save-device-groups"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(saveGroups).toHaveBeenCalledTimes(1)
    expect(savedSelections).toEqual([['g1', 'g2']])
    expect(document.querySelector('[role="status"]')?.textContent).toBe('Device groups saved.')
  })
})

describe('device overview components (PDK-236)', () => {
  it('lists every component with installed and expected version, its status and the hint', async () => {
    await mountOverview({ device: {
      components: [
        { name: 'paddockd', installed: '0.1.0', expected: '0.1.0', status: 'ok' },
        { name: 'paddock_supervisor', installed: '0.1.0', expected: '0.1.0', status: 'ok' },
        { name: 'paddock_revoke', installed: '', expected: null, status: 'missing' },
        { name: 'himmelblau', installed: '4.0.3-1', expected: '4.0.4', status: 'outdated' },
        { name: 'fleetd', installed: '', expected: '1.43.0', status: 'missing' },
      ],
    } })
    const cells = (name: string) => {
      const item = document.querySelector(`[data-testid="component-${name}"]`)
      const text = (id: string) => item?.querySelector(`[data-testid="${id}"]`)?.textContent?.trim()
      return [text('component-name'), text('component-installed'), text('component-expected'), item?.querySelector('.pd-chip')?.textContent?.trim()]
    }
    expect(cells('paddockd')).toEqual(['Agent (paddockd)', '0.1.0', '0.1.0', 'Up to date'])
    expect(cells('paddock_revoke')).toEqual(['Revocation module (paddock-revoke)', '–', '–', 'Not installed'])
    expect(cells('himmelblau')).toEqual(['Himmelblau', '4.0.3-1', '4.0.4', 'Outdated'])
    expect(cells('fleetd')).toEqual(['fleetd (osquery)', '–', '1.43.0', 'Not installed'])
    const labels = [...document.querySelectorAll('[data-testid="component-himmelblau"] dt')].map((dt) => dt.textContent?.trim())
    expect(labels).toEqual(['Installed', 'Expected'])
    expect(document.querySelector('[data-testid="device-components"]')?.textContent)
      .toContain('Expected versions come from the current agent release')
    expect(document.querySelector('[data-testid="components-target-hint"]')?.textContent)
      .toContain('a component newer than its target counts as up to date')
  })

  it('shows Not reported for an agent that reports no components', async () => {
    await mountOverview({ device: {
      components: ['paddockd', 'paddock_supervisor', 'paddock_revoke', 'himmelblau', 'fleetd'].map((name) => ({
        name: name as 'paddockd', installed: '', expected: null, status: 'unknown' as const,
      })),
    } })
    const statuses = [...document.querySelectorAll('[data-testid="device-components"] li .pd-chip')].map((c) => c.textContent?.trim())
    expect(statuses).toEqual(['Not reported', 'Not reported', 'Not reported', 'Not reported', 'Not reported'])
  })

  // Browser check M8d defect 1: the four-column table overflowed the side column and needed a focusable scroll region.
  it('renders the components as a list without a table, a scroll region or a repeated panel title', async () => {
    await mountOverview({ device: {
      components: [{ name: 'himmelblau', installed: '4.0.3-1', expected: '4.0.4', status: 'outdated' }],
    } })
    const panel = document.querySelector('[data-testid="device-components"]')!
    expect(panel.querySelector('table, .v-table, .v-table__wrapper, [role="table"], th')).toBeNull()
    expect(panel.querySelectorAll('ul.pd-components > li')).toHaveLength(1)
    const titles = [...panel.querySelectorAll('*')].filter((el) => el.children.length === 0 && el.textContent?.trim() === 'Components')
    expect(titles).toHaveLength(1)
    expect(titles[0].tagName).toBe('H2')
  })
})

const panel = () => document.querySelector('[data-testid="device-name-panel"]') as HTMLElement
const nameField = () => panel().querySelector('input') as HTMLInputElement | null
const stateLine = () => panel().querySelector('[data-testid="device-name-state"]')?.textContent?.trim()
const button = (testid: string) => panel().querySelector(`[data-testid="${testid}"]`) as HTMLButtonElement | null

async function type(value: string): Promise<void> {
  const field = nameField()!
  field.value = value
  field.dispatchEvent(new Event('input'))
  await flushPromises()
}

describe('device name panel', () => {
  it('names an unmanaged device and shows it as pending', async () => {
    const { page } = await mountOverview()
    expect(stateLine()).toBe('Not managed: the device keeps its own hostname.')
    expect(nameField()!.value).toBe('')
    expect(nameField()!.getAttribute('autocapitalize')).toBe('off')
    expect(nameField()!.getAttribute('maxlength')).toBe('63')
    expect(button('save-device-name')!.disabled).toBe(true)
    expect(button('clear-device-name')).toBeNull()
    await type('lap-0421')
    expect(button('save-device-name')!.disabled).toBe(false)
    setDeviceName.mockResolvedValue({ ...device, name: 'lap-0421', name_state: 'pending' })
    button('save-device-name')!.click()
    await flushPromises()
    expect(setDeviceName).toHaveBeenCalledWith('d1', 'lap-0421')
    expect(page.device.value?.name).toBe('lap-0421')
    expect(nameField()!.value).toBe('lap-0421')
    expect(stateLine()).toBe('Pending: the device still reports acme-lt-0142.')
    expect(panel().querySelector('[role="status"]')?.textContent).toBe('Device name saved.')
  })

  it('clears an applied name without a confirmation', async () => {
    await mountOverview({ device: { hostname: 'lap-0421', name: 'lap-0421', name_state: 'applied' } })
    expect(stateLine()).toBe('Applied: the device reports this name.')
    setDeviceName.mockResolvedValue({ ...device, hostname: 'lap-0421', name: null, name_state: 'unmanaged' })
    button('clear-device-name')!.click()
    await flushPromises()
    expect(setDeviceName).toHaveBeenCalledWith('d1', null)
    expect(document.querySelector('[role="dialog"]')).toBeNull()
    expect(stateLine()).toBe('Not managed: the device keeps its own hostname.')
    expect(button('clear-device-name')).toBeNull()
  })

  it('shows the server detail of a 400 and the conflict message of a 409 and keeps the typed value', async () => {
    await mountOverview()
    await type('A1')
    setDeviceName.mockResolvedValue({ problem: 'invalid_request', detail: 'name must be a lowercase host name label' })
    button('save-device-name')!.click()
    await flushPromises()
    expect(panel().textContent).toContain('name must be a lowercase host name label')
    expect(nameField()!.value).toBe('A1')
    await type('lap-0421')
    setDeviceName.mockResolvedValue({ problem: 'conflict', detail: 'name is used by another device of this organization' })
    button('save-device-name')!.click()
    await flushPromises()
    expect(panel().textContent).toContain('Another device of this organization already has this name.')
    expect(nameField()!.value).toBe('lap-0421')
    expect(panel().querySelector('[role="status"]')).toBeNull()
  })

  it('shows the state without a form to an auditor', async () => {
    await mountOverview({ role: 'org_auditor', device: { name: 'lap-0421', name_state: 'pending' } })
    expect(stateLine()).toBe('Pending: the device still reports acme-lt-0142.')
    expect(nameField()).toBeNull()
    expect(button('save-device-name')).toBeNull()
    expect(button('clear-device-name')).toBeNull()
  })
})
