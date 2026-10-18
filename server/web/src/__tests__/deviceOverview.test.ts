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

vi.mock('../lib/inventory', async (original) => ({
  ...(await original<typeof import('../lib/inventory')>()),
  listDeviceVulnerabilities: () => () => Promise.resolve({ items: [], total: 0 }),
}))

const now = '2026-10-10T12:00:00Z'
const device = {
  id: 'd1', hostname: 'acme-lt-0142', state: 'active', contact: 'ok', hardware_uuid: null, machine_id: null,
  os_release: { VERSION_ID: '24.04' }, enrollment_token_id: null, enrolled_at: now, state_changed_at: now, bundle_version: 3,
  last_contact_at: now, applied_bundle_version: 3, agent_version: '1.9.1', groups: [], identity_keys: [], logins_suspended: false,
  login_assignment: { users: [], groups: [] }, schema_versions: [], login_management: true, login_status: { login: null, sudo: null },
  sudo_flavor: null, presumed_self_locked_at: null, presumed_lost_at: null, owners: [],
} as DeviceDetail

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountOverview() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null, revocation_enabled: true } as never
  const selectedGroups = ref<string[]>(['g1'])
  const saved = ref(false)
  const savedSelections: string[][] = []
  const saveGroups = vi.fn(async () => {
    savedSelections.push([...selectedGroups.value])
    saved.value = true
  })
  const page = {
    device: ref(device), groups: ref([{ id: 'g1', name: 'Laptops' }, { id: 'g2', name: 'Finance' }]), selectedGroups, saved,
    diskState: ref(null), updates: ref(null), conditions: ref([]), refresh: ref(0), actions: ref([]), saveGroups, changed: vi.fn(),
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
  return { saveGroups, savedSelections }
}

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
