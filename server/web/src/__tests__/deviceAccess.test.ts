import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h, provide, ref } from 'vue'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DeviceDetail } from '../api/client'
import { createPortalI18n } from '../i18n'
import { deviceDetailKey, type DevicePage } from '../lib/deviceDetailPage'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import DeviceAccess from '../views/DeviceAccess.vue'

const now = '2026-10-10T12:00:00Z'
const device = {
  id: 'd1', hostname: 'acme-lt-0142', state: 'active', contact: 'ok', hardware_uuid: null, machine_id: null,
  os_release: { VERSION_ID: '24.04' }, enrollment_token_id: null, enrolled_at: now, state_changed_at: now, bundle_version: 3,
  last_contact_at: now, applied_bundle_version: 3, agent_version: '1.9.1', groups: [], identity_keys: [], logins_suspended: false,
  login_assignment: { users: [], groups: [] }, schema_versions: [], login_management: true, login_status: { login: null, sudo: null },
  sudo_flavor: null, presumed_self_locked_at: null, presumed_lost_at: null, owners: [], hardware: null, components: [], components_outdated: [],
} as DeviceDetail

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountAccess() {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null, revocation_enabled: true } as never
  const loginUsers = ref<string[]>(['u1'])
  const loginGroups = ref<string[]>([])
  const loginSaved = ref(false)
  const saved: { users: string[], groups: string[] }[] = []
  const saveLogin = vi.fn(async () => {
    saved.push({ users: [...loginUsers.value], groups: [...loginGroups.value] })
    loginSaved.value = true
  })
  const page = {
    device: ref(device),
    users: ref([{ id: 'u1', username: 'jdoe' }, { id: 'u2', username: 'mmuster' }]),
    userGroups: ref([{ id: 'ug1', name: 'Developers' }, { id: 'ug2', name: 'Finance' }]),
    loginUsers, loginGroups, loginSaved, sudo: ref(null), saveLogin, toggleSuspension: vi.fn(),
  } as unknown as DevicePage
  const Frame = defineComponent({
    setup() {
      provide(deviceDetailKey, page)
      return () => h(VApp, null, { default: () => h(DeviceAccess) })
    },
  })
  wrapper = mount(Frame, { global: { plugins: [createPortalI18n(), vuetify, pinia] }, attachTo: document.body })
  await flushPromises()
  return { saveLogin, saved }
}

function combobox(label: string): HTMLInputElement {
  const field = [...document.querySelectorAll<HTMLElement>('.v-input')].find((f) => f.querySelector('label')?.textContent?.trim() === label)
  return field!.querySelector('input[role="combobox"]') as HTMLInputElement
}

async function pick(label: string, typed: string, option: string): Promise<void> {
  const input = combobox(label)
  input.focus()
  input.value = typed
  input.dispatchEvent(new Event('input'))
  const find = () => [...document.querySelectorAll<HTMLElement>('[role="option"]')].find((o) => o.textContent?.includes(option))
  await vi.waitFor(() => expect(find()).toBeTruthy())
  find()!.click()
  await flushPromises()
}

function saveButton(): HTMLButtonElement {
  return [...document.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent?.trim() === 'Save')!
}

describe('device access login assignment', () => {
  it('saves the user picked last when Save is clicked right after picking it, without leaving the field', async () => {
    const { saveLogin, saved } = await mountAccess()
    await pick('Users', 'mmu', 'mmuster')
    saveButton().click()
    await flushPromises()
    expect(saveLogin).toHaveBeenCalledTimes(1)
    expect(saved).toEqual([{ users: ['u1', 'u2'], groups: [] }])
    expect(document.querySelector('[role="status"]')?.textContent).toBe('Login assignment saved.')
  })

  it('saves the group picked last when Save is clicked right after picking it, without leaving the field', async () => {
    const { saveLogin, saved } = await mountAccess()
    await pick('Groups', 'Fin', 'Finance')
    saveButton().click()
    await flushPromises()
    expect(saveLogin).toHaveBeenCalledTimes(1)
    expect(saved).toEqual([{ users: ['u1'], groups: ['ug2'] }])
  })
})
