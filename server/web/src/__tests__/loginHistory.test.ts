import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h, provide, ref } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { LoginSettings, LoginSettingsUpdate } from '../api/client'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { deviceDetailKey, type DevicePage } from '../lib/deviceDetailPage'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import DeviceLogins from '../views/DeviceLogins.vue'
import LoginSettingsView from '../views/LoginSettings.vue'

const enabled = vi.fn<() => Promise<boolean | null>>()
vi.mock('../lib/loginHistory', async (original) => ({
  ...(await original<typeof import('../lib/loginHistory')>()),
  loginHistoryEnabled: () => enabled(),
  listDeviceLogins: () => () => Promise.resolve({
    items: [{ id: 'e1', username: 'dave@acme.test', at: '2026-10-17T10:15:02Z' }], page: 1, page_size: 25, total: 1,
    total_capped: false, sort: '-at',
  }),
}))

const stored: LoginSettings = {
  hello_enabled: true, hello_pin_min_length: 6, user_lock_session_action: 'lock_screen', break_glass_accounts: [],
  sudoers_d_allowlist: ['README'], sudo_lecture_text: 'Be careful.', local_admin_username: 'paddock-admin',
  local_admin_rotation_days: 30, rotate_after_reveal_hours: null, notice_text: '', boot_pin_min_length: 8,
  login_history_enabled: true, login_history_days: 90, disk_unlock_mode: 'tpm_pin', updated_at: '2026-10-17T10:00:00Z',
} as LoginSettings
const saveLoginSettings = vi.fn<(s: LoginSettingsUpdate) => Promise<LoginSettings | string>>()
vi.mock('../lib/loginSettings', async (original) => ({
  ...(await original<typeof import('../lib/loginSettings')>()),
  getLoginSettings: () => Promise.resolve({ ...stored }),
  saveLoginSettings: (s: LoginSettingsUpdate) => saveLoginSettings(s),
}))

let wrapper: VueWrapper | null = null
beforeEach(() => {
  setActivePinia(createPinia())
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null, revocation_enabled: true } as never
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  saveLoginSettings.mockReset()
})

async function mountView(view: object, frame = false): Promise<void> {
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: '/', component: { render: () => null } }, { path: '/settings/login', name: 'login-settings', component: { render: () => null } }],
  })
  await router.push('/')
  const page = { device: ref({ id: 'd1' }) } as unknown as DevicePage
  const Frame = defineComponent({
    setup() {
      if (frame) provide(deviceDetailKey, page)
      return () => h(VApp, null, { default: () => h(view) })
    },
  })
  wrapper = mount(Frame, { global: { plugins: [createPortalI18n(), vuetify, router] }, attachTo: document.body })
  await flushPromises()
}

describe('device logins tab (PDK-224)', () => {
  it('says the history is off and links administrators to the setting', async () => {
    enabled.mockResolvedValue(false)
    await mountView(DeviceLogins, true)
    const off = document.querySelector('[data-testid="device-logins-off"]')
    expect(off?.textContent).toContain('The login history is off for this organization.')
    expect(off?.querySelector('a')?.getAttribute('href')).toBe('/settings/login')
    expect(document.querySelector('[data-testid="device-login-list"]')).toBeNull()
  })

  it('lists user and time while the history is on', async () => {
    enabled.mockResolvedValue(true)
    await mountView(DeviceLogins, true)
    expect(document.querySelector('[data-testid="device-login-list"]')?.textContent).toContain('dave@acme.test')
  })
})

describe('login history setting (PDK-224)', () => {
  it('shows the notice and asks before switching the history off', async () => {
    await mountView(LoginSettingsView)
    expect(document.querySelector('[data-testid="login-history-notice"]')?.textContent).toContain('works council')
    const toggle = document.querySelector('#settings-login-history') as HTMLInputElement
    toggle.click()
    await flushPromises()
    ;(document.querySelector('[data-testid="save-login-settings"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(pendingConfirm.value?.options.message).toBe('Switch the login history off? Every recorded login of this organization is deleted at once.')
    expect(pendingConfirm.value?.options.destructive).toBe(true)
    expect(pendingConfirm.value?.options.confirmLabel).toBe('Switch off and delete')
    settleConfirm(false)
    await flushPromises()
    expect(saveLoginSettings).not.toHaveBeenCalled()

    saveLoginSettings.mockResolvedValue({ ...stored, login_history_enabled: false })
    ;(document.querySelector('[data-testid="save-login-settings"]') as HTMLButtonElement).click()
    await flushPromises()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(saveLoginSettings).toHaveBeenCalledWith(expect.objectContaining({ login_history_enabled: false, login_history_days: 90 }))
  })

  // Browser check M8d defect 2: days below the minimum showed only the generic problem.
  it.each(['3', '366', '', '7.5'])('marks %j retention days, names the rule and does not save', async (days) => {
    await mountView(LoginSettingsView)
    const input = document.querySelector('#settings-login-history-days') as HTMLInputElement
    input.value = days
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('[data-testid="save-login-settings"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(saveLoginSettings).not.toHaveBeenCalled()
    expect(pendingConfirm.value).toBeNull()
    expect(input.getAttribute('aria-invalid')).toBe('true')
    expect(document.querySelector('[data-testid="login-history-days"]')?.textContent).toContain('Enter a whole number of days from 7 to 365.')
  })

  it('accepts the limits of the retention', async () => {
    saveLoginSettings.mockResolvedValue({ ...stored, login_history_days: 7 })
    await mountView(LoginSettingsView)
    const input = document.querySelector('#settings-login-history-days') as HTMLInputElement
    input.value = '7'
    input.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('[data-testid="save-login-settings"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(saveLoginSettings).toHaveBeenCalledWith(expect.objectContaining({ login_history_days: 7 }))
    expect(input.getAttribute('aria-invalid')).toBe('false')
  })
})
