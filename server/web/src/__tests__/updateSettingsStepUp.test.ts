import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import UpdateSettingsView from '../views/UpdateSettings.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import type { UpdateSettings, UpdateSettingsUpdate } from '../api/client'
import type { UrgentInput } from '../lib/configRollouts'

const current = {
  security_daily_at: '03:00', regular_schedule: 'Sat 04:00', regular_updates_enabled: true, max_random_delay_min: 60,
  staleness_warning_h: 24, staleness_critical_h: 168, agent_update_policy: 'automatic', updated_at: '2026-10-25T10:00:00Z',
} as UpdateSettings
const saveUpdateSettings = vi.fn<(s: UpdateSettingsUpdate, urgent?: UrgentInput) => Promise<UpdateSettings | string>>()
vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  getUpdateSettings: () => Promise.resolve(current),
  saveUpdateSettings: (s: UpdateSettingsUpdate, urgent?: UrgentInput) => saveUpdateSettings(s, urgent),
}))
vi.mock('../lib/rolloutSettings', async (original) => ({
  ...(await original<typeof import('../lib/rolloutSettings')>()),
  getRolloutSettings: () => Promise.resolve({ enabled: true }),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  saveUpdateSettings.mockReset()
  assign.mockReset()
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/settings/updates', search: '' }, writable: true, configurable: true,
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings/updates', component: UpdateSettingsView }] })
  await router.push('/settings/updates')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

function pendingSave(): void {
  sessionStorage.setItem('paddock.stepup', JSON.stringify({
    action: 'update-settings', target: 'update-settings', at: Date.now(),
    payload: { settings: current, urgent: { urgent: true, reason: 'hotfix' } },
  }))
}

describe('UpdateSettings step-up', () => {
  it('repeats the save once after the step-up, with the opt-out', async () => {
    pendingSave()
    saveUpdateSettings.mockResolvedValueOnce(current)
    await mountPage()
    expect(saveUpdateSettings).toHaveBeenCalledTimes(1)
    expect(saveUpdateSettings.mock.calls[0][1]).toEqual({ urgent: true, reason: 'hotfix' })
    expect(assign).not.toHaveBeenCalled()
  })

  it('does not start a second step-up when the resumed save still needs one', async () => {
    pendingSave()
    saveUpdateSettings.mockResolvedValueOnce('step_up_required')
    await mountPage()
    expect(saveUpdateSettings).toHaveBeenCalledTimes(1)
    expect(assign).not.toHaveBeenCalled()
    expect(document.querySelector('.form-error')?.textContent).toContain('Confirm your identity')
  })

  it('starts the step-up for a save the server refuses with step_up_required', async () => {
    saveUpdateSettings.mockResolvedValueOnce('step_up_required')
    const w = await mountPage()
    w.get('form').element.dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsettings%2Fupdates')
  })
})
