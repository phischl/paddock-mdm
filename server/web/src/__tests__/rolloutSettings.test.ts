import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import RolloutSettingsView from '../views/RolloutSettings.vue'
import type { RolloutSettings, RolloutSettingsUpdate } from '../api/client'
import { formatWaves, parseWaves, validWaves } from '../lib/rolloutSettings'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const canaryID = '00000000-0000-7000-8000-0000000000c1'
let stored: RolloutSettings
const save = vi.fn<(s: RolloutSettingsUpdate) => Promise<RolloutSettings | string>>()
vi.mock('../lib/rolloutSettings', async (original) => ({
  ...(await original<typeof import('../lib/rolloutSettings')>()),
  getRolloutSettings: () => Promise.resolve({ ...stored }),
  saveRolloutSettings: (s: RolloutSettingsUpdate) => save(s),
}))
vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  allGroups: () => Promise.resolve([{ id: canaryID, name: 'Canary laptops' }, { id: 'other', name: 'Servers' }]),
}))

let wrapper: VueWrapper | null = null

beforeEach(() => {
  save.mockReset()
  stored = {
    enabled: false, waves: [1, 10, 50, 100], min_wave_minutes: 60, failure_threshold_percent: 2, failure_threshold_min: 3,
    canary_device_group_id: null, updated_at: '2026-10-30T08:00:00Z',
  }
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountAs(role: string): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings/rollout', component: RolloutSettingsView }] })
  await router.push('/settings/rollout')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

function input(id: string): HTMLInputElement {
  return document.querySelector('#' + id) as HTMLInputElement
}

async function type(id: string, value: string): Promise<void> {
  input(id).value = value
  input(id).dispatchEvent(new Event('input'))
  await flushPromises()
}

async function submit(): Promise<void> {
  ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
  await flushPromises()
}

describe('rollout settings helpers', () => {
  it('formats and parses the waves text', () => {
    expect(formatWaves([1, 10, 100])).toBe('1, 10, 100')
    expect(parseWaves('1, 10 ,100')).toEqual([1, 10, 100])
    expect(parseWaves('1, x, 100')).toBeNull()
    expect(parseWaves('')).toBeNull()
  })

  it('validates the waves like the server', () => {
    expect(validWaves([100])).toBe(true)
    expect(validWaves([1, 10, 50, 100])).toBe(true)
    for (const bad of [null, [], [50], [10, 10, 100], [50, 10, 100], [0, 100], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100]]) {
      expect(validWaves(bad)).toBe(false)
    }
  })
})

describe('RolloutSettings (plan M11 decision 24)', () => {
  it('shows the stored settings and saves changes with the canary group', async () => {
    save.mockImplementation((s) => Promise.resolve({ ...s, canary_device_group_id: s.canary_device_group_id ?? null, updated_at: '2026-10-30T09:00:00Z' }))
    const w = await mountAs('org_admin')
    expect(input('rollout-waves').value).toBe('1, 10, 50, 100')
    expect(input('rollout-min-wave').value).toBe('60')
    expect(w.text()).toContain('Canary device group')
    await type('rollout-waves', '5, 50, 100')
    await type('rollout-min-wave', '30')
    input('rollout-enabled').click()
    await flushPromises()
    ;(w.find('[data-testid="rollout-canary"] .v-field') as { trigger: (e: string) => Promise<void> }).trigger('mousedown')
    await flushPromises()
    const option = Array.from(document.querySelectorAll('.v-list-item')).find((o) => o.textContent?.includes('Canary laptops'))
    expect(option).toBeTruthy()
    ;(option as HTMLElement).click()
    await flushPromises()
    await submit()
    expect(save).toHaveBeenCalledWith({
      enabled: true, waves: [5, 50, 100], min_wave_minutes: 30, failure_threshold_percent: 2, failure_threshold_min: 3,
      canary_device_group_id: canaryID,
    })
    expect(document.body.textContent).toContain('The rollout settings were saved.')
  })

  it('shows "None" when the canary group is gone', async () => {
    const w = await mountAs('org_admin')
    expect(w.find('[data-testid="rollout-canary"]').text()).toContain('None')
  })

  it('shows the stored canary group', async () => {
    stored.canary_device_group_id = canaryID
    const w = await mountAs('org_admin')
    expect(w.find('[data-testid="rollout-canary"]').text()).toContain('Canary laptops')
  })

  it('refuses invalid waves and thresholds inline without saving', async () => {
    const w = await mountAs('org_admin')
    await type('rollout-waves', '10, 50')
    await type('rollout-threshold-percent', '101')
    await submit()
    expect(w.text()).toContain('ending with 100')
    expect(w.text()).toContain('Enter a whole number from 0 to 100.')
    expect(save).not.toHaveBeenCalled()
  })

  it('shows a refusal of the server inline', async () => {
    save.mockResolvedValue('invalid_request')
    const w = await mountAs('org_admin')
    await submit()
    expect(w.find('[role="alert"]').exists()).toBe(true)
    expect(document.body.textContent).not.toContain('The rollout settings were saved.')
  })

  it.each(['org_operator', 'org_auditor'])('is read-only for %s', async (role) => {
    const w = await mountAs(role)
    expect(input('rollout-waves').matches(':disabled')).toBe(true)
    expect(w.find('[data-testid="save-rollout-settings"]').exists()).toBe(false)
    expect(w.find('[data-testid="rollout-read-only"]').text()).toContain('Only organization administrators')
  })
})
