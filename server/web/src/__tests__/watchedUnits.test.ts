import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import WatchedUnits from '../views/WatchedUnits.vue'
import { validateWatchedUnits, type WatchedUnits as Saved } from '../lib/watchedUnits'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { useSessionStore } from '../stores/session'

let stored: Saved = { units: ['wazuh-agent.service'], updatedAt: '2026-10-31T10:00:00Z' }
const setWatchedUnits = vi.fn<(u: string[]) => Promise<Saved | string>>()
vi.mock('../lib/watchedUnits', async (original) => ({
  ...(await original<typeof import('../lib/watchedUnits')>()),
  getWatchedUnits: () => Promise.resolve(stored),
  setWatchedUnits: (u: string[]) => setWatchedUnits(u),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  setWatchedUnits.mockReset()
  assign.mockReset()
  stored = { units: ['wazuh-agent.service'], updatedAt: '2026-10-31T10:00:00Z' }
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/settings/watched-units', search: '' }, writable: true,
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(role = 'org_admin'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings/watched-units', component: WatchedUnits }] })
  await router.push('/settings/watched-units')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

async function addUnit(name: string): Promise<void> {
  const input = document.querySelector('#watched-units') as HTMLInputElement
  input.focus()
  input.value = name
  input.dispatchEvent(new Event('input'))
  input.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }))
  await flushPromises()
}

describe('validateWatchedUnits', () => {
  it('names the first unit that is not a service or is listed twice', () => {
    expect(validateWatchedUnits(['wazuh-agent.service'])).toBeNull()
    expect(validateWatchedUnits(['foo.timer'])?.values).toEqual({ unit: 'foo.timer' })
    expect(validateWatchedUnits(['a.service', 'a.service'])?.key).toBe('watchedUnits.errors.duplicate')
    expect(validateWatchedUnits(Array.from({ length: 33 }, (_, i) => `u${i}.service`))?.key).toBe('watchedUnits.errors.tooMany')
  })
})

describe('WatchedUnits (plan M9 decision 38)', () => {
  it('shows the stored units, confirms, steps up and saves after the return', async () => {
    setWatchedUnits.mockResolvedValueOnce('step_up_required')
    const w = await mountPage()
    expect(w.text()).toContain('wazuh-agent.service')
    expect(w.find('[data-testid="watched-info"]').text()).toContain('never installs')
    await addUnit('falcon-sensor.service')
    expect(w.text()).toContain('falcon-sensor.service')
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(pendingConfirm.value?.options.message).toContain('2 units')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(setWatchedUnits).toHaveBeenCalledWith(['wazuh-agent.service', 'falcon-sensor.service'])
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsettings%2Fwatched-units')
    wrapper?.unmount()

    setWatchedUnits.mockResolvedValueOnce({ units: ['wazuh-agent.service', 'falcon-sensor.service'], updatedAt: '2026-10-31T11:00:00Z' })
    const resumed = await mountPage()
    expect(setWatchedUnits).toHaveBeenLastCalledWith(['wazuh-agent.service', 'falcon-sensor.service'])
    expect(resumed.find('[data-testid="watched-saved"]').exists()).toBe(true)
  })

  it('shows a validation error inline and does not save a name that is no service', async () => {
    const w = await mountPage()
    await addUnit('foo.timer')
    expect(w.text()).toContain('foo.timer is not a service name')
    expect((w.find('[data-testid="save-watched-units"]').element as HTMLButtonElement).disabled).toBe(true)
    expect(setWatchedUnits).not.toHaveBeenCalled()
  })

  async function submit(): Promise<void> {
    ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    settleConfirm({ reason: '' })
    await flushPromises()
  }
  const invalidAttr = () => document.querySelector('#watched-units')?.getAttribute('aria-invalid')

  it('shows the server refusal inline and marks the input invalid', async () => {
    setWatchedUnits.mockResolvedValueOnce('unit_not_allowed')
    const w = await mountPage()
    expect(invalidAttr()).not.toBe('true')
    await submit()
    expect(w.text()).toContain('This unit is not allowed')
    expect(invalidAttr()).toBe('true')
  })

  it('clears the refusal as soon as the list changes', async () => {
    setWatchedUnits.mockResolvedValueOnce('unit_not_allowed')
    const w = await mountPage()
    await submit()
    expect(invalidAttr()).toBe('true')
    ;(document.querySelector('.v-chip__close') as HTMLElement).click()
    await flushPromises()
    expect(w.text()).not.toContain('This unit is not allowed')
    expect(invalidAttr()).not.toBe('true')
  })

  it('marks the input invalid while a client-side error shows', async () => {
    await mountPage()
    await addUnit('foo.timer')
    expect(invalidAttr()).toBe('true')
  })

  it('shows another server problem below the field', async () => {
    setWatchedUnits.mockResolvedValueOnce('invalid_request')
    const w = await mountPage()
    await submit()
    expect(w.find('[data-testid="watched-problem"]').exists()).toBe(true)
  })

  it('offers no save button to an auditor', async () => {
    const w = await mountPage('org_auditor')
    expect(w.find('[data-testid="save-watched-units"]').exists()).toBe(false)
  })
})
