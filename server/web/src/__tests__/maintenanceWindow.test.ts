import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import MaintenanceWindowForm from '../components/MaintenanceWindowForm.vue'
import DeviceGroupDetail from '../views/DeviceGroupDetail.vue'
import { useSessionStore } from '../stores/session'
import { clockToMinutes, minutesToClock, validateWindow, windowForm, windowInput } from '../lib/maintenanceWindows'
import type { MaintenanceWindow } from '../api/client'

const stored: MaintenanceWindow = {
  device_group_id: 'g1', days: [1, 3], start_minute: 22 * 60 + 30, duration_minutes: 270, timezone: 'Europe/Berlin', updated_at: '2026-11-01T00:00:00Z',
}
const windowState = vi.hoisted(() => ({ current: null as unknown }))
const setWindow = vi.hoisted(() => vi.fn())
const deleteWindow = vi.hoisted(() => vi.fn())
const confirmAnswer = vi.hoisted(() => ({ value: true, messages: [] as string[] }))

vi.mock('../lib/maintenanceWindows', async (original) => ({
  ...(await original<typeof import('../lib/maintenanceWindows')>()),
  getMaintenanceWindow: () => Promise.resolve(windowState.current),
  setMaintenanceWindow: setWindow,
  deleteMaintenanceWindow: deleteWindow,
}))
vi.mock('../api/client', async (original) => {
  const real = await original<typeof import('../api/client')>()
  return {
    ...real,
    api: {
      ...real.api,
      GET: (path: string) => Promise.resolve(path === '/api/v1/device-groups/{id}'
        ? { data: { id: 'g1', name: 'Laptops', description: '', staleness: null }, error: undefined }
        : { data: { items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'hostname' }, error: undefined }),
    },
  }
})
vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  getUpdateSettings: () => Promise.resolve('unavailable'),
}))
vi.mock('../composables/useConfirm', async (original) => ({
  ...(await original<typeof import('../composables/useConfirm')>()),
  useConfirm: () => (options: { message: string }) => {
    confirmAnswer.messages.push(options.message)
    return Promise.resolve(confirmAnswer.value)
  },
}))

describe('maintenance window form values (plan M13c decision 4)', () => {
  it('converts the start time between HH:MM and minutes', () => {
    expect(minutesToClock(0)).toBe('00:00')
    expect(minutesToClock(1439)).toBe('23:59')
    expect(clockToMinutes('22:30')).toBe(1350)
    expect(clockToMinutes('24:00')).toBeNull()
    expect(clockToMinutes('7:00')).toBeNull()
  })

  it('validates days, start, duration and timezone', () => {
    const ok = windowForm(stored)
    expect(validateWindow(ok)).toEqual({})
    expect(validateWindow({ ...ok, days: [] }).days).toBe('maintenanceWindow.daysRequired')
    expect(validateWindow({ ...ok, days: [1, 1] }).days).toBe('maintenanceWindow.daysRequired')
    expect(validateWindow({ ...ok, days: [8] }).days).toBe('maintenanceWindow.daysRequired')
    expect(validateWindow({ ...ok, start: '25:00' }).start).toBe('maintenanceWindow.startInvalid')
    expect(validateWindow({ ...ok, duration: '29' }).duration).toBe('maintenanceWindow.durationInvalid')
    expect(validateWindow({ ...ok, duration: '1441' }).duration).toBe('maintenanceWindow.durationInvalid')
    expect(validateWindow({ ...ok, duration: '90.5' }).duration).toBe('maintenanceWindow.durationInvalid')
    expect(validateWindow({ ...ok, duration: '1440' })).toEqual({})
    expect(validateWindow({ ...ok, timezone: ' ' }).timezone).toBe('maintenanceWindow.timezoneInvalid')
  })

  it('sends the days sorted and the start in minutes', () => {
    expect(windowInput({ days: [7, 1], start: '01:15', duration: '60', timezone: ' UTC ' }))
      .toEqual({ days: [1, 7], start_minute: 75, duration_minutes: 60, timezone: 'UTC' })
  })
})

describe('MaintenanceWindowForm', () => {
  it('refuses a window without days before any request and submits the stored window unchanged', async () => {
    const w = mount(MaintenanceWindowForm, { props: { initial: stored }, global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body })
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toEqual([[{ days: [1, 3], start_minute: 1350, duration_minutes: 270, timezone: 'Europe/Berlin' }]])
    for (const d of [1, 3]) await w.find(`[data-testid="window-day-${d}"] input`).setValue(false)
    await w.find('form').trigger('submit')
    expect(w.emitted('submit')).toHaveLength(1)
    expect(w.text()).toContain('Choose at least one day.')
    w.unmount()
  })
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountGroup(role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/device-groups/:id', name: 'device-group', component: { render: () => null } },
      { path: '/device-groups', name: 'device-groups', component: { render: () => null } },
      { path: '/devices/:id', name: 'device', component: { render: () => null } },
    ],
  })
  await router.push('/device-groups/g1')
  wrapper = mount(() => h(VApp, null, { default: () => h(DeviceGroupDetail) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

describe('DeviceGroupDetail maintenance window', () => {
  it('shows the stored window to an auditor without write controls', async () => {
    windowState.current = stored
    await mountGroup('org_auditor')
    expect(document.querySelector('[data-testid="window-summary"]')?.textContent).toContain('Mon, Wed, from 22:30 for 4 hours 30 minutes (Europe/Berlin)')
    expect(document.querySelector('[data-testid="edit-window"]')).toBeNull()
    expect(document.querySelector('[data-testid="remove-window"]')).toBeNull()
  })

  it('says when the group has no window and offers to set one', async () => {
    windowState.current = null
    await mountGroup('org_operator')
    expect(document.querySelector('[data-testid="window-summary"]')?.textContent).toContain('No window')
    expect(document.querySelector('[data-testid="edit-window"]')?.textContent).toContain('Set window')
    expect(document.querySelector('[data-testid="remove-window"]')).toBeNull()
  })

  it('shows only the error when the window cannot be loaded', async () => {
    windowState.current = 'internal'
    await mountGroup('org_admin')
    expect(document.querySelector('[role="alert"]')?.textContent).toContain('Something went wrong.')
    expect(document.querySelector('[data-testid="window-summary"]')).toBeNull()
    expect(document.querySelector('[data-testid="edit-window"]')).toBeNull()
    expect(document.querySelector('[data-testid="remove-window"]')).toBeNull()
  })

  it('removes the window only after the confirmation that names the group', async () => {
    windowState.current = stored
    deleteWindow.mockReset()
    deleteWindow.mockImplementation(() => {
      windowState.current = null
      return Promise.resolve(null)
    })
    confirmAnswer.messages.length = 0
    confirmAnswer.value = false
    await mountGroup('org_operator')
    ;(document.querySelector('[data-testid="remove-window"]') as HTMLElement).click()
    await flushPromises()
    expect(confirmAnswer.messages[0]).toContain('Laptops')
    expect(deleteWindow).not.toHaveBeenCalled()
    confirmAnswer.value = true
    ;(document.querySelector('[data-testid="remove-window"]') as HTMLElement).click()
    await flushPromises()
    expect(deleteWindow).toHaveBeenCalledWith('g1')
    expect(document.querySelector('[data-testid="window-summary"]')?.textContent).toContain('No window')
  })

  it('saves the window from the dialog and shows what the server stored', async () => {
    windowState.current = null
    setWindow.mockReset()
    setWindow.mockResolvedValue({ ...stored, days: [6, 7], start_minute: 60, duration_minutes: 60 })
    await mountGroup('org_operator')
    ;(document.querySelector('[data-testid="edit-window"]') as HTMLElement).click()
    await flushPromises()
    ;(document.querySelector('.v-dialog form') as HTMLFormElement).dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(setWindow).toHaveBeenCalledTimes(1)
    expect(document.querySelector('[data-testid="window-summary"]')?.textContent).toContain('Sat, Sun, from 01:00 for 1 hour')
  })
})
