import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { DeviceUninstall } from '../api/client'
import DangerZone from '../components/DangerZone.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { diskUsesTpm, uninstallCancellable } from '../lib/uninstall'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const started: string[] = []
const requested: unknown[] = []
const cancelled: string[] = []
let resumeFor: string | null = null
vi.mock('../lib/revocations', async (original) => ({
  ...(await original<typeof import('../lib/revocations')>()),
  listRevocations: () => () => Promise.resolve({ items: [], page: 1, page_size: 10, total: 0, total_capped: false, sort: '-requested_at' }),
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (action: string) => started.push(action),
  resumeStepUp: (action: string) => (resumeFor === action ? { payload: {}, failed: false } : null),
  withoutStepUpParam: () => '/devices/d1',
}))
vi.mock('../lib/uninstall', async (original) => ({
  ...(await original<typeof import('../lib/uninstall')>()),
  requestUninstall: (...args: unknown[]) => {
    requested.push(args)
    return Promise.resolve(null)
  },
  cancelUninstall: (id: string) => {
    cancelled.push(id)
    return Promise.resolve(null)
  },
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
  started.length = 0
  requested.length = 0
  cancelled.length = 0
  resumeFor = null
})

async function mountZone(props: Record<string, unknown> = {}, onChanged?: () => void): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = {
    id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', theme: 'system', organization: null,
    revocation_enabled: true,
  } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/devices/:id', component: { render: () => null } }] })
  await router.push('/devices/d1')
  const App = () => h(VApp, null, {
    default: () => h(DangerZone, {
      deviceId: 'd1', hostname: 'lt-1', revocable: true, presumedSelfLockedAt: null, retirable: false,
      uninstallable: true, uninstall: null, diskTpm: false, onChanged, ...props,
    }),
  })
  wrapper = mount(App, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

const el = (testid: string) => document.querySelector<HTMLElement>(`[data-testid="${testid}"]`)
const text = (testid: string) => el(testid)?.textContent?.replace(/\s+/g, ' ').trim()

async function type(testid: string, value: string): Promise<void> {
  const input = el(testid)!.querySelector<HTMLInputElement | HTMLTextAreaElement>('input, textarea')!
  input.value = value
  input.dispatchEvent(new Event('input'))
  await flushPromises()
}

const pending: DeviceUninstall = {
  mode: 'leave', requested_at: '2026-10-18T09:00:00Z', command_id: 'c1', command_status: 'pending', uninstalled_at: null,
  local_admin: null, tpm: null, report_overdue: false,
}

describe('remove Paddock (plan M8d decision 42)', () => {
  it('offers the row to organization administrators of active devices and starts with a step-up', async () => {
    const w = await mountZone()
    expect(text('danger-uninstall')).toContain('Remove Paddock')
    expect(text('danger-uninstall')).toContain('User data is never deleted.')
    await w.find('[data-testid="device-uninstall"]').trigger('click')
    expect(started).toEqual(['uninstall'])
  })

  it('hides the row for a device that is not active', async () => {
    await mountZone({ uninstallable: false })
    expect(el('danger-uninstall')).toBeNull()
  })

  it('after the step-up asks for mode, reason and the typed hostname; leave sends no reset options', async () => {
    resumeFor = 'uninstall'
    const onChanged = vi.fn()
    await mountZone({}, onChanged)
    expect(el('uninstall-dialog')).not.toBeNull()
    expect(text('uninstall-explanation')).toContain('Keeps every local account')
    expect(el('uninstall-clear-tpm')).toBeNull()
    const accept = el('uninstall-accept') as HTMLButtonElement
    await type('uninstall-reason', 'returned')
    expect(accept.disabled).toBe(true)
    await type('uninstall-typed', 'lt-2')
    expect(accept.disabled).toBe(true)
    await type('uninstall-typed', 'lt-1')
    expect(accept.disabled).toBe(false)
    accept.click()
    await flushPromises()
    expect(requested).toEqual([['d1', 'lt-1', { mode: 'leave', clearTpm: false, keepLocalAdmin: false, reason: 'returned' }]])
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('offers the reset options and disables clearing the TPM while the disk unlocks with it', async () => {
    resumeFor = 'uninstall'
    await mountZone({ diskTpm: true })
    ;(el('uninstall-mode-reset')!.querySelector('input') as HTMLInputElement).click()
    await flushPromises()
    expect(text('uninstall-explanation')).toContain('Himmelblau and its configuration are removed')
    expect((el('uninstall-clear-tpm')!.querySelector('input') as HTMLInputElement).disabled).toBe(true)
    expect(text('uninstall-clear-tpm')).toContain('Not available: the disk of this device unlocks with the TPM.')
    ;(el('uninstall-keep-local-admin')!.querySelector('input') as HTMLInputElement).click()
    await type('uninstall-reason', 'reissue')
    await type('uninstall-typed', 'lt-1')
    ;(el('uninstall-accept') as HTMLButtonElement).click()
    await flushPromises()
    expect(requested).toEqual([['d1', 'lt-1', { mode: 'reset', clearTpm: false, keepLocalAdmin: true, reason: 'reissue' }]])
  })

  it('shows a pending removal with its mode and command status and cancels it after a confirmation', async () => {
    const onChanged = vi.fn()
    const w = await mountZone({ uninstall: pending }, onChanged)
    expect(el('danger-uninstall')).toBeNull()
    expect(text('danger-uninstall-pending')).toContain('Removal requested (leave as is) — Pending.')
    await w.find('[data-testid="uninstall-cancel-request"]').trigger('click')
    expect(pendingConfirm.value?.options).toMatchObject({ title: 'Cancel the removal', confirmLabel: 'Cancel request' })
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(cancelled).toEqual(['d1'])
    expect(onChanged).toHaveBeenCalledTimes(1)
  })

  it('offers no cancel once the device received the command', async () => {
    await mountZone({ uninstall: { ...pending, command_status: 'delivered' } })
    expect(text('danger-uninstall-pending')).toContain('Delivered')
    expect(el('uninstall-cancel-request')).toBeNull()
  })

  it('replaces Lock and Destroy with a hint while a removal is pending (PDK-327)', async () => {
    await mountZone({ uninstall: pending })
    expect(text('revocation-uninstall-pending')).toContain('Cancel the removal first.')
    expect(el('revocation-lock')).toBeNull()
    expect(el('revocation-destroy')).toBeNull()
  })

  it('offers the cancel again once the removal report is overdue', async () => {
    await mountZone({ uninstall: { ...pending, command_status: 'succeeded', report_overdue: true } })
    expect(el('uninstall-cancel-request')).not.toBeNull()
  })

  it('knows when a pending removal can be cancelled and when a disk uses the TPM', () => {
    expect(uninstallCancellable(pending)).toBe(true)
    expect(uninstallCancellable({ ...pending, command_status: 'failed' })).toBe(true)
    expect(uninstallCancellable({ ...pending, command_status: 'delivered' })).toBe(false)
    expect(uninstallCancellable({ ...pending, command_status: 'delivered', report_overdue: true })).toBe(true)
    expect(uninstallCancellable({ ...pending, uninstalled_at: '2026-10-18T10:00:00Z' })).toBe(false)
    expect(uninstallCancellable(null)).toBe(false)
    expect(diskUsesTpm({ tokens: ['recovery', 'tpm2+pin'], volumes: [] })).toBe(true)
    expect(diskUsesTpm({ tokens: ['password'], volumes: [{ tokens: ['tpm2'] }] })).toBe(true)
    expect(diskUsesTpm({ tokens: ['password', 'recovery'], volumes: [{}] })).toBe(false)
    expect(diskUsesTpm(null)).toBe(false)
  })
})
