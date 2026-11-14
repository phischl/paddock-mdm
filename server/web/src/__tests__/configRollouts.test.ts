import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import ManagedDeleteDialog from '../components/ManagedDeleteDialog.vue'
import ManagedFileForm from '../components/ManagedFileForm.vue'
import UrgentOptOut from '../components/UrgentOptOut.vue'
import ConfigRolloutDetail from '../views/ConfigRolloutDetail.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { noUrgent, rolloutActionsFor, rolloutOpen, rolloutPercent, urgentQuery, validUrgent } from '../lib/configRollouts'
import { useSessionStore } from '../stores/session'
import type { ConfigRollout, ConfigRolloutDetail as Detail } from '../api/client'

function rollout(extra: Partial<ConfigRollout> = {}): ConfigRollout {
  return {
    id: 'r1', change_set_id: 'cs1', waves: [1, 10, 50, 100], current_wave_index: 0, wave_started_at: '2026-10-31T10:00:00Z',
    min_wave_minutes: 60, failure_threshold_percent: 5, failure_threshold_min: 2, canary_device_group_id: 'g1', status: 'running',
    halted_reason: null, started_by: 'alice', started_at: '2026-10-31T10:00:00Z', ended_at: null, ended_reason: null,
    counts: { eligible: 4, applied: 2, failed: 1, pending: 1, waiting: 0, awaiting_retry: 0 }, ...extra,
  }
}

describe('configuration rollout helpers', () => {
  it('offers only the actions the state allows', () => {
    expect(rolloutActionsFor(rollout())).toEqual(['halt', 'advance', 'complete'])
    expect(rolloutActionsFor(rollout({ current_wave_index: 3 }))).toEqual(['halt', 'complete'])
    expect(rolloutActionsFor(rollout({ status: 'halted' }))).toEqual(['resume', 'complete'])
    expect(rolloutActionsFor(rollout({ status: 'completed' }))).toEqual([])
    expect(rolloutActionsFor(rollout({ status: 'reverted' }))).toEqual([])
  })

  it('knows when a rollout is open and how far it reached', () => {
    expect(rolloutOpen(rollout())).toBe(true)
    expect(rolloutOpen(rollout({ status: 'halted' }))).toBe(true)
    expect(rolloutOpen(rollout({ status: 'completed' }))).toBe(false)
    expect(rolloutPercent(rollout({ current_wave_index: 1 }))).toBe(10)
    expect(rolloutPercent(rollout({ status: 'completed', current_wave_index: 1 }))).toBe(100)
  })

  it('needs a reason of 2 to 500 characters only when the opt-out is checked', () => {
    expect(validUrgent(undefined)).toBe(true)
    expect(validUrgent(noUrgent())).toBe(true)
    expect(validUrgent({ urgent: true, reason: '' })).toBe(false)
    expect(validUrgent({ urgent: true, reason: ' x ' })).toBe(false)
    expect(validUrgent({ urgent: true, reason: 'hotfix' })).toBe(true)
    expect(validUrgent({ urgent: true, reason: 'hot\x07fix' })).toBe(false)
    expect(validUrgent({ urgent: true, reason: 'x'.repeat(501) })).toBe(false)
  })

  it('sends urgent and the trimmed reason only when opted out', () => {
    expect(urgentQuery(undefined)).toEqual({})
    expect(urgentQuery({ urgent: false, reason: 'ignored' })).toEqual({})
    expect(urgentQuery({ urgent: true, reason: ' hotfix ' })).toEqual({ urgent: true, reason: 'hotfix' })
  })
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

describe('UrgentOptOut', () => {
  function mountOptOut(enabled: boolean, modelValue = noUrgent()): VueWrapper {
    wrapper = mount(
      () => h(VApp, null, { default: () => h(UrgentOptOut, { enabled, modelValue, showErrors: true }) }),
      { global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body },
    )
    return wrapper
  }

  it('is absent while rollouts are disabled', () => {
    mountOptOut(false)
    expect(document.querySelector('[data-testid="urgent-opt-out"]')).toBeNull()
  })

  it('shows the checkbox, and the reason field once it is checked', async () => {
    mountOptOut(true)
    expect(document.body.textContent).toContain('Apply immediately to every device (urgent)')
    expect(document.querySelector('[data-testid="urgent-reason"]')).toBeNull()
    wrapper?.unmount()
    mountOptOut(true, { urgent: true, reason: '' })
    await flushPromises()
    expect(document.querySelector('[data-testid="urgent-reason"]')).not.toBeNull()
    expect(document.body.textContent).toContain('Enter a reason of 2 to 500 characters.')
  })
})

describe('ManagedFileForm with the urgent opt-out', () => {
  async function fill(w: VueWrapper, checkUrgent: boolean, reason: string): Promise<void> {
    const path = document.querySelector('#file-path') as HTMLInputElement
    path.value = '/etc/myapp/app.conf'
    path.dispatchEvent(new Event('input'))
    if (checkUrgent) {
      const box = document.querySelector('[data-testid="urgent-checkbox"] input') as HTMLInputElement
      box.click()
      await flushPromises()
      const text = document.querySelector('[data-testid="urgent-reason"] textarea') as HTMLTextAreaElement
      text.value = reason
      text.dispatchEvent(new Event('input'))
    }
    await flushPromises()
    w.get('form').element.dispatchEvent(new Event('submit'))
    await flushPromises()
  }

  function mountForm(enabled: boolean): VueWrapper {
    wrapper = mount(
      () => h(VApp, null, { default: () => h(ManagedFileForm, { groups: [], rolloutsEnabled: enabled }) }),
      { global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body },
    )
    return wrapper
  }

  it('submits without the opt-out, and shows none while rollouts are disabled', async () => {
    const w = mountForm(false)
    expect(document.querySelector('[data-testid="urgent-opt-out"]')).toBeNull()
    await fill(w, false, '')
    const emitted = w.findComponent(ManagedFileForm).emitted('submit')
    expect(emitted?.[0][0]).toMatchObject({ path: '/etc/myapp/app.conf', urgent: { urgent: false, reason: '' } })
  })

  it('holds the submit back until the urgent reason is given', async () => {
    const w = mountForm(true)
    await fill(w, true, '')
    expect(w.findComponent(ManagedFileForm).emitted('submit')).toBeUndefined()
    await fill(w, false, '')
    const text = document.querySelector('[data-testid="urgent-reason"] textarea') as HTMLTextAreaElement
    text.value = 'hotfix'
    text.dispatchEvent(new Event('input'))
    await flushPromises()
    w.get('form').element.dispatchEvent(new Event('submit'))
    await flushPromises()
    expect(w.findComponent(ManagedFileForm).emitted('submit')?.[0][0]).toMatchObject({ urgent: { urgent: true, reason: 'hotfix' } })
  })
})

describe('ManagedDeleteDialog', () => {
  it('confirms a delete with the urgent opt-out only once it has its reason', async () => {
    const confirm = vi.fn()
    wrapper = mount(
      () => h(VApp, null, {
        default: () => h(ManagedDeleteDialog, { title: 'Delete file', message: 'Delete?', rolloutsEnabled: true, onConfirm: confirm }),
      }),
      { global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body },
    )
    await flushPromises()
    ;(document.querySelector('[data-testid="urgent-checkbox"] input') as HTMLInputElement).click()
    await flushPromises()
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(confirm).not.toHaveBeenCalled()
    const text = document.querySelector('[data-testid="urgent-reason"] textarea') as HTMLTextAreaElement
    text.value = 'hotfix'
    text.dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(confirm).toHaveBeenCalledWith({ urgent: true, reason: 'hotfix' })
  })
})

const getConfigRollout = vi.fn<(id: string) => Promise<Detail | string>>()
const runRolloutAction = vi.fn<(id: string, action: string, reason?: string) => Promise<ConfigRollout | string>>()
vi.mock('../lib/configRollouts', async (original) => ({
  ...(await original<typeof import('../lib/configRollouts')>()),
  getConfigRollout: (id: string) => getConfigRollout(id),
  runRolloutAction: (id: string, action: string, reason?: string) => runRolloutAction(id, action, reason),
  rolloutDevicesFetcher: () => () => Promise.resolve({ items: [], page: 1, page_size: 25, total: 0, total_capped: false, sort: 'hostname' }),
}))
vi.mock('../lib/devices', async (original) => ({
  ...(await original<typeof import('../lib/devices')>()),
  allGroups: () => Promise.resolve([{ id: 'g1', name: 'Pilot' }]),
}))

function detail(extra: Partial<ConfigRollout> = {}): Detail {
  return {
    rollout: rollout(extra), staged_resource_ids: ['file:/etc/motd'],
    change_set: {
      id: 'cs1', applied_at: '2026-10-31T10:00:00Z', actor: { type: 'admin', display: 'Alice' }, source: 'session',
      summary: { created: 0, updated: 1, deleted: 0, sections: ['managed_files'] },
      plan: { changes: [], created: 0, updated: 1, deleted: 0 }, rollout: 'staged', before_available: true, rollout_id: 'r1',
    },
  } as Detail
}

/** Hosts the confirmation dialog like App.vue does. */
const Host = defineComponent({
  setup: () => () => h(VApp, null, {
    default: () => [
      h(RouterView),
      pendingConfirm.value
        ? h(ConfirmDialog, {
          key: pendingConfirm.value.id, modelValue: true, ...pendingConfirm.value.options,
          onConfirm: (a: { reason: string }) => settleConfirm(a), onCancel: () => settleConfirm(false),
        })
        : null,
    ],
  }),
})

async function mountDetail(role: string): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/config-rollouts', name: 'config-rollouts', component: { render: () => null } },
      { path: '/config-rollouts/:id', name: 'config-rollout', component: ConfigRolloutDetail },
      { path: '/change-sets', name: 'change-sets', component: { render: () => null } },
      { path: '/devices/:id', name: 'device', component: { render: () => null } },
    ],
  })
  await router.push('/config-rollouts/r1')
  await router.isReady()
  wrapper = mount(Host, { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

describe('ConfigRolloutDetail', () => {
  beforeEach(() => {
    getConfigRollout.mockReset()
    runRolloutAction.mockReset()
  })

  it('shows the wave strip with the current wave and the canary group', async () => {
    getConfigRollout.mockResolvedValue(detail({ current_wave_index: 1 }))
    const w = await mountDetail('org_admin')
    expect(w.get('[data-testid="wave-2"]').attributes('aria-current')).toBe('step')
    expect(w.get('[data-testid="wave-1"]').attributes('aria-current')).toBeUndefined()
    expect(w.get('[data-testid="wave-1"]').text()).toContain('Reached')
    expect(w.get('[data-testid="wave-3"]').text()).toContain('Upcoming')
    expect(w.get('[data-testid="config-rollout-canary"]').text()).toContain('Pilot')
    expect(w.get('[data-testid="config-rollout-wave"]').text()).toBe('Wave 2 of 4 (10 %)')
    expect(w.get('[data-testid="config-rollout-counts"]').text()).toContain('4 in the waves so far, 2 applied, 1 failed, 1 pending')
  })

  it('hides every action from an auditor', async () => {
    getConfigRollout.mockResolvedValue(detail())
    const w = await mountDetail('org_auditor')
    for (const a of ['halt', 'advance', 'complete', 'revert']) expect(w.find(`[data-testid="config-rollout-${a}"]`).exists()).toBe(false)
  })

  it('halts only with a reason', async () => {
    getConfigRollout.mockResolvedValue(detail())
    runRolloutAction.mockResolvedValue(rollout({ status: 'halted' }))
    const w = await mountDetail('org_admin')
    await w.get('[data-testid="config-rollout-halt"]').trigger('click')
    await flushPromises()
    const accept = document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement
    expect(accept.disabled).toBe(true)
    const reason = document.querySelector('[data-testid="confirm-reason"] textarea') as HTMLTextAreaElement
    reason.value = 'x'
    reason.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(accept.disabled).toBe(true)
    reason.value = 'too many failures'
    reason.dispatchEvent(new Event('input'))
    await flushPromises()
    accept.click()
    await flushPromises()
    expect(runRolloutAction).toHaveBeenCalledWith('r1', 'halt', 'too many failures')
  })

  it('states in the completion modal that every device receives the change', async () => {
    getConfigRollout.mockResolvedValue(detail())
    runRolloutAction.mockResolvedValue(rollout({ status: 'completed' }))
    const w = await mountDetail('org_operator')
    await w.get('[data-testid="config-rollout-complete"]').trigger('click')
    await flushPromises()
    expect(document.querySelector('[data-testid="confirm-dialog"]')?.textContent).toContain('Every device receives this change')
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(runRolloutAction).toHaveBeenCalledWith('r1', 'complete', '')
  })

  it('does not run an action that was cancelled', async () => {
    getConfigRollout.mockResolvedValue(detail())
    const w = await mountDetail('org_admin')
    await w.get('[data-testid="config-rollout-advance"]').trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-testid="confirm-cancel"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(runRolloutAction).not.toHaveBeenCalled()
  })

  it('offers resume, not advance, for a halted rollout and shows its reason', async () => {
    getConfigRollout.mockResolvedValue(detail({ status: 'halted', halted_reason: 'canary failed' }))
    const w = await mountDetail('org_admin')
    expect(w.find('[data-testid="config-rollout-resume"]').exists()).toBe(true)
    expect(w.find('[data-testid="config-rollout-advance"]').exists()).toBe(false)
    expect(w.get('[data-testid="config-rollout-halted-reason"]').text()).toBe('canary failed')
  })
})
