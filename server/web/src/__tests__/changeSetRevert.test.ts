import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import ChangeSets from '../views/ChangeSets.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { revertBlocked } from '../lib/changeSets'
import type { ChangeSet, ConfigApplyResult } from '../api/client'

function changeSet(id: string, extra: Partial<ChangeSet> = {}): ChangeSet {
  return {
    id, applied_at: '2026-10-31T10:00:00Z', actor: { type: 'admin', display: 'Alice' }, source: 'session',
    summary: { created: 1, updated: 1, deleted: 0, sections: ['managed_files'] },
    plan: { changes: [], created: 1, updated: 1, deleted: 0 }, rollout: 'immediate', before_available: true, ...extra,
  } as ChangeSet
}

function result(content: string, hash: string): ConfigApplyResult {
  return {
    dry_run: true, change_set_id: null, plan_sha256: hash,
    plan: {
      changes: [
        { section: 'managed_units', key: '[null,"acme.service"]', action: 'delete', fields: [] },
        { section: 'managed_files', key: '[null,"/etc/motd"]', action: 'update', fields: [{ name: 'content', before: 'sha256:b', after: content }] },
      ],
      created: 0, updated: 1, deleted: 1,
    },
  } as ConfigApplyResult
}

const revertable = changeSet('cs-1')
const reverted = changeSet('cs-2', { reverted_by: 'cs-9' })
const legacy = changeSet('cs-3', { before_available: false })
const revertDryRun = vi.fn<(id: string) => Promise<ConfigApplyResult | string>>()
const revertChangeSet = vi.fn<(id: string, hash: string) => Promise<ConfigApplyResult | string>>()
vi.mock('../lib/changeSets', async (original) => ({
  ...(await original<typeof import('../lib/changeSets')>()),
  listChangeSets: () => Promise.resolve({ items: [revertable, reverted, legacy], page: 1, page_size: 25, total: 3, total_capped: false, sort: '-applied_at' }),
  revertDryRun: (id: string) => revertDryRun(id),
  revertChangeSet: (id: string, hash: string) => revertChangeSet(id, hash),
}))

let wrapper: VueWrapper | null = null

beforeEach(() => {
  sessionStorage.clear()
  revertDryRun.mockReset()
  revertChangeSet.mockReset()
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountList(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role: 'org_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/change-sets', component: ChangeSets }] })
  await router.push('/change-sets')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

function dialog(): HTMLElement | null {
  return document.querySelector('[data-testid="confirm-dialog"]')
}

describe('revert a change set (plan M11 decision 22)', () => {
  it('blocks a reverted change set and one without before-state', () => {
    expect(revertBlocked(revertable)).toBeNull()
    expect(revertBlocked(reverted)).toBe('reverted')
    expect(revertBlocked(legacy)).toBe('noBefore')
  })

  it('shows the inverse plan in a modal and reverts with the confirmed plan', async () => {
    const nativeConfirm = vi.spyOn(window, 'confirm')
    revertDryRun.mockResolvedValueOnce(result('sha256:a', 'h1'))
    revertChangeSet.mockResolvedValueOnce({ ...result('sha256:a', 'h1'), dry_run: false, change_set_id: 'cs-10' })
    const w = await mountList()
    const buttons = w.findAll('[data-testid="change-set-revert"]')
    expect(buttons).toHaveLength(1)
    expect(w.findAll('[data-testid="change-set-revert-blocked"]')).toHaveLength(2)
    await buttons[0].trigger('click')
    await flushPromises()
    expect(revertDryRun).toHaveBeenCalledWith('cs-1')
    expect(dialog()?.textContent).toContain('Revert change set')
    expect(dialog()?.querySelectorAll('[data-testid="change-set-plan"] tbody tr')).toHaveLength(2)
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(revertChangeSet).toHaveBeenCalledWith('cs-1', 'h1')
    expect(dialog()).toBeNull()
    expect(w.find('[data-testid="change-set-reverted"]').exists()).toBe(true)
    expect(nativeConfirm).not.toHaveBeenCalled()
  })

  it('shows plan_changed inline and asks again with the reloaded plan', async () => {
    revertDryRun.mockResolvedValueOnce(result('sha256:a', 'h1')).mockResolvedValueOnce(result('sha256:c', 'h2'))
    revertChangeSet.mockResolvedValueOnce('plan_changed').mockResolvedValueOnce({ ...result('sha256:c', 'h2'), dry_run: false, change_set_id: 'cs-11' })
    const w = await mountList()
    await w.find('[data-testid="change-set-revert"]').trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(revertDryRun).toHaveBeenCalledTimes(2)
    expect(document.querySelector('[data-testid="confirm-warning"]')?.textContent).toContain('The configuration changed')
    expect(dialog()?.textContent).toContain('sha256:c')
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(revertChangeSet).toHaveBeenLastCalledWith('cs-1', 'h2')
    expect(dialog()).toBeNull()
  })

  it('offers no confirmation for an empty inverse plan', async () => {
    revertDryRun.mockResolvedValueOnce({ dry_run: true, change_set_id: null, plan_sha256: 'h0', plan: { changes: [], created: 0, updated: 0, deleted: 0 } } as ConfigApplyResult)
    const w = await mountList()
    await w.find('[data-testid="change-set-revert"]').trigger('click')
    await flushPromises()
    expect(dialog()).toBeNull()
    expect(w.find('[data-testid="change-set-nothing-to-revert"]').text()).toContain('nothing to revert')
    expect(revertChangeSet).not.toHaveBeenCalled()
  })

  it('sends one revert for a double click on confirm', async () => {
    revertDryRun.mockResolvedValueOnce(result('sha256:a', 'h1'))
    let answer!: (r: ConfigApplyResult) => void
    revertChangeSet.mockReturnValueOnce(new Promise((resolve) => (answer = resolve)))
    const w = await mountList()
    await w.find('[data-testid="change-set-revert"]').trigger('click')
    await flushPromises()
    const accept = document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement
    accept.click()
    accept.click()
    await flushPromises()
    answer({ ...result('sha256:a', 'h1'), dry_run: false, change_set_id: 'cs-10' })
    await flushPromises()
    expect(revertChangeSet).toHaveBeenCalledTimes(1)
    expect(w.find('[data-testid="change-set-reverted"]').exists()).toBe(true)
    expect(document.querySelector('.form-error')).toBeNull()
  })

  it('starts the step-up when the reloaded plan needs one', async () => {
    const assign = vi.fn()
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign, href: 'https://admin.test/change-sets', search: '' }, writable: true, configurable: true,
    })
    revertDryRun.mockResolvedValueOnce(result('sha256:a', 'h1')).mockResolvedValueOnce('step_up_required')
    revertChangeSet.mockResolvedValueOnce('plan_changed')
    const w = await mountList()
    await w.find('[data-testid="change-set-revert"]').trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-testid="confirm-accept"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fchange-sets')
    expect(document.querySelector('.form-error')).toBeNull()
  })

  it('cancels without reverting', async () => {
    revertDryRun.mockResolvedValueOnce(result('sha256:a', 'h1'))
    const w = await mountList()
    await w.find('[data-testid="change-set-revert"]').trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-testid="confirm-cancel"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(revertChangeSet).not.toHaveBeenCalled()
    expect(dialog()).toBeNull()
  })
})
