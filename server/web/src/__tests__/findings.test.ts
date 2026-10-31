import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { Finding } from '../api/client'
import FindingAssignDialog from '../components/FindingAssignDialog.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import FindingsView from '../views/Findings.vue'

const base: Finding = {
  id: 'f1', kind: 'attention', key: 'attention:a1', code: 'stale_critical', subject: '', device_id: 'd1', hostname: 'acme-lt-0142',
  status: 'open', assignee: null, opened_at: '2026-10-30T10:00:00Z', last_seen_at: '2026-10-31T10:00:00Z', occurrences: 1,
  first_event_id: null, last_event_id: null, acknowledged_at: null, closed_at: null, closed_by: null, reason: null, external_ref: null,
  cleared_at: null,
}
const tamper: Finding = {
  ...base, id: 'f2', kind: 'tamper', key: 'tamper:d1:device.tamper_sudoers_d_file:/etc/sudoers.d/x', code: 'device.tamper_sudoers_d_file',
  subject: '/etc/sudoers.d/x', occurrences: 3, status: 'in_progress', assignee: { id: 'u1', username: 'bob', display_name: 'Bob Builder' },
}
const closedFinding: Finding = { ...base, id: 'f3', status: 'false_positive', closed_at: '2026-10-31T11:00:00Z', closed_by: 'alice', reason: 'test lab' }

const accountsResult = vi.hoisted(() => ({ value: null as Promise<unknown> | null }))
let items: Finding[] = [base, tamper, closedFinding]
const queries: unknown[] = []
const calls = vi.hoisted(() => ({
  acknowledge: vi.fn(), assign: vi.fn(), close: vi.fn(), reopen: vi.fn(),
}))
vi.mock('../lib/findings', async (original) => ({
  ...(await original<typeof import('../lib/findings')>()),
  listFindings: (p: unknown) => {
    queries.push(p)
    return Promise.resolve({ items, page: 1, page_size: 25, total: items.length, total_capped: false, sort: '-last_seen_at' })
  },
  listAccounts: () => accountsResult.value ?? Promise.resolve([
    { id: 'u1', username: 'bob', display_name: 'Bob Builder', role: 'org_operator' },
    { id: 'u2', username: 'alice', display_name: 'Alice Admin', role: 'org_admin' },
  ]),
  acknowledgeFinding: calls.acknowledge,
  assignFinding: calls.assign,
  closeFinding: calls.close,
  reopenFinding: calls.reopen,
}))

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
  settleConfirm(false)
  items = [base, tamper, closedFinding]
  queries.length = 0
  accountsResult.value = null
  for (const c of Object.values(calls)) c.mockReset()
  document.body.innerHTML = ''
})

async function mountFindings(role = 'org_admin', path = '/findings'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', theme: 'system', organization: null } as never
  const stub = { render: () => null }
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/findings', component: stub }, { path: '/devices/:id', name: 'device', component: stub }] })
  await router.push(path)
  wrapper = mount(() => h(VApp, null, { default: () => h(FindingsView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

const rows = (w: VueWrapper) => w.findAll('[data-testid="finding-list"] tbody tr')
const body = (testid: string) => document.body.querySelector<HTMLElement>(`[data-testid="${testid}"]`)
const buttonsOf = (row: ReturnType<typeof rows>[number]) => row.findAll('button').map((b) => b.text())

describe('findings page', () => {
  it('lists the findings with status chip, device link, subject, occurrences and assignee', async () => {
    const w = await mountFindings()
    const r = rows(w)
    expect(r).toHaveLength(3)
    expect(r[0].text()).toContain('Silent (critical)')
    expect(r[0].find('[data-testid="finding-status-open"]').text()).toBe('Open')
    expect(r[0].find('a.mono').text()).toBe('acme-lt-0142')
    expect(r[1].text()).toContain('device.tamper_sudoers_d_file')
    expect(r[1].text()).toContain('/etc/sudoers.d/x')
    expect(r[1].text()).toContain('Bob Builder')
    expect(r[1].find('[data-testid="finding-status-in_progress"]').text()).toBe('In progress')
    expect(queries[0]).toMatchObject({ sort: '-last_seen_at' })
  })

  it('offers each step only where the finding can take it', async () => {
    const w = await mountFindings()
    const r = rows(w)
    expect(buttonsOf(r[0])).toEqual(['Acknowledge', 'Assign', 'Close'])
    expect(buttonsOf(r[1])).toEqual(['Assign', 'Close'])
    expect(buttonsOf(r[2])).toEqual(['Reopen'])
  })

  it('shows an auditor the findings without any action', async () => {
    const w = await mountFindings('org_auditor')
    expect(rows(w)).toHaveLength(3)
    expect(w.findAll('[data-testid="finding-list"] tbody button')).toHaveLength(0)
  })

  it('acknowledges after a modal confirmation and shows the new status inline', async () => {
    const confirmSpy = vi.spyOn(window, 'confirm')
    calls.acknowledge.mockResolvedValue({ ...base, status: 'acknowledged' })
    const w = await mountFindings()
    await rows(w)[0].findAll('button')[0].trigger('click')
    await flushPromises()
    expect(pendingConfirm.value?.options).toMatchObject({ title: 'Acknowledge finding', confirmLabel: 'Acknowledge' })
    expect(calls.acknowledge).not.toHaveBeenCalled()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(calls.acknowledge).toHaveBeenCalledWith('f1')
    expect(w.find('[data-testid="finding-done"]').text()).toBe('Silent (critical) on acme-lt-0142 is now Acknowledged.')
    expect(confirmSpy).not.toHaveBeenCalled()
    expect(queries.length).toBeGreaterThan(1)
  })

  it('does not acknowledge when the confirmation is cancelled', async () => {
    const w = await mountFindings()
    await rows(w)[0].findAll('button')[0].trigger('click')
    await flushPromises()
    settleConfirm(false)
    await flushPromises()
    expect(calls.acknowledge).not.toHaveBeenCalled()
  })

  it('surfaces a refused step as an inline alert', async () => {
    calls.acknowledge.mockResolvedValue('invalid_state')
    const w = await mountFindings()
    await rows(w)[0].findAll('button')[0].trigger('click')
    await flushPromises()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(w.find('[data-testid="finding-problem"]').text()).toBe('This action is not possible in the current state.')
    expect(w.find('[data-testid="finding-done"]').exists()).toBe(false)
  })

  it('reopens with a required reason', async () => {
    calls.reopen.mockResolvedValue({ ...closedFinding, status: 'open', closed_at: null })
    const w = await mountFindings()
    await rows(w)[2].findAll('button')[0].trigger('click')
    await flushPromises()
    expect(pendingConfirm.value?.options.reason).toMatchObject({ required: true, maxLength: 1000 })
    settleConfirm({ reason: 'happened again' })
    await flushPromises()
    expect(calls.reopen).toHaveBeenCalledWith('f3', 'happened again')
    expect(w.find('[data-testid="finding-done"]').text()).toContain('is now Open')
  })

  it('closes with a resolution and a required reason, then shows the status', async () => {
    calls.close.mockResolvedValue({ ...base, status: 'false_positive', closed_at: '2026-10-31T12:00:00Z' })
    const w = await mountFindings()
    await rows(w)[0].findAll('button')[2].trigger('click')
    await flushPromises()
    expect(body('finding-close-dialog')).not.toBeNull()
    expect(body('finding-close-dialog')!.textContent).toContain('Close Silent (critical) on acme-lt-0142')
    expect(body('finding-close-dialog')!.textContent).not.toContain('stale_critical')
    expect(document.body.textContent).toContain('Facts and ticket references, no personal judgements.')
    body('finding-resolution-false_positive')!.querySelector('input')!.click()
    body('finding-close-submit')!.click()
    await flushPromises()
    expect(calls.close).not.toHaveBeenCalled()
    expect(document.body.textContent).toContain('Enter a reason.')
    const reason = body('finding-reason')!.querySelector('textarea')!
    reason.value = 'lab device, CHG-4711'
    reason.dispatchEvent(new Event('input'))
    body('finding-external-ref')!.querySelector('input')!.value = 'CHG-4711'
    body('finding-external-ref')!.querySelector('input')!.dispatchEvent(new Event('input'))
    await flushPromises()
    body('finding-close-submit')!.click()
    await flushPromises()
    expect(calls.close).toHaveBeenCalledWith('f1', { resolution: 'false_positive', reason: 'lab device, CHG-4711', externalRef: 'CHG-4711' })
    expect(body('finding-close-dialog')).toBeNull()
    expect(w.find('[data-testid="finding-done"]').text()).toContain('is now False positive')
  })

  it('offers accepted risk to administrators only', async () => {
    let w = await mountFindings('org_admin')
    await rows(w)[0].findAll('button')[2].trigger('click')
    await flushPromises()
    expect(body('finding-resolution-accepted_risk')!.querySelector('input')!.disabled).toBe(false)
    expect(body('finding-accepted-risk-hint')).toBeNull()
    w.unmount()
    wrapper = null
    document.body.innerHTML = ''

    w = await mountFindings('org_operator')
    await rows(w)[0].findAll('button')[2].trigger('click')
    await flushPromises()
    expect(body('finding-resolution-accepted_risk')!.querySelector('input')!.disabled).toBe(true)
    expect(body('finding-resolution-resolved')!.querySelector('input')!.disabled).toBe(false)
    expect(body('finding-accepted-risk-hint')!.textContent).toContain('needs an organization administrator')
  })

  it('keeps the close dialog open and shows a refused close inline', async () => {
    calls.close.mockResolvedValue('forbidden')
    const w = await mountFindings()
    await rows(w)[0].findAll('button')[2].trigger('click')
    await flushPromises()
    const reason = body('finding-reason')!.querySelector('textarea')!
    reason.value = 'fine'
    reason.dispatchEvent(new Event('input'))
    await flushPromises()
    body('finding-close-submit')!.click()
    await flushPromises()
    expect(body('finding-close-dialog')!.querySelector('.form-error')!.textContent).toBe('You are not allowed to do this.')
    expect(w.find('[data-testid="finding-done"]').exists()).toBe(false)
  })

  it('names an attention finding by its label in the assign dialog', async () => {
    const w = await mountFindings()
    await rows(w)[0].findAll('button')[1].trigger('click')
    await flushPromises()
    expect(body('finding-assign-dialog')!.textContent).toContain('Who takes care of Silent (critical) on acme-lt-0142?')
    expect(body('finding-assign-dialog')!.textContent).not.toContain('stale_critical')
  })

  it('assigns through the assign dialog', async () => {
    calls.assign.mockResolvedValue({ ...base, status: 'in_progress', assignee: { id: 'u1', username: 'bob', display_name: 'Bob Builder' } })
    const w = await mountFindings()
    await rows(w)[1].findAll('button')[0].trigger('click')
    await flushPromises()
    expect(body('finding-assign-dialog')).not.toBeNull()
    body('finding-assign-submit')!.click()
    await flushPromises()
    expect(calls.assign).toHaveBeenCalledWith('f2', 'u1')
    expect(w.find('[data-testid="finding-done"]').exists()).toBe(true)
  })
})

describe('FindingAssignDialog', () => {
  it('shows a failed account load as an inline alert', async () => {
    accountsResult.value = Promise.resolve('forbidden')
    wrapper = mount(FindingAssignDialog, {
      props: { modelValue: true, finding: base, problem: '', pending: false },
      global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body,
    })
    await flushPromises()
    expect(document.body.querySelector('.form-error')!.textContent).toBe('You are not allowed to do this.')
  })

  it('submits the current assignee and shows a refusal inline', async () => {
    wrapper = mount(FindingAssignDialog, {
      props: { modelValue: true, finding: tamper, problem: 'invalid_state', pending: false },
      global: { plugins: [createPortalI18n(), vuetify] }, attachTo: document.body,
    })
    await flushPromises()
    expect(document.body.querySelector('.form-error')!.textContent).toBe('This action is not possible in the current state.')
    body('finding-assign-submit')!.click()
    expect(wrapper.emitted('submit')).toEqual([['u1']])
    body('finding-assign-cancel')!.click()
    expect(wrapper.emitted('cancel')).toHaveLength(1)
  })
})
