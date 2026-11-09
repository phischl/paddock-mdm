import { afterEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import SoftwareRequests from '../views/SoftwareRequests.vue'
import { useSessionStore } from '../stores/session'
import { canDecide, softwareRequestStates, softwareRequestStatus } from '../lib/softwareRequests'
import type { SoftwareRequest } from '../api/client'
import en from '../locales/en.json'
import de from '../locales/de.json'

const request = (over: Partial<SoftwareRequest>): SoftwareRequest => ({
  id: 'r1', catalog_entry_id: 'e1', entry_name: 'GIMP', entry_approval: 'required', device_id: 'd1', hostname: 'lap-0421', user_id: 'u1',
  username: 'alice@acme.test', state: 'requested', requested_at: '2026-11-01T10:00:00Z', expires_at: '2026-12-01T10:00:00Z', decided_by: null,
  decided_at: null, decision_reason: null, ...over,
})
const rows = [
  request({}),
  request({
    id: 'r2', username: 'bob@acme.test', state: 'denied', decided_by: 'Carol Admin', decided_at: '2026-11-02T10:00:00Z',
    decision_reason: '<img src=x onerror=alert(1)> not licensed',
  }),
]
const decide = vi.hoisted(() => vi.fn())
const asked = vi.hoisted(() => ({ options: [] as { message: string; reason?: { required: boolean } }[], answer: false as false | { reason: string } }))

vi.mock('../lib/softwareRequests', async (original) => ({
  ...(await original<typeof import('../lib/softwareRequests')>()),
  listSoftwareRequests: () => Promise.resolve({ items: rows, page: 1, page_size: 25, total: rows.length, total_capped: false, sort: '-requested_at' }),
  decideSoftwareRequest: decide,
}))
vi.mock('../composables/useConfirm', async (original) => ({
  ...(await original<typeof import('../composables/useConfirm')>()),
  useConfirm: () => (options: { message: string; reason?: { required: boolean } }) => {
    asked.options.push(options)
    return Promise.resolve(asked.answer)
  },
}))

describe('software request states (plan M13c §3.7)', () => {
  it('labels every state in both languages', () => {
    for (const s of softwareRequestStates) {
      expect(en.softwareRequests.states[s]).toBeTruthy()
      expect(de.softwareRequests.states[s]).toBeTruthy()
    }
    expect(softwareRequestStatus('requested').status).toBe('warn')
    expect(softwareRequestStatus('approved').status).toBe('ok')
  })

  it('lets only an organization administrator decide, and only an open request', () => {
    expect(canDecide({ state: 'requested' }, true)).toBe(true)
    expect(canDecide({ state: 'requested' }, false)).toBe(false)
    for (const state of ['approved', 'denied', 'expired', 'withdrawn'] as const) expect(canDecide({ state }, true)).toBe(false)
  })
})

let wrapper: VueWrapper | null = null
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountList(role: string): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/software-requests', name: 'software-requests', component: { render: () => null } },
      { path: '/software-catalog/:id', name: 'software-catalog-entry', component: { render: () => null } },
      { path: '/devices/:id', name: 'device', component: { render: () => null } },
    ],
  })
  await router.push('/software-requests')
  wrapper = mount(() => h(VApp, null, { default: () => h(SoftwareRequests) }), { global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

function list(): Element {
  return document.querySelector('[data-testid="software-request-list"]') as Element
}

describe('SoftwareRequests', () => {
  it('lists the requests with state, user, device and the decision; the reason stays inert text', async () => {
    await mountList('org_admin')
    const text = list().textContent ?? ''
    for (const expected of ['GIMP', 'alice@acme.test', 'lap-0421', 'Waiting', 'Denied', 'by Carol Admin', '<img src=x onerror=alert(1)> not licensed']) {
      expect(text).toContain(expected)
    }
    expect(list().querySelector('img')).toBeNull()
    expect(list().querySelectorAll('[data-testid="approve-request"]')).toHaveLength(1)
  })

  it('shows no decision controls to operators and auditors', async () => {
    for (const role of ['org_operator', 'org_auditor']) {
      await mountList(role)
      expect(list().textContent).toContain('GIMP')
      expect(list().querySelector('[data-testid="approve-request"]')).toBeNull()
      expect(list().querySelector('[data-testid="deny-request"]')).toBeNull()
      wrapper?.unmount()
      wrapper = null
    }
  })

  it('denies only with a required reason from the dialog and sends nothing on cancel', async () => {
    decide.mockReset()
    asked.options.length = 0
    asked.answer = false
    await mountList('org_admin')
    ;(list().querySelector('[data-testid="deny-request"]') as HTMLElement).click()
    await flushPromises()
    expect(asked.options[0].reason?.required).toBe(true)
    expect(asked.options[0].message).toContain('alice@acme.test')
    expect(decide).not.toHaveBeenCalled()

    asked.answer = { reason: 'Not licensed' }
    decide.mockResolvedValue(null)
    ;(list().querySelector('[data-testid="deny-request"]') as HTMLElement).click()
    await flushPromises()
    expect(decide).toHaveBeenCalledWith('r1', 'deny', 'Not licensed')
    expect(document.querySelector('[data-testid="request-done"]')?.textContent).toContain('The request of alice@acme.test for GIMP is denied.')
  })

  it('approves with an optional reason and shows a refusal of the server', async () => {
    decide.mockReset()
    decide.mockResolvedValue('invalid_state')
    asked.options.length = 0
    asked.answer = { reason: '' }
    await mountList('org_admin')
    ;(list().querySelector('[data-testid="approve-request"]') as HTMLElement).click()
    await flushPromises()
    expect(asked.options[0].reason?.required).toBe(false)
    expect(decide).toHaveBeenCalledWith('r1', 'approve', '')
    expect(document.querySelector('[data-testid="request-problem"]')?.textContent).toBeTruthy()
  })
})
