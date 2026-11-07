import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createRouter, createMemoryHistory } from 'vue-router'
import { VApp } from 'vuetify/components'
import { createPinia, setActivePinia } from 'pinia'
import type { Diagnostics } from '../api/client'
import ConfirmDialog from '../components/ConfirmDialog.vue'
import DiagnosticsList from '../components/DiagnosticsList.vue'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { createPortalI18n } from '../i18n'
import { diagnosticsStateView, validReason } from '../lib/diagnostics'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'

const mocks = vi.hoisted(() => ({
  downloadDiagnostics: vi.fn(),
  purgeDiagnostics: vi.fn(),
  saveFile: vi.fn(),
  startStepUp: vi.fn(),
  resumeStepUp: vi.fn(),
}))

vi.mock('../lib/diagnostics', async (original) => ({
  ...(await original<typeof import('../lib/diagnostics')>()),
  downloadDiagnostics: mocks.downloadDiagnostics,
  purgeDiagnostics: mocks.purgeDiagnostics,
}))
vi.mock('../lib/disk', async (original) => ({
  ...(await original<typeof import('../lib/disk')>()),
  saveFile: mocks.saveFile,
}))
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: mocks.startStepUp,
  resumeStepUp: mocks.resumeStepUp,
}))

const at = '2026-11-05T10:00:00Z'
const bundle = (id: string, state: Diagnostics['state']): Diagnostics => ({
  id, device_id: 'd1', hostname: 'lt-1', requested_by: 'Alice', requested_at: at, reason: 'VPN fails', state,
  truncated_entries: [], download_count: 0, ...(state === 'stored' ? { size: 3 << 20, expires_at: at } : {}),
})
const page = (items: Diagnostics[]) => () => Promise.resolve({ items, page: 1, page_size: 25, total: items.length, total_capped: false, sort: '-requested_at' })

let wrapper: VueWrapper | null = null

async function mountList(role: string, items: Diagnostics[], locale: 'en' | 'de' = 'en'): Promise<void> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', theme: 'system', organization: null } as never
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/', component: { render: () => null } },
      { path: '/diagnostics', component: { render: () => null } },
      { path: '/devices/:id/diagnostics', name: 'device-diagnostics', component: { render: () => null } },
    ],
  })
  await router.push('/diagnostics')
  // App.vue hosts the single ConfirmDialog in the portal; the test hosts it the same way.
  const Host = defineComponent({
    setup: () => () => h(VApp, null, {
      default: () => [
        h(DiagnosticsList, { fetch: page(items), fleet: true }),
        pendingConfirm.value
          ? h(ConfirmDialog, {
            key: pendingConfirm.value.id, modelValue: true, ...pendingConfirm.value.options,
            onConfirm: (answer: { reason: string }) => settleConfirm(answer), onCancel: () => settleConfirm(false),
          })
          : null,
      ],
    }),
  })
  wrapper = mount(Host, { global: { plugins: [createPortalI18n(locale), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
}

function button(testid: string): HTMLElement | null {
  return document.querySelector(`[data-testid="${testid}"]`)
}

describe('diagnostics list', () => {
  beforeEach(() => {
    for (const m of Object.values(mocks)) m.mockReset()
    mocks.resumeStepUp.mockReturnValue(null)
  })
  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  it('offers download and purge on stored bundles only; the purge to administrators only', async () => {
    await mountList('org_operator', [bundle('b1', 'stored'), bundle('b2', 'requested')])
    expect(document.querySelectorAll('[data-testid="diagnostics-download"]')).toHaveLength(1)
    expect(button('diagnostics-purge')).toBeNull()
    expect(document.body.textContent).toContain('lt-1')
    wrapper?.unmount()

    await mountList('org_admin', [bundle('b1', 'stored')])
    expect(button('diagnostics-purge')).not.toBeNull()
  })

  it('starts the step-up when the server asks for it and downloads once it is back', async () => {
    mocks.downloadDiagnostics.mockResolvedValueOnce('step_up_required')
    await mountList('org_operator', [bundle('b1', 'stored')])
    button('diagnostics-download')?.click()
    await flushPromises()
    expect(mocks.startStepUp).toHaveBeenCalledWith('diagnostics-download', 'diagnostics', 'b1')
    expect(mocks.saveFile).not.toHaveBeenCalled()
    wrapper?.unmount()

    const file = { blob: new Blob(['x']), filename: 'paddock-diagnostics-lt-1-b1.tar.gz' }
    mocks.resumeStepUp.mockReturnValue({ failed: false, payload: 'b1' })
    mocks.downloadDiagnostics.mockResolvedValueOnce(file)
    await mountList('org_operator', [bundle('b1', 'stored')])
    expect(mocks.resumeStepUp).toHaveBeenCalledWith('diagnostics-download', 'diagnostics')
    // A resumed download waits for the router to drop the step-up parameter first.
    await vi.waitFor(() => expect(mocks.saveFile).toHaveBeenCalledWith(file))
    expect(mocks.downloadDiagnostics).toHaveBeenCalledTimes(2)
    expect(mocks.downloadDiagnostics).toHaveBeenLastCalledWith('b1')
    expect(mocks.startStepUp).toHaveBeenCalledTimes(1)
  })

  it('shows a refused download inline and never starts a second step-up after one', async () => {
    mocks.resumeStepUp.mockReturnValue({ failed: false, payload: 'b1' })
    mocks.downloadDiagnostics.mockResolvedValueOnce('invalid_state')
    await mountList('org_admin', [bundle('b1', 'stored')])
    await vi.waitFor(() => expect(button('diagnostics-problem')?.textContent).toContain('not possible in the current state'))
    expect(mocks.startStepUp).not.toHaveBeenCalled()
  })

  it('says when no user was notified of a collection, and only then', async () => {
    await mountList('org_admin', [
      { ...bundle('b1', 'stored'), notified_sessions: 0 },
      { ...bundle('b2', 'stored'), notified_sessions: 1 },
      bundle('b3', 'requested'),
    ])
    const chips = document.querySelectorAll('[data-testid="diagnostics-not-notified"]')
    expect(chips).toHaveLength(1)
    expect(chips[0].textContent).toContain('User not notified')
    expect(chips[0].getAttribute('title')).toContain('transparency notice')
  })

  it('says in German when no user was notified', async () => {
    await mountList('org_admin', [{ ...bundle('b1', 'stored'), notified_sessions: 0 }], 'de')
    const chip = document.querySelector('[data-testid="diagnostics-not-notified"]')
    expect(chip?.textContent).toContain('Benutzer nicht benachrichtigt')
    expect(chip?.getAttribute('title')).toContain('Transparenzhinweis')
  })

  it('purges after the confirmation dialog only', async () => {
    mocks.purgeDiagnostics.mockResolvedValue(null)
    await mountList('org_admin', [bundle('b1', 'stored')])
    button('diagnostics-purge')?.click()
    await flushPromises()
    expect(document.body.textContent).toContain('Delete the diagnostics bundle of lt-1 now?')
    expect(mocks.purgeDiagnostics).not.toHaveBeenCalled()
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(mocks.purgeDiagnostics).toHaveBeenCalledWith('b1')
  })
})

describe('diagnostics lib', () => {
  it('accepts reasons of 2 to 500 characters', () => {
    expect(validReason(' x ')).toBe(false)
    expect(validReason('ok')).toBe(true)
    expect(validReason('ä'.repeat(500))).toBe(true)
    expect(validReason('ä'.repeat(501))).toBe(false)
  })

  it('maps every state to a chip', () => {
    expect(diagnosticsStateView('stored')).toEqual({ status: 'ok', label: 'diagnostics.states.stored' })
    expect(diagnosticsStateView('failed').status).toBe('critical')
  })
})
