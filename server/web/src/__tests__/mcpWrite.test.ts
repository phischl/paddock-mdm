import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import App from '../App.vue'
import { api, type Me } from '../api/client'
import { createPortalI18n, type PortalLocale } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { useSessionStore } from '../stores/session'
import { settleConfirm } from '../composables/useConfirm'
import { formatDateTime } from '../lib/format'

vi.mock('../lib/updates', async (original) => ({
  ...(await original<typeof import('../lib/updates')>()),
  attentionCount: () => Promise.resolve(0),
}))

const started: { action: string; target: string }[] = []
let resumed: unknown = null
vi.mock('../lib/stepUp', async (original) => ({
  ...(await original<typeof import('../lib/stepUp')>()),
  startStepUp: (action: string, target: string) => started.push({ action, target }),
  resumeStepUp: (action: string, target: string) => {
    if (action !== 'mcp-write' || target !== 'me') return null
    const r = resumed
    resumed = null
    return r
  },
}))

const enabledAt = '2026-10-29T08:15:00Z'
const alice: Me = {
  id: '00000000-0000-0000-0000-000000000001', username: 'alice@acme.test', display_name: 'Alice Admin',
  role: 'org_admin', organization: { id: '00000000-0000-0000-0000-0000000000aa', slug: 'acme', name: 'Acme', domains: ['acme.test'] },
  locale: 'en', theme: 'system', revocation_enabled: false, client_ip: '198.51.100.7', step_up_valid_until: null,
  server_version: '0.1.0-alpha.7', alternate_role: null, channel: 'portal', mcp_write_enabled: false,
  mcp_write_enabled_at: null,
}
const aliceOn: Me = { ...alice, mcp_write_enabled: true, mcp_write_enabled_at: enabledAt }

type Answer = { data?: Me; error?: { code: string; status: number } }
let answers: Record<string, Answer[]> = {}
const posts: string[] = []

let wrapper: VueWrapper | null = null

beforeEach(() => {
  localStorage.clear()
  Object.defineProperty(window, 'innerWidth', { value: 1920, configurable: true, writable: true })
  started.length = 0
  posts.length = 0
  resumed = null
  answers = {}
  vi.spyOn(api, 'POST').mockImplementation(((path: string) => {
    posts.push(path)
    const next = answers[path]?.shift()
    if (!next) throw new Error('unexpected POST ' + path)
    return Promise.resolve(next)
  }) as unknown as typeof api.POST)
})

afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
  vi.restoreAllMocks()
})

async function mountApp(me: Me, locale: PortalLocale = 'en'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = me
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:path(.*)*', component: { render: () => null } }] })
  await router.push('/')
  await router.isReady()
  wrapper = mount(App, { global: { plugins: [createPortalI18n(locale), vuetify, router, pinia] }, attachTo: document.body })
  await flushPromises()
  return wrapper
}

const query = (id: string) => document.querySelector<HTMLElement>(`[data-testid="${id}"]`)
const text = (id: string) => query(id)?.textContent?.replace(/\s+/g, ' ').trim()

async function openMenu(w: VueWrapper): Promise<void> {
  await w.get('[data-testid="user-menu"]').trigger('click')
  await vi.waitFor(() => expect(query('logout')).not.toBeNull())
}

async function openDialog(w: VueWrapper): Promise<void> {
  await openMenu(w)
  query('mcp-write-menu')!.click()
  await vi.waitFor(() => expect(query('mcp-write-dialog')).not.toBeNull())
}

async function confirmDialog(): Promise<HTMLElement> {
  await vi.waitFor(() => expect(query('confirm-dialog')).not.toBeNull())
  return query('confirm-dialog')!
}

describe('MCP write access in the account menu (plan M14 §3.6 item 32)', () => {
  it('shows the entry with the state and explains the layers with write access disabled', async () => {
    const w = await mountApp(alice)
    await openMenu(w)
    expect(text('mcp-write-menu')).toBe('AI assistant (MCP) Read only')
    query('mcp-write-menu')!.click()
    await vi.waitFor(() => expect(query('mcp-write-dialog')).not.toBeNull())
    const dialog = query('mcp-write-dialog')!
    expect(dialog.querySelector('h2')?.textContent?.trim()).toBe('AI assistant write access')
    expect(dialog.textContent).toContain('The MCP policy of your organization must allow changes too.')
    expect(dialog.textContent).toContain('paddockctl mcp login')
    expect(text('mcp-write-state')).toBe('Write access is disabled.')
    expect(query('mcp-write-enable')?.textContent?.trim()).toBe('Enable write access')
    expect(query('mcp-write-disable')).toBeNull()
  })

  it('confirms enabling destructively, then starts the step-up the server asks for', async () => {
    answers['/api/v1/me/mcp-write/enable'] = [{ error: { code: 'step_up_required', status: 403 } }]
    const w = await mountApp(alice)
    await openDialog(w)
    query('mcp-write-enable')!.click()
    const dialog = await confirmDialog()
    expect(dialog.textContent).toContain('Enable write access for AI assistants?')
    expect(dialog.textContent).toContain('A step-up follows.')
    expect(query('confirm-typed')).toBeNull()
    expect(query('confirm-accept')?.className).toContain('bg-error')
    query('confirm-accept')!.click()
    await flushPromises()
    expect(posts).toEqual(['/api/v1/me/mcp-write/enable'])
    expect(started).toEqual([{ action: 'mcp-write', target: 'me' }])
    expect(query('mcp-write-problem')).toBeNull()
  })

  it('does not call the server when enabling is cancelled', async () => {
    const w = await mountApp(alice)
    await openDialog(w)
    query('mcp-write-enable')!.click()
    await confirmDialog()
    query('confirm-cancel')!.click()
    await flushPromises()
    expect(posts).toEqual([])
    expect(text('mcp-write-state')).toBe('Write access is disabled.')
  })

  it('repeats enabling after the step-up and shows since when, also in the menu without a reload', async () => {
    answers['/api/v1/me/mcp-write/enable'] = [{ data: aliceOn }]
    resumed = { failed: false, payload: null }
    const w = await mountApp(alice)
    await vi.waitFor(() => expect(query('mcp-write-dialog')).not.toBeNull())
    await flushPromises()
    expect(posts).toEqual(['/api/v1/me/mcp-write/enable'])
    expect(text('mcp-write-state')).toBe(`Write access is enabled since ${formatDateTime(enabledAt, 'en')}.`)
    expect(query('mcp-write-disable')?.textContent?.trim()).toBe('Disable write access')
    expect(query('mcp-write-enable')).toBeNull()
    query('mcp-write-close')!.click()
    await openMenu(w)
    expect(text('mcp-write-menu')).toBe('AI assistant (MCP) Write access enabled')
  })

  it('shows a refused step-up inline and leaves the state unchanged', async () => {
    resumed = { failed: true }
    await mountApp(alice)
    await vi.waitFor(() => expect(query('mcp-write-problem')).not.toBeNull())
    expect(text('mcp-write-problem')).toContain('The identity confirmation failed.')
    expect(text('mcp-write-state')).toBe('Write access is disabled.')
    expect(posts).toEqual([])
    expect(started).toEqual([])
  })

  it('disables after a plain confirmation without a step-up', async () => {
    answers['/api/v1/me/mcp-write/disable'] = [{ data: alice }]
    const w = await mountApp(aliceOn)
    await openDialog(w)
    expect(text('mcp-write-state')).toBe(`Write access is enabled since ${formatDateTime(enabledAt, 'en')}.`)
    query('mcp-write-disable')!.click()
    const dialog = await confirmDialog()
    expect(dialog.textContent).toContain('Disable write access for AI assistants?')
    expect(query('confirm-typed')).toBeNull()
    expect(query('confirm-accept')?.className).not.toContain('bg-error')
    query('confirm-accept')!.click()
    await flushPromises()
    expect(posts).toEqual(['/api/v1/me/mcp-write/disable'])
    expect(started).toEqual([])
    expect(text('mcp-write-state')).toBe('Write access is disabled.')
    expect(query('mcp-write-enable')).not.toBeNull()
  })

  it('shows a refusal of the server inline', async () => {
    answers['/api/v1/me/mcp-write/disable'] = [{ error: { code: 'forbidden', status: 403 } }]
    const w = await mountApp(aliceOn)
    await openDialog(w)
    query('mcp-write-disable')!.click()
    await confirmDialog()
    query('confirm-accept')!.click()
    await flushPromises()
    expect(text('mcp-write-problem')).toBe('You are not allowed to do this.')
    expect(text('mcp-write-state')).toContain('Write access is enabled since')
  })

  it('falls back to a sentence without a time when the server names none', async () => {
    const w = await mountApp({ ...aliceOn, mcp_write_enabled_at: null })
    await openDialog(w)
    expect(text('mcp-write-state')).toBe('Write access is enabled.')
  })

  it('has no entry for an auditor', async () => {
    const w = await mountApp({ ...alice, role: 'org_auditor' })
    await openMenu(w)
    expect(query('mcp-write-menu')).toBeNull()
    expect(query('mcp-write-dialog')).toBeNull()
  })

  it('offers the entry to the platform administrator and names the platform policy', async () => {
    const w = await mountApp({ ...alice, role: 'platform_admin', organization: null })
    await openDialog(w)
    expect(query('mcp-write-dialog')?.textContent).toContain('The MCP policy of your platform must allow changes too.')
  })

  it('speaks German', async () => {
    const w = await mountApp({ ...aliceOn, locale: 'de' }, 'de')
    await openMenu(w)
    expect(text('mcp-write-menu')).toBe('KI-Assistent (MCP) Schreibzugriff aktiviert')
    query('mcp-write-menu')!.click()
    await vi.waitFor(() => expect(query('mcp-write-dialog')).not.toBeNull())
    expect(text('mcp-write-state')).toBe(`Schreibzugriff ist aktiviert seit ${formatDateTime(enabledAt, 'de')}.`)
  })
})
