import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import McpSettings from '../views/McpSettings.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { useSessionStore } from '../stores/session'
import type { McpProblem, McpSettings as Settings, McpSettingsInput, McpTool } from '../lib/mcp'

function tool(operation_id: string, over: Partial<McpTool> = {}): McpTool {
  return {
    operation_id, method: 'GET', path: '/api/v1/x', tag: 'devices', scope: 'organization', class: 'read',
    step_up: false, destructive: false, exposed: true, summary: operation_id + ' summary', ...over,
  }
}

const catalog: McpTool[] = [
  tool('listDevices', { summary: 'List devices' }),
  tool('lockDevice', { class: 'write', step_up: true, exposed: false, summary: 'Lock a device' }),
  tool('revealLocalAdmin', { tag: 'local-admin', class: 'write', step_up: true, exposed: false, summary: 'Reveal the password' }),
  tool('createDeviceGroup', { tag: 'device-groups', class: 'write', method: 'POST', summary: 'Create a device group' }),
  tool('listOrganizations', { tag: 'organizations', scope: 'platform', summary: 'List organizations' }),
]

const defaults: Settings = { enabled: false, write_enabled: false, mode: 'all', allowed_operations: [], updated_at: null, updated_by: null }
let settings: Settings = defaults
const saveMcpSettings = vi.fn<(input: McpSettingsInput) => Promise<Settings | McpProblem>>()
vi.mock('../lib/mcp', async (original) => ({
  ...(await original<typeof import('../lib/mcp')>()),
  getMcpSettings: () => Promise.resolve(settings),
  getMcpCatalog: () => Promise.resolve(catalog),
  saveMcpSettings: (input: McpSettingsInput) => saveMcpSettings(input),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  saveMcpSettings.mockReset()
  assign.mockReset()
  settings = defaults
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/settings/mcp', search: '' }, writable: true,
  })
})
afterEach(() => {
  settleConfirm(false)
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(role = 'org_admin'): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'a', username: 'alice', display_name: 'Alice', role, locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/settings/mcp', component: McpSettings }] })
  await router.push('/settings/mcp')
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

async function check(id: string, on = true): Promise<void> {
  const el = input(id)
  el.checked = on
  el.dispatchEvent(new Event('change'))
  el.dispatchEvent(new Event('input'))
  await flushPromises()
}

async function chooseSelected(w: VueWrapper): Promise<void> {
  await w.find('[data-testid="mcp-mode-selected"] input').setValue(true)
  await flushPromises()
}

async function submit(): Promise<void> {
  ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
  await flushPromises()
}

describe('McpSettings (plan M14 §3.6 item 29)', () => {
  it('shows the defaults hint without a saved policy and starts with changes allowed once the MCP is switched on', async () => {
    const w = await mountPage()
    expect(w.find('h1').text()).toBe('AI assistants (MCP)')
    expect(w.find('[data-testid="mcp-defaults-hint"]').text()).toContain('the MCP is switched off for this organization')
    expect(w.find('[data-testid="mcp-disabled-hint"]').exists()).toBe(false)
    expect(w.find('[data-testid="mcp-updated-at"]').exists()).toBe(false)
    expect(input('mcp-enabled').checked).toBe(false)
    expect(input('mcp-write-enabled').checked).toBe(false)
    expect((w.find('[data-testid="mcp-mode-all"] input').element as HTMLInputElement).checked).toBe(true)
    expect(w.find('[data-testid="mcp-tool-picker"]').exists()).toBe(false)

    await check('mcp-enabled')
    expect(input('mcp-write-enabled').checked).toBe(true)
    await check('mcp-write-enabled', false)
    expect(input('mcp-write-enabled').checked).toBe(false)
    expect(input('mcp-enabled').checked).toBe(true)
  })

  it('names paddockctl mcp login and links the operations guide', async () => {
    const w = await mountPage()
    expect(w.find('[data-testid="mcp-connect-hint"]').text()).toContain('paddockctl mcp login')
    expect(w.find('[data-testid="mcp-guide"]').attributes('href')).toMatch(/docs\/operations\/mcp\.md$/)
  })

  it('lists the organization tools by tag, filters them and keeps step-up tools out of reach', async () => {
    const w = await mountPage()
    await chooseSelected(w)
    const tags = w.findAll('.mcp-group').map((g) => g.attributes('data-tag'))
    expect(tags).toEqual(['device-groups', 'devices', 'local-admin'])
    expect(w.find('[data-tool="listOrganizations"]').exists()).toBe(false)
    for (const id of ['lockDevice', 'revealLocalAdmin']) {
      const row = w.find(`[data-tool="${id}"]`)
      expect(input('mcp-tool-' + id).disabled).toBe(true)
      expect(row.find('[data-testid="mcp-tool-portal-only"]').text()).toBe('portal only (step-up)')
    }
    expect(input('mcp-tool-listDevices').disabled).toBe(false)
    expect(w.find('[data-tool="createDeviceGroup"] .pd-chip').text()).toBe('write')
    expect(w.find('[data-tool="listDevices"] .pd-chip').text()).toBe('read')

    await w.find('#mcp-tool-filter').setValue('device group')
    expect(w.findAll('.mcp-tool').map((r) => r.attributes('data-tool'))).toEqual(['createDeviceGroup'])
    await w.find('#mcp-tool-filter').setValue('LISTDEV')
    expect(w.findAll('.mcp-tool').map((r) => r.attributes('data-tool'))).toEqual(['listDevices'])
  })

  it('refuses to save selected tools without a selection', async () => {
    const w = await mountPage()
    await chooseSelected(w)
    await submit()
    expect(pendingConfirm.value).toBeNull()
    expect(w.find('.form-error').text()).toContain('Select at least one tool')
    expect(saveMcpSettings).not.toHaveBeenCalled()
  })

  it('confirms with the count, steps up and repeats the save once on return', async () => {
    saveMcpSettings.mockResolvedValueOnce({ code: 'step_up_required' })
    const w = await mountPage()
    await check('mcp-enabled')
    await chooseSelected(w)
    await check('mcp-tool-listDevices')
    await submit()
    expect(pendingConfirm.value?.options.title).toBe('Save MCP policy?')
    expect(pendingConfirm.value?.options.message)
      .toBe('1 tools will be available to MCP sessions of this organization; changes stay possible.')
    settleConfirm({ reason: '' })
    await flushPromises()
    const sent = { enabled: true, write_enabled: true, mode: 'selected', allowed_operations: ['listDevices'] }
    expect(saveMcpSettings).toHaveBeenCalledWith(sent)
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fsettings%2Fmcp')
    wrapper?.unmount()

    const stored: Settings = { ...(sent as McpSettingsInput), updated_at: '2026-10-29T10:00:00Z', updated_by: 'a' }
    saveMcpSettings.mockResolvedValueOnce(stored)
    const resumed = await mountPage()
    expect(saveMcpSettings).toHaveBeenCalledTimes(2)
    expect(saveMcpSettings).toHaveBeenLastCalledWith(sent)
    expect(pendingConfirm.value).toBeNull()
    expect(document.body.textContent).toContain('MCP policy saved.')
    expect(resumed.find('[data-testid="mcp-updated-at"]').text()).toContain('Oct 29, 2026')
    expect(resumed.find('[data-testid="mcp-defaults-hint"]').exists()).toBe(false)
    expect(input('mcp-tool-listDevices').checked).toBe(true)
  })

  it('counts every selectable tool for all tools and says changes are refused', async () => {
    saveMcpSettings.mockResolvedValueOnce({ ...defaults, enabled: true, updated_at: '2026-10-29T10:00:00Z' })
    await mountPage()
    await check('mcp-enabled')
    await check('mcp-write-enabled', false)
    await submit()
    expect(pendingConfirm.value?.options.message)
      .toBe('2 tools will be available to MCP sessions of this organization; changes are refused.')
    settleConfirm({ reason: '' })
    await flushPromises()
    expect(saveMcpSettings).toHaveBeenCalledWith({ enabled: true, write_enabled: false, mode: 'all', allowed_operations: [] })
  })

  it('keeps the resumed choice for changes when the repeated save fails', async () => {
    const payload = { enabled: true, write_enabled: false, mode: 'all', allowed_operations: [] }
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'mcp-settings', target: 'organization', payload, at: Date.now() }))
    saveMcpSettings.mockResolvedValueOnce({ code: 'invalid_request' })
    const w = await mountPage()
    expect(saveMcpSettings).toHaveBeenCalledWith(payload)
    expect(w.find('[data-testid="mcp-problem"]').exists()).toBe(true)
    expect(input('mcp-enabled').checked).toBe(true)
    expect(input('mcp-write-enabled').checked).toBe(false)
  })

  it('shows the problem and its detail inline when the server refuses the policy', async () => {
    saveMcpSettings.mockResolvedValueOnce({ code: 'invalid_request', detail: 'unknown operation "nope"' })
    const w = await mountPage()
    await submit()
    settleConfirm({ reason: '' })
    await flushPromises()
    const alert = w.find('[data-testid="mcp-problem"]').text()
    expect(alert).toContain('The request was not valid.')
    expect(alert).toContain('unknown operation "nope"')
    expect(document.body.textContent).not.toContain('MCP policy saved.')
  })

  it('shows the switched-off hint for a saved policy that is off', async () => {
    settings = { ...defaults, updated_at: '2026-10-29T10:00:00Z', updated_by: 'a' }
    const w = await mountPage()
    expect(w.find('[data-testid="mcp-disabled-hint"]').text()).toContain('every MCP session of this organization is refused')
    expect(w.find('[data-testid="mcp-defaults-hint"]').exists()).toBe(false)
    await check('mcp-enabled')
    expect(input('mcp-write-enabled').checked).toBe(false)
  })

  it.each(['org_operator', 'org_auditor'])('is readable but not editable for %s', async (role) => {
    settings = { enabled: true, write_enabled: false, mode: 'selected', allowed_operations: ['listDevices'], updated_at: '2026-10-29T10:00:00Z', updated_by: 'a' }
    const w = await mountPage(role)
    expect(w.find('h1').text()).toBe('AI assistants (MCP)')
    expect(input('mcp-enabled').checked).toBe(true)
    expect(input('mcp-enabled').disabled).toBe(true)
    expect(input('mcp-write-enabled').disabled).toBe(true)
    expect((w.find('[data-testid="mcp-mode-selected"] input').element as HTMLInputElement).disabled).toBe(true)
    expect(input('mcp-tool-listDevices').checked).toBe(true)
    expect(input('mcp-tool-listDevices').disabled).toBe(true)
    expect(w.find('[data-testid="save-mcp"]').exists()).toBe(false)
  })
})
