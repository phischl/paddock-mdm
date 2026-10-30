import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { h } from 'vue'
import { createPinia, setActivePinia } from 'pinia'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { VApp } from 'vuetify/components'
import PlatformMcp from '../views/PlatformMcp.vue'
import { createPortalI18n } from '../i18n'
import { vuetify } from '../plugins/vuetify'
import { pendingConfirm, settleConfirm } from '../composables/useConfirm'
import { useSessionStore } from '../stores/session'
import {
  availableToolCount,
  filterTools,
  groupByTag,
  platformTools,
  validSelection,
  type McpSettings,
  type McpSettingsInput,
  type McpTool,
} from '../lib/platformMcp'

function tool(operation_id: string, over: Partial<McpTool> = {}): McpTool {
  return {
    operation_id, method: 'GET', path: '/x', tag: 'organizations', scope: 'platform', class: 'read',
    step_up: false, destructive: false, exposed: true, summary: 'Summary of ' + operation_id, ...over,
  }
}

const catalog: McpTool[] = [
  tool('listOrganizations'),
  tool('createOrganization', { method: 'POST', class: 'write' }),
  tool('listPlatformSessions', { tag: 'sessions', summary: 'List the platform sessions' }),
  tool('rollbackAgentRelease', { tag: 'releases', class: 'write', step_up: true }),
  tool('getMcpCatalog', { tag: 'mcp', scope: 'any' }),
  tool('listDevices', { tag: 'devices', scope: 'organization' }),
  tool('getMcpAccess', { tag: 'mcp', exposed: false }),
]

const defaults: McpSettings = {
  enabled: false, write_enabled: false, mode: 'all', allowed_operations: [], updated_at: null, updated_by: null,
}

describe('platform MCP policy logic (plan M14 §3.6 item 31)', () => {
  it('offers only exposed tools of scope platform or any', () => {
    expect(platformTools(catalog).map((t) => t.operation_id)).toEqual([
      'listOrganizations', 'createOrganization', 'listPlatformSessions', 'rollbackAgentRelease', 'getMcpCatalog',
    ])
  })

  it('filters by operation id and summary, case-insensitively', () => {
    expect(filterTools(catalog, '  ').length).toBe(catalog.length)
    expect(filterTools(catalog, 'CREATEORG').map((t) => t.operation_id)).toEqual(['createOrganization'])
    expect(filterTools(catalog, 'platform sessions').map((t) => t.operation_id)).toEqual(['listPlatformSessions'])
  })

  it('groups by tag in catalog order', () => {
    expect(groupByTag(platformTools(catalog)).map((g) => [g.tag, g.tools.length])).toEqual([
      ['organizations', 2], ['sessions', 1], ['releases', 1], ['mcp', 1],
    ])
  })

  it('counts the tools a session can call: none while off, writes only when allowed, never step-up tools', () => {
    const tools = platformTools(catalog)
    const on: McpSettingsInput = { enabled: true, write_enabled: false, mode: 'all', allowed_operations: [] }
    expect(availableToolCount({ ...on, enabled: false }, tools)).toBe(0)
    expect(availableToolCount(on, tools)).toBe(3)
    expect(availableToolCount({ ...on, write_enabled: true }, tools)).toBe(4)
    const selected = { ...on, write_enabled: true, mode: 'selected' as const, allowed_operations: ['createOrganization'] }
    expect(availableToolCount(selected, tools)).toBe(1)
    expect(availableToolCount({ ...selected, write_enabled: false }, tools)).toBe(0)
  })

  it('needs at least one tool in mode selected', () => {
    const input: McpSettingsInput = { enabled: true, write_enabled: false, mode: 'selected', allowed_operations: [] }
    expect(validSelection(input)).toBe(false)
    expect(validSelection({ ...input, allowed_operations: ['listOrganizations'] })).toBe(true)
    expect(validSelection({ ...input, mode: 'all' })).toBe(true)
  })
})

let stored: McpSettings | string = defaults
const save = vi.fn<(input: McpSettingsInput) => Promise<McpSettings | string>>()
vi.mock('../lib/platformMcp', async (original) => ({
  ...(await original<typeof import('../lib/platformMcp')>()),
  getPlatformMcpSettings: () => Promise.resolve(stored),
  getMcpTools: () => Promise.resolve(catalog),
  savePlatformMcpSettings: (input: McpSettingsInput) => save(input),
}))

let wrapper: VueWrapper | null = null
const assign = vi.fn()

beforeEach(() => {
  sessionStorage.clear()
  save.mockReset()
  assign.mockReset()
  stored = defaults
  Object.defineProperty(window, 'location', {
    value: { ...window.location, assign, href: 'https://admin.test/platform/mcp', search: '' }, writable: true,
  })
})
afterEach(() => {
  wrapper?.unmount()
  wrapper = null
})

async function mountPage(): Promise<VueWrapper> {
  const pinia = createPinia()
  setActivePinia(pinia)
  useSessionStore().me = { id: 'p', username: 'root', display_name: 'Root', role: 'platform_admin', locale: 'en', organization: null } as never
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/platform/mcp', component: PlatformMcp }] })
  await router.push('/platform/mcp')
  await router.isReady()
  wrapper = mount(() => h(VApp, null, { default: () => h(RouterView) }), {
    global: { plugins: [createPortalI18n(), vuetify, router, pinia] }, attachTo: document.body,
  })
  await flushPromises()
  return wrapper
}

async function click(selector: string): Promise<void> {
  ;(document.querySelector(selector) as HTMLInputElement).click()
  await flushPromises()
}

async function submit(): Promise<void> {
  ;(document.querySelector('form') as HTMLFormElement).dispatchEvent(new Event('submit'))
  await flushPromises()
}

describe('PlatformMcp page (plan M14 §3.6 item 31)', () => {
  it('shows the defaults hint and the connect hint without a saved policy', async () => {
    const w = await mountPage()
    expect(w.find('h1').text()).toBe('AI assistants (MCP)')
    expect(w.find('[data-testid="mcp-defaults-hint"]').text()).toContain('the MCP is switched off for this platform')
    expect(w.find('[data-testid="mcp-disabled-hint"]').exists()).toBe(false)
    expect(w.find('[data-testid="mcp-connect-hint"]').text()).toContain('paddockctl mcp login')
    expect((document.querySelector('#mcp-enabled') as HTMLInputElement).checked).toBe(false)
  })

  it('shows the disabled hint for a saved policy that is switched off', async () => {
    stored = { ...defaults, updated_at: '2026-10-28T10:00:00Z', updated_by: 'b4d6f0f4-4b4a-4f8e-9a54-0d1c7f1c2a10' }
    const w = await mountPage()
    expect(w.find('[data-testid="mcp-defaults-hint"]').exists()).toBe(false)
    expect(w.find('[data-testid="mcp-disabled-hint"]').text()).toContain('every MCP session of this platform is refused')
  })

  it('lists only platform and any tools, step-up tools disabled as portal only, and filters them', async () => {
    const w = await mountPage()
    await click('[data-testid="mcp-mode-selected"] input')
    const rows = w.findAll('[data-testid^="mcp-tool-"]').map((r) => r.attributes('data-testid'))
    expect(rows).toEqual([
      'mcp-tool-listOrganizations', 'mcp-tool-createOrganization', 'mcp-tool-listPlatformSessions',
      'mcp-tool-rollbackAgentRelease', 'mcp-tool-getMcpCatalog',
    ])
    const stepUp = w.find('[data-testid="mcp-tool-rollbackAgentRelease"]')
    expect(stepUp.text()).toContain('portal only (step-up)')
    expect(stepUp.find('input').attributes('disabled')).toBeDefined()
    expect(w.find('[data-testid="mcp-tool-createOrganization"]').text()).toContain('write')
    expect(w.find('[data-testid="mcp-select-hint"]').text()).toBe('Select at least one tool.')
    expect(w.find('[data-testid="save-mcp"]').attributes('disabled')).toBeDefined()

    const field = document.querySelector('#mcp-filter') as HTMLInputElement
    field.value = 'sessions'
    field.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(w.findAll('[data-testid^="mcp-tool-"]').map((r) => r.attributes('data-testid'))).toEqual(['mcp-tool-listPlatformSessions'])
  })

  it('enabling and saving confirms, steps up, saves after the return and shows the saved state', async () => {
    save.mockResolvedValueOnce('step_up_required')
    await mountPage()
    await click('#mcp-enabled')
    await submit()
    expect(pendingConfirm.value?.options.title).toBe('Save MCP policy?')
    expect(pendingConfirm.value?.options.message).toBe(
      '3 tools will be available to MCP sessions of this platform; changes are refused.',
    )
    settleConfirm({ reason: '' })
    await flushPromises()
    const input: McpSettingsInput = { enabled: true, write_enabled: false, mode: 'all', allowed_operations: [] }
    expect(save).toHaveBeenCalledWith(input)
    expect(assign).toHaveBeenCalledWith('/api/auth/stepup?return_to=%2Fplatform%2Fmcp')
    wrapper?.unmount()

    const savedPolicy: McpSettings = { ...input, updated_at: '2026-10-29T09:00:00Z', updated_by: 'b4d6f0f4-4b4a-4f8e-9a54-0d1c7f1c2a10' }
    save.mockResolvedValueOnce(savedPolicy)
    const resumed = await mountPage()
    expect(save).toHaveBeenLastCalledWith(input)
    expect(document.body.textContent).toContain('MCP policy saved.')
    expect((document.querySelector('#mcp-enabled') as HTMLInputElement).checked).toBe(true)
    expect(resumed.find('[data-testid="mcp-defaults-hint"]').exists()).toBe(false)
    expect(resumed.find('[data-testid="mcp-disabled-hint"]').exists()).toBe(false)
  })

  it('does not save when the confirmation is cancelled', async () => {
    await mountPage()
    await click('#mcp-enabled')
    await submit()
    settleConfirm(false)
    await flushPromises()
    expect(save).not.toHaveBeenCalled()
  })

  it('reports a refused step-up and a refused policy as problems', async () => {
    sessionStorage.setItem('paddock.stepup', JSON.stringify({ action: 'mcp-settings', target: 'platform', payload: {}, at: Date.now() }))
    Object.defineProperty(window, 'location', {
      value: { ...window.location, assign, href: 'https://admin.test/platform/mcp?stepup=failed', search: '?stepup=failed' }, writable: true,
    })
    const w = await mountPage()
    expect(save).not.toHaveBeenCalled()
    expect(w.find('[data-testid="mcp-problem"]').text()).toContain('identity confirmation failed')
    wrapper?.unmount()

    stored = 'not_found'
    const refused = await mountPage()
    expect(refused.find('[data-testid="mcp-problem"]').exists()).toBe(true)
    expect(refused.find('form').exists()).toBe(false)
  })
})
