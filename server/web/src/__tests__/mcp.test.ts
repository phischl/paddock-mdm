import { describe, expect, it } from 'vitest'
import {
  allowedCount, filterTools, groupByTag, policyForm, policyInput, scopeTools, selectable, type McpTool,
} from '../lib/mcp'

function tool(operation_id: string, over: Partial<McpTool> = {}): McpTool {
  return {
    operation_id, method: 'GET', path: '/api/v1/x', tag: 'devices', scope: 'organization', class: 'read',
    step_up: false, destructive: false, exposed: true, summary: operation_id + ' summary', ...over,
  }
}

const catalog: McpTool[] = [
  tool('listDevices', { summary: 'List the devices of the organization' }),
  tool('lockDevice', { class: 'write', step_up: true, exposed: false }),
  tool('createDeviceGroup', { tag: 'device-groups', class: 'write', method: 'POST' }),
  tool('listOrganizations', { tag: 'organizations', scope: 'platform' }),
  tool('getMcpCatalog', { tag: 'mcp', scope: 'any' }),
  tool('updateMcpSettings', { tag: 'mcp', class: 'write', exposed: false }),
]

describe('scopeTools (plan M14 §3.6 item 29)', () => {
  it('keeps the tools of the scope and of any scope that the MCP offers, plus the step-up tools', () => {
    expect(scopeTools(catalog, 'organization').map((t) => t.operation_id))
      .toEqual(['listDevices', 'lockDevice', 'createDeviceGroup', 'getMcpCatalog'])
    expect(scopeTools(catalog, 'platform').map((t) => t.operation_id)).toEqual(['listOrganizations', 'getMcpCatalog'])
  })

  it('never makes a step-up or unexposed tool selectable', () => {
    expect(catalog.filter(selectable).map((t) => t.operation_id))
      .toEqual(['listDevices', 'createDeviceGroup', 'listOrganizations', 'getMcpCatalog'])
  })
})

describe('groupByTag', () => {
  it('sorts the groups by tag and the tools by operation id', () => {
    const groups = groupByTag([tool('updateDevice'), tool('b', { tag: 'audit' }), tool('getDevice'), tool('a', { tag: 'audit' })])
    expect(groups.map((g) => [g.tag, g.tools.map((t) => t.operation_id)])).toEqual([
      ['audit', ['a', 'b']],
      ['devices', ['getDevice', 'updateDevice']],
    ])
    expect(groupByTag([])).toEqual([])
  })
})

describe('filterTools', () => {
  it('matches operation id and summary case-insensitively; an empty query keeps everything', () => {
    expect(filterTools(catalog, 'LISTDEV').map((t) => t.operation_id)).toEqual(['listDevices'])
    expect(filterTools(catalog, 'of the organization').map((t) => t.operation_id)).toEqual(['listDevices'])
    expect(filterTools(catalog, '  ')).toHaveLength(catalog.length)
    expect(filterTools(catalog, 'nothing matches')).toEqual([])
  })
})

describe('policyInput', () => {
  const tools = scopeTools(catalog, 'organization')

  it('sends no operations for all tools, as the server requires', () => {
    const form = { enabled: true, writeEnabled: false, mode: 'all' as const, selected: ['listDevices'] }
    expect(policyInput(form, tools)).toEqual({ enabled: true, write_enabled: false, mode: 'all', allowed_operations: [] })
  })

  it('sends the selected tools sorted and once, dropping ids that are not selectable any more', () => {
    const form = {
      enabled: true, writeEnabled: true, mode: 'selected' as const,
      selected: ['listDevices', 'lockDevice', 'createDeviceGroup', 'listDevices', 'removedTool', 'listOrganizations'],
    }
    expect(policyInput(form, tools).allowed_operations).toEqual(['createDeviceGroup', 'listDevices'])
  })

  it('round-trips a stored policy through the form', () => {
    const stored = {
      enabled: true, write_enabled: true, mode: 'selected' as const, allowed_operations: ['listDevices'],
      updated_at: '2026-10-29T10:00:00Z', updated_by: null,
    }
    const form = policyForm(stored)
    expect(form).toEqual({ enabled: true, writeEnabled: true, mode: 'selected', selected: ['listDevices'] })
    form.selected.push('createDeviceGroup')
    expect(stored.allowed_operations).toEqual(['listDevices'])
  })
})

describe('allowedCount', () => {
  const tools = scopeTools(catalog, 'organization')

  it('counts the selectable tools for all, the selection for selected, and none while switched off', () => {
    expect(allowedCount({ enabled: true, write_enabled: true, mode: 'all', allowed_operations: [] }, tools)).toBe(3)
    expect(allowedCount({ enabled: true, write_enabled: true, mode: 'selected', allowed_operations: ['listDevices'] }, tools)).toBe(1)
    expect(allowedCount({ enabled: false, write_enabled: true, mode: 'all', allowed_operations: [] }, tools)).toBe(0)
  })
})
