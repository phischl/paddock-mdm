import { api, problemCode } from '../api/client'
import type { components } from '../api/schema'

export type McpSettings = components['schemas']['McpSettings']
export type McpSettingsInput = components['schemas']['McpSettingsInput']
export type McpTool = components['schemas']['McpTool']
export type McpScope = 'organization' | 'platform'

/** The operations guide on connecting an assistant (plan M14 §3.6 item 29). */
export const mcpGuide = 'https://github.com/phischl/paddock-mdm/blob/main/docs/operations/mcp.md'

/** The tools of one catalog tag, sorted by operation id. */
export interface McpToolGroup {
  tag: string
  tools: McpTool[]
}

/** The form state of an MCP policy; selected keeps the picked tools while mode is all. */
export interface McpPolicyForm {
  enabled: boolean
  writeEnabled: boolean
  mode: McpSettings['mode']
  selected: string[]
}

/** A problem answer: the code and the server's detail when it sent one. */
export interface McpProblem {
  code: string
  detail?: string
}

/**
 * The tools the policy page of scope lists: those of the scope or of any scope that the MCP offers, plus the step-up
 * tools, which the page shows disabled (the catalog never exposes them, ADR 0044 decision 5).
 */
export function scopeTools(tools: readonly McpTool[], scope: McpScope): McpTool[] {
  return tools.filter((tool) => (tool.scope === scope || tool.scope === 'any') && (tool.exposed || tool.step_up))
}

/** Whether a policy may name the tool in allowed_operations. */
export function selectable(tool: McpTool): boolean {
  return tool.exposed && !tool.step_up
}

/** The tools grouped by tag, groups and tools in alphabetical order. */
export function groupByTag(tools: readonly McpTool[]): McpToolGroup[] {
  const groups = new Map<string, McpTool[]>()
  for (const tool of tools) groups.set(tool.tag, [...(groups.get(tool.tag) ?? []), tool])
  return [...groups.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([tag, list]) => ({ tag, tools: [...list].sort((a, b) => a.operation_id.localeCompare(b.operation_id)) }))
}

/** The tools whose operation id or summary contains query (case-insensitive); all tools for an empty query. */
export function filterTools(tools: readonly McpTool[], query: string): McpTool[] {
  const q = query.trim().toLowerCase()
  if (!q) return [...tools]
  return tools.filter((tool) => tool.operation_id.toLowerCase().includes(q) || tool.summary.toLowerCase().includes(q))
}

/** The form for a stored policy. */
export function policyForm(s: McpSettings): McpPolicyForm {
  return { enabled: s.enabled, writeEnabled: s.write_enabled, mode: s.mode, selected: [...s.allowed_operations] }
}

/**
 * The request body for the form: mode all sends no operations (the server requires that); mode selected sends the
 * picked tools that are still selectable, so an id the catalog no longer offers does not fail the save.
 */
export function policyInput(form: McpPolicyForm, tools: readonly McpTool[]): McpSettingsInput {
  const allowed = new Set(tools.filter(selectable).map((tool) => tool.operation_id))
  return {
    enabled: form.enabled,
    write_enabled: form.writeEnabled,
    mode: form.mode,
    allowed_operations: form.mode === 'all' ? [] : [...new Set(form.selected)].filter((id) => allowed.has(id)).sort(),
  }
}

/** The number of tools MCP sessions may call under input: none while switched off. */
export function allowedCount(input: McpSettingsInput, tools: readonly McpTool[]): number {
  if (!input.enabled) return 0
  return input.mode === 'all' ? tools.filter(selectable).length : input.allowed_operations.length
}

/** The MCP tool catalog. */
export async function getMcpCatalog(): Promise<McpTool[] | string> {
  const { data, error } = await api.GET('/api/v1/mcp/catalog')
  return data ? data.tools : problemCode(error)
}

/** The MCP policy of the caller's organization. */
export async function getMcpSettings(): Promise<McpSettings | string> {
  const { data, error } = await api.GET('/api/v1/settings/mcp')
  return data ?? problemCode(error)
}

/** Replaces the MCP policy of the organization (organization administrator with a step-up). */
export async function saveMcpSettings(input: McpSettingsInput): Promise<McpSettings | McpProblem> {
  const { data, error } = await api.PUT('/api/v1/settings/mcp', { params: { header: { 'X-Paddock-CSRF': '1' } }, body: input })
  if (data) return data
  const detail = error && typeof error === 'object' && 'detail' in error && typeof error.detail === 'string' ? error.detail : undefined
  return { code: problemCode(error), detail }
}
