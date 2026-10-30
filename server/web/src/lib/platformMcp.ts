import { api, problemCode } from '../api/client'
import type { components } from '../api/schema'

/** An MCP policy as the server stores it (ADR 0044 decision 5); updated_at null means none was saved yet. */
export type McpSettings = components['schemas']['McpSettings']
/** What a save sends: the whole policy. */
export type McpSettingsInput = components['schemas']['McpSettingsInput']
/** One entry of the MCP tool catalog. */
export type McpTool = components['schemas']['McpTool']

/** Tools that share one catalog tag, in catalog order. */
export interface McpToolGroup {
  tag: string
  tools: McpTool[]
}

/** The MCP policy of the platform; the problem code on failure. */
export async function getPlatformMcpSettings(): Promise<McpSettings | string> {
  const { data, error } = await api.GET('/api/platform/v1/settings/mcp')
  return data ?? problemCode(error)
}

/** Replaces the MCP policy of the platform; the saved policy or the problem code (step_up_required first). */
export async function savePlatformMcpSettings(input: McpSettingsInput): Promise<McpSettings | string> {
  const { data, error } = await api.PUT('/api/platform/v1/settings/mcp', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: input,
  })
  return data ?? problemCode(error)
}

/** The MCP tool catalog's tools; the problem code on failure. */
export async function getMcpTools(): Promise<McpTool[] | string> {
  const { data, error } = await api.GET('/api/v1/mcp/catalog')
  return data ? data.tools : problemCode(error)
}

/** The tools an MCP session in the platform scope can be offered: exposed ones of scope platform or any. */
export function platformTools(tools: McpTool[]): McpTool[] {
  return tools.filter((tool) => tool.exposed && (tool.scope === 'platform' || tool.scope === 'any'))
}

/** The tools whose operation id or summary contains the filter text (case-insensitive); all for an empty filter. */
export function filterTools(tools: McpTool[], text: string): McpTool[] {
  const needle = text.trim().toLowerCase()
  if (needle === '') return tools
  return tools.filter((tool) => tool.operation_id.toLowerCase().includes(needle) || tool.summary.toLowerCase().includes(needle))
}

/** Groups the tools by tag; groups appear in the order their first tool appears. */
export function groupByTag(tools: McpTool[]): McpToolGroup[] {
  const groups = new Map<string, McpTool[]>()
  for (const tool of tools) {
    const group = groups.get(tool.tag)
    if (group) group.push(tool)
    else groups.set(tool.tag, [tool])
  }
  return [...groups].map(([tag, members]) => ({ tag, tools: members }))
}

/** The editable part of a stored policy. */
export function toInput(settings: McpSettings): McpSettingsInput {
  return {
    enabled: settings.enabled,
    write_enabled: settings.write_enabled,
    mode: settings.mode,
    allowed_operations: [...settings.allowed_operations],
  }
}

/**
 * The number of tools MCP sessions can call under the policy: none while it is switched off, write tools only while
 * changes are allowed, and step-up tools never (the MCP refuses them whatever the policy says).
 */
export function availableToolCount(input: McpSettingsInput, tools: McpTool[]): number {
  if (!input.enabled) return 0
  const allowed = new Set(input.allowed_operations)
  return tools.filter(
    (tool) =>
      !tool.step_up &&
      (tool.class === 'read' || input.write_enabled) &&
      (input.mode === 'all' || allowed.has(tool.operation_id)),
  ).length
}

/** Whether the server accepts the policy's tool selection: mode selected needs at least one tool. */
export function validSelection(input: McpSettingsInput): boolean {
  return input.mode === 'all' || input.allowed_operations.length > 0
}
