import {
  api, listPage, problemCode, type AgentRelease, type AgentReleaseDetail, type AgentReleaseSort, type AgentReleaseStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

const statuses: AgentReleaseStatus[] = ['draft', 'published']

/** Filters of the agent release list. */
export const agentReleaseFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'status', label: 'agentReleases.status',
    options: statuses.map((value) => ({ value, title: 'agentReleases.statuses.' + value })),
  },
]

/** One page of agent releases for DataList. */
export async function listAgentReleases(p: ListParams): Promise<Page<AgentRelease>> {
  return listPage(
    await api.GET('/api/platform/v1/agent-releases', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as AgentReleaseSort, q: p.q,
          status: p.status as AgentReleaseStatus[],
        },
      },
    }),
  )
}

/** Loads a release with artifacts and rollout; the problem code on failure. */
export async function getAgentRelease(version: string): Promise<AgentReleaseDetail | string> {
  const { data, error } = await api.GET('/api/platform/v1/agent-releases/{version}', { params: { path: { version } } })
  return data ?? problemCode(error)
}

export type RolloutAction = 'start' | 'halt' | 'resume'

/** The rollout actions offered for a release. */
export function rolloutActionsFor(d: AgentReleaseDetail): RolloutAction[] {
  if (!d.rollout) return d.release.status === 'published' ? ['start'] : []
  switch (d.rollout.status) {
    case 'running':
      return ['halt']
    case 'halted':
      return ['resume']
    default:
      return []
  }
}

/** Runs a rollout action with the default rollout settings; null on success, otherwise the problem code. */
export async function runRolloutAction(version: string, action: RolloutAction): Promise<string | null> {
  const params = { path: { version }, header: { 'X-Paddock-CSRF': '1' as const } }
  let error: unknown
  switch (action) {
    case 'start':
      ({ error } = await api.POST('/api/platform/v1/agent-releases/{version}/rollout', { params, body: {} }))
      break
    case 'halt':
      ({ error } = await api.POST('/api/platform/v1/agent-releases/{version}/rollout/halt', { params }))
      break
    case 'resume':
      ({ error } = await api.POST('/api/platform/v1/agent-releases/{version}/rollout/resume', { params }))
      break
  }
  return error ? problemCode(error) : null
}
