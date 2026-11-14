import { onMounted, ref } from 'vue'
import {
  api, listPage, problemCode, type ConfigRollout, type ConfigRolloutDetail, type ConfigRolloutDevice, type ConfigRolloutDeviceSort,
  type ConfigRolloutSort, type ConfigRolloutStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import { getRolloutSettings } from './rolloutSettings'

const csrf = { 'X-Paddock-CSRF': '1' } as const

const statuses: ConfigRolloutStatus[] = ['running', 'halted', 'completed', 'reverted']

/** Filters of the rollout list. */
export const configRolloutFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'status', label: 'configRollouts.status',
    options: statuses.map((value) => ({ value, title: 'configRollouts.statuses.' + value })),
  },
]

/** Filters of a rollout's device list; the in_wave boolean is an enum of its two values here. */
export const rolloutDeviceFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'in_wave', label: 'configRollouts.devices.inWave',
    options: [
      { value: 'true', title: 'configRollouts.devices.inWaveYes' },
      { value: 'false', title: 'configRollouts.devices.inWaveNo' },
    ],
  },
  {
    kind: 'enum', key: 'report_outcome', label: 'configRollouts.devices.outcome',
    options: ['applied', 'rejected', 'report_only', 'none'].map((value) => ({ value, title: 'configRollouts.devices.outcomes.' + value })),
  },
]

/** One page of rollouts for DataList. */
export async function listConfigRollouts(p: ListParams): Promise<Page<ConfigRollout>> {
  return listPage(
    await api.GET('/api/v1/config-rollouts', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as ConfigRolloutSort, q: p.q, status: p.status as ConfigRolloutStatus[],
        },
      },
    }),
  )
}

/** Loads a rollout with its change set; the problem code on failure. */
export async function getConfigRollout(id: string): Promise<ConfigRolloutDetail | string> {
  const { data, error } = await api.GET('/api/v1/config-rollouts/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** The fetcher of a rollout's device list for DataList. */
export function rolloutDevicesFetcher(id: string): (p: ListParams) => Promise<Page<ConfigRolloutDevice>> {
  return async (p) => {
    // Only a single in_wave value selects; both or none show every device.
    const inWave = ((p.in_wave as string[] | undefined) ?? [])
    return listPage(
      await api.GET('/api/v1/config-rollouts/{id}/devices', {
        params: {
          path: { id },
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as ConfigRolloutDeviceSort, q: p.q,
            in_wave: inWave.length === 1 ? inWave[0] === 'true' : undefined,
            report_outcome: p.report_outcome as string[],
          },
        },
      }),
    )
  }
}

export type RolloutAction = 'halt' | 'resume' | 'advance' | 'complete'

/** The wave actions the rollout allows now; the server refuses the others with 409 invalid_state. */
export function rolloutActionsFor(r: ConfigRollout): RolloutAction[] {
  if (r.status === 'running') return r.current_wave_index < r.waves.length - 1 ? ['halt', 'advance', 'complete'] : ['halt', 'complete']
  if (r.status === 'halted') return ['resume', 'complete']
  return []
}

/** Whether the rollout is open: its change set can still be reverted from here and its keys stay blocked. */
export function rolloutOpen(r: ConfigRollout): boolean {
  return r.status === 'running' || r.status === 'halted'
}

/** A key an open rollout stages: the key's parts as the plan names them, and the rollout. */
export interface StagedKey {
  parts: unknown[]
  rolloutID: string
}

/**
 * The keys of a section that the organization's open rollouts stage (plan M11 decision 29), read from their change
 * sets' plans; empty when they cannot be read, so a list still renders without its chips.
 */
export async function openRolloutStagedKeys(section: string): Promise<StagedKey[]> {
  const out: StagedKey[] = []
  try {
    const { data } = await api.GET('/api/v1/config-rollouts', {
      params: { query: { page: 1, page_size: 10, sort: '-started_at', status: ['running', 'halted'] } },
    })
    for (const r of data?.items ?? []) {
      const detail = await getConfigRollout(r.id)
      if (typeof detail === 'string') continue
      for (const c of detail.change_set.plan.changes) {
        if (c.section !== section || c.key === '') continue
        const parts: unknown = JSON.parse(c.key)
        if (Array.isArray(parts)) out.push({ parts, rolloutID: r.id })
      }
    }
  } catch {
    return []
  }
  return out
}

/** Runs a wave action; the rollout or the problem code. The reason is required for halt only. */
export async function runRolloutAction(id: string, action: RolloutAction, reason = ''): Promise<ConfigRollout | string> {
  const params = { path: { id }, header: csrf }
  const res = await {
    halt: () => api.POST('/api/v1/config-rollouts/{id}/halt', { params, body: { reason } }),
    resume: () => api.POST('/api/v1/config-rollouts/{id}/resume', { params }),
    advance: () => api.POST('/api/v1/config-rollouts/{id}/advance', { params }),
    complete: () => api.POST('/api/v1/config-rollouts/{id}/complete', { params }),
  }[action]()
  return res.data ?? problemCode(res.error)
}

/** The percent of devices the rollout reached: the current wave, or all once it completed. */
export function rolloutPercent(r: ConfigRollout): number {
  return r.status === 'completed' ? 100 : (r.waves[r.current_wave_index] ?? 0)
}

/** The urgent opt-out of a write (plan M11 decision 37): apply at once to every device, with a reason. */
export interface UrgentInput {
  urgent: boolean
  reason: string
}

export const noUrgent = (): UrgentInput => ({ urgent: false, reason: '' })

/** Longest and shortest reason the server accepts. */
export const urgentReasonMin = 2
export const urgentReasonMax = 500

/** Whether the opt-out is complete: unchecked, or checked with a reason of the allowed length. */
export function validUrgent(u: UrgentInput | undefined): boolean {
  if (!u?.urgent) return true
  const reason = u.reason.trim()
  const len = [...reason].length
  // The server refuses control characters in a reason.
  return len >= urgentReasonMin && len <= urgentReasonMax && !/[\x00-\x08\x0b-\x1f\x7f]/.test(reason)
}

/** The query parameters of a write: urgent and reason when opted out, nothing otherwise. */
export function urgentQuery(u: UrgentInput | undefined): { urgent?: boolean; reason?: string } {
  return u?.urgent ? { urgent: true, reason: u.reason.trim() } : {}
}

/** Whether rollouts are enabled for the organization; a failed read counts as disabled (the server decides anyway). */
export async function rolloutsEnabled(): Promise<boolean> {
  try {
    const s = await getRolloutSettings()
    return typeof s !== 'string' && s.enabled
  } catch {
    return false
  }
}

/** The enabled flag of the rollout settings, read once when the page mounts. */
export function useRolloutsEnabled() {
  const enabled = ref(false)
  onMounted(async () => {
    enabled.value = await rolloutsEnabled()
  })
  return enabled
}
