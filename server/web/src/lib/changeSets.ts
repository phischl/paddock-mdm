import {
  api, listPage, problemCode, type ChangeSet, type ChangeSetSort, type ChangeSetSource, type ConfigApplyResult, type ConfigPlan,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

const sources: ChangeSetSource[] = ['session', 'api_token']

/** Filters of the change set list. */
export const changeSetFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'source', label: 'changeSets.source',
    options: sources.map((value) => ({ value, title: 'changeSets.sources.' + value })),
  },
]

/** One page of change sets for DataList. */
export async function listChangeSets(p: ListParams): Promise<Page<ChangeSet>> {
  return listPage(
    await api.GET('/api/v1/change-sets', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as ChangeSetSort, q: p.q, source: p.source as ChangeSetSource[],
        },
      },
    }),
  )
}

/** One row of the plan table: a field of a change, or the change itself when it lists no fields. */
export interface PlanRow {
  section: string
  key: string
  action: string
  field: string
  before: string
  after: string
}

/** Values as the plan shows them: JSON, absent values empty. */
function shown(v: unknown): string {
  if (v === null || v === undefined) return ''
  return typeof v === 'string' ? v : JSON.stringify(v)
}

/** Flattens a plan into one row per changed field, in the plan's order. */
export function planRows(plan: ConfigPlan): PlanRow[] {
  return plan.changes.flatMap((c) => {
    if (c.fields.length === 0) return [{ section: c.section, key: c.key, action: c.action, field: '', before: '', after: '' }]
    return c.fields.map((f) => ({
      section: c.section, key: c.key, action: c.action, field: f.name, before: shown(f.before), after: shown(f.after),
    }))
  })
}

/** Loads one change set; the problem code on failure. */
export async function getChangeSet(id: string): Promise<ChangeSet | string> {
  const { data, error } = await api.GET('/api/v1/change-sets/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/**
 * The dry run of a revert (plan M11 decision 22): the inverse plan and its hash, or the problem code (invalid_state,
 * step_up_required, …). Nothing is applied.
 */
export async function revertDryRun(id: string): Promise<ConfigApplyResult | string> {
  const { data, error } = await api.POST('/api/v1/change-sets/{id}/revert', {
    params: { path: { id }, query: { dry_run: true }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return data ?? problemCode(error)
}

/** Reverts a change set with the plan the administrator confirmed; plan_changed when the plan differs by now. */
export async function revertChangeSet(id: string, expectedPlan: string): Promise<ConfigApplyResult | string> {
  const { data, error } = await api.POST('/api/v1/change-sets/{id}/revert', {
    params: { path: { id }, query: { expected_plan: expectedPlan }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return data ?? problemCode(error)
}

/** Why a change set cannot be reverted (the tooltip of the disabled button), or null when it can. */
export function revertBlocked(cs: ChangeSet): 'reverted' | 'noBefore' | null {
  if (cs.reverted_by) return 'reverted'
  if (!cs.before_available) return 'noBefore'
  return null
}
