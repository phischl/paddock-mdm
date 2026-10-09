import { api, listPage, type ChangeSet, type ChangeSetSort, type ChangeSetSource, type ConfigPlan } from '../api/client'
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
