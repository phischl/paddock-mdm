import {
  api, listPage, problemCode, type AuditIntegrity, type AuditManifest, type AuditManifestSort, type AuditVerificationRun,
  type AuditVerificationRunSort, type AuditVerificationTrigger,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { KpiCell } from './overview'
import type { StatusView } from './status'
import { formatAbsolute } from './time'

const triggers: AuditVerificationTrigger[] = ['nightly', 'sample', 'cli']

/** Filters of the verification runs (plan M8b decision 30): the result and the trigger. */
export const runFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'ok', label: 'auditIntegrity.runs.result',
    options: [{ value: 'true', title: 'auditIntegrity.result.ok' }, { value: 'false', title: 'auditIntegrity.result.failed' }],
  },
  { kind: 'enum', key: 'trigger', label: 'auditIntegrity.runs.trigger', options: triggers.map((value) => ({ value, title: 'auditIntegrity.triggers.' + value })) },
]

/** Filters of the manifests: the day range (inclusive) and whether a successful run covered the day. */
export const manifestFilters: ListFilter[] = [
  { kind: 'dateRange', from: 'from', to: 'to', fromLabel: 'auditIntegrity.manifests.from', toLabel: 'auditIntegrity.manifests.to' },
  {
    kind: 'enum', key: 'verified', label: 'auditIntegrity.manifests.verified',
    options: [{ value: 'true', title: 'auditIntegrity.verified.true' }, { value: 'false', title: 'auditIntegrity.verified.false' }],
  },
]

/** A boolean filter from an enum filter with the values "true" and "false": none or both selected mean no filter. */
export function booleanFilter(value: unknown): boolean | undefined {
  const values = (value as string[] | undefined) ?? []
  return values.length === 1 ? values[0] === 'true' : undefined
}

function firstDate(value: unknown): string | undefined {
  return (value as string[] | undefined)?.[0] || undefined
}

/** The integrity summary, or the problem code. */
export async function getAuditIntegrity(): Promise<AuditIntegrity | string> {
  const { data, error } = await api.GET('/api/v1/audit/integrity')
  return data ?? problemCode(error)
}

/** One page of verification runs for DataList. */
export async function listVerificationRuns(p: ListParams): Promise<Page<AuditVerificationRun>> {
  return listPage(
    await api.GET('/api/v1/audit/verification-runs', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as AuditVerificationRunSort, q: p.q,
          ok: booleanFilter(p.ok), trigger: p.trigger as AuditVerificationTrigger[],
        },
      },
    }),
  )
}

/** One page of manifests for DataList; the dates are days, sent as entered. */
export async function listManifests(p: ListParams): Promise<Page<AuditManifest>> {
  return listPage(
    await api.GET('/api/v1/audit/manifests', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as AuditManifestSort, q: p.q,
          from: firstDate(p.from), to: firstDate(p.to), verified: booleanFilter(p.verified),
        },
      },
    }),
  )
}

/** The chip of a verification result; null (no run covered the day) is "not verified". */
export function resultStatus(ok: boolean | null): StatusView {
  if (ok === null) return { status: 'neutral', label: 'auditIntegrity.result.none' }
  return ok ? { status: 'ok', label: 'auditIntegrity.result.ok' } : { status: 'critical', label: 'auditIntegrity.result.failed' }
}

/**
 * The KPI cells of the evidence integrity page (plan M8b decision 32): sealed through, manifests, the last
 * verification with its result, the last failure. A failure newer than the last success is critical.
 */
export function integrityCells(i: AuditIntegrity, now: Date): KpiCell[] {
  const time = (iso: string | null) => (iso ? formatAbsolute(iso, now) : '–')
  const failureOpen = !!i.last_failure_at && (!i.last_success_at || Date.parse(i.last_failure_at) > Date.parse(i.last_success_at))
  const last = i.last_run ? resultStatus(i.last_run.ok) : { status: 'warn' as const, label: 'auditIntegrity.kpi.neverVerified' }
  return [
    {
      key: 'sealed-through', label: 'auditIntegrity.kpi.sealedThrough', value: i.sealed_through ?? '–',
      note: i.sealed_through ? 'auditIntegrity.kpi.sealedNote' : 'auditIntegrity.kpi.notSealed', noteValues: {},
      status: i.sealed_through ? 'ok' : 'neutral',
    },
    {
      key: 'manifests', label: 'auditIntegrity.kpi.manifests', value: i.manifests, note: 'auditIntegrity.kpi.windowNote',
      noteValues: { days: i.verification_window_days }, status: 'info',
    },
    {
      key: 'last-run', label: 'auditIntegrity.kpi.lastRun', value: time(i.last_run?.finished_at ?? null), note: last.label,
      noteValues: {}, status: last.status,
    },
    {
      key: 'last-failure', label: 'auditIntegrity.kpi.lastFailure', value: time(i.last_failure_at),
      note: i.last_failure_at ? (failureOpen ? 'auditIntegrity.kpi.failureOpen' : 'auditIntegrity.kpi.failureResolved') : 'auditIntegrity.kpi.noFailure',
      noteValues: {}, status: failureOpen ? 'critical' : i.last_failure_at ? 'warn' : 'ok',
    },
  ]
}
