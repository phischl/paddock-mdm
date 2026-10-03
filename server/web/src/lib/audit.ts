import {
  api, listPage, type AuditActorType, type AuditEvent, type AuditEventSort, type AuditOutcome,
} from '../api/client'
import { dateInputToRFC3339 } from './format'
import type { ListFilter, ListParams, Page } from './listQuery'

/** Codes offered in the filter (the closed registry, server/internal/domain/audit/codes.go). */
export const auditCodes = [
  'admin.login',
  'device_group.created',
  'device_group.updated',
  'device_group.deleted',
  'organization.created',
] as const

const outcomes: AuditOutcome[] = ['success', 'failure', 'denied', 'unknown']
const actorTypes: AuditActorType[] = ['admin', 'platform_admin', 'system', 'anonymous']

/** Filters of the audit log; without dates the server shows the last 7 days. */
export const auditFilters: ListFilter[] = [
  { kind: 'dateRange', from: 'from', to: 'to', fromLabel: 'audit.from', toLabel: 'audit.to' },
  { kind: 'enum', key: 'code', label: 'audit.code', options: auditCodes.map((value) => ({ value })) },
  { kind: 'enum', key: 'outcome', label: 'audit.outcome', options: outcomes.map((value) => ({ value, title: 'audit.outcomes.' + value })) },
  {
    kind: 'enum', key: 'actor_type', label: 'audit.actorType',
    options: actorTypes.map((value) => ({ value, title: 'audit.actorTypes.' + value })),
  },
]

function firstDate(value: unknown): string {
  return (value as string[])[0] ?? ''
}

/** One page of audit events for DataList; dates (local days) become RFC 3339 instants, "to" includes its day. */
export async function listAuditEvents(p: ListParams): Promise<Page<AuditEvent>> {
  return listPage(
    await api.GET('/api/v1/audit-events', {
      params: {
        query: {
          page: p.page,
          page_size: p.page_size,
          sort: p.sort as AuditEventSort,
          q: p.q,
          from: dateInputToRFC3339(firstDate(p.from), false),
          to: dateInputToRFC3339(firstDate(p.to), true),
          code: p.code as string[],
          outcome: p.outcome as AuditOutcome[],
          actor_type: p.actor_type as AuditActorType[],
        },
      },
    }),
  )
}
