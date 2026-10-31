import {
  api, listPage, problemCode, type Account, type Finding, type FindingKind, type FindingListSort, type FindingResolution, type FindingStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

const csrf = { 'X-Paddock-CSRF': '1' } as const

export const findingStatuses: FindingStatus[] = ['open', 'acknowledged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive']
export const findingKinds: FindingKind[] = ['tamper', 'attention']
export const findingResolutions: FindingResolution[] = ['resolved', 'accepted_risk', 'false_positive']

/** The statuses of a finding that still needs someone; the list shows exactly these until a status is chosen. */
export const liveFindingStatuses: FindingStatus[] = ['open', 'acknowledged', 'in_progress']

/** Limits of the close and reopen texts (server: domain/finding). */
export const maxFindingReason = 1000
export const maxFindingExternalRef = 200

export const findingFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'status', label: 'findings.filters.status', hint: 'findings.filters.statusHint',
    options: findingStatuses.map((value) => ({ value, title: 'findings.status.' + value })),
  },
  {
    kind: 'enum', key: 'kind', label: 'findings.filters.kind',
    options: findingKinds.map((value) => ({ value, title: 'findings.kinds.' + value })),
  },
  {
    kind: 'enum', key: 'cleared', label: 'findings.filters.cleared', hint: 'findings.filters.clearedHint',
    options: [{ value: 'true', title: 'findings.filters.clearedOnly' }],
  },
]

/** The finding's code for people: the attention kind's label, or the audit code of a tamper event as it is. */
export function findingCodeText(f: Pick<Finding, 'kind' | 'code'>, t: (key: string) => string): string {
  return f.kind === 'attention' ? t('attention.kinds.' + f.code) : f.code
}

/** One page of findings for DataList; without a status filter the live findings, without a cleared filter the uncleared. */
export async function listFindings(p: ListParams): Promise<Page<Finding>> {
  const status = ((p.status as FindingStatus[] | undefined) ?? [])
  const kinds = (p.kind as FindingKind[] | undefined) ?? []
  return listPage(
    await api.GET('/api/v1/findings', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as FindingListSort, q: p.q,
          status: status.length > 0 ? status : liveFindingStatuses,
          // The API takes one kind; both chosen means no restriction.
          kind: kinds.length === 1 ? kinds[0] : undefined,
          cleared: ((p.cleared as string[] | undefined) ?? []).includes('true'),
        },
      },
    }),
  )
}

/**
 * The organization's assignable accounts, the first hundred by user name: administrators and operators, because the
 * assign step refuses an auditor. The problem code on failure.
 */
export async function listAccounts(): Promise<Account[] | string> {
  const { data, error } = await api.GET('/api/v1/accounts', {
    params: { query: { page: 1, page_size: 100, sort: 'username', role: ['org_admin', 'org_operator'] } },
  })
  return data?.items ?? problemCode(error)
}

/** The finding after a step, or the problem code. */
export type FindingResult = Finding | string

export async function acknowledgeFinding(id: string): Promise<FindingResult> {
  const { data, error } = await api.POST('/api/v1/findings/{id}/acknowledge', { params: { path: { id }, header: csrf } })
  return data ?? problemCode(error)
}

/** Assigns the finding; null removes the assignee. */
export async function assignFinding(id: string, assigneeID: string | null): Promise<FindingResult> {
  const { data, error } = await api.POST('/api/v1/findings/{id}/assign', {
    params: { path: { id }, header: csrf }, body: { assignee_id: assigneeID },
  })
  return data ?? problemCode(error)
}

export interface CloseInput {
  resolution: FindingResolution
  reason: string
  externalRef: string
}

export async function closeFinding(id: string, input: CloseInput): Promise<FindingResult> {
  const ref = input.externalRef.trim()
  const { data, error } = await api.POST('/api/v1/findings/{id}/close', {
    params: { path: { id }, header: csrf },
    body: { resolution: input.resolution, reason: input.reason.trim(), ...(ref ? { external_ref: ref } : {}) },
  })
  return data ?? problemCode(error)
}

export async function reopenFinding(id: string, reason: string): Promise<FindingResult> {
  const { data, error } = await api.POST('/api/v1/findings/{id}/reopen', {
    params: { path: { id }, header: csrf }, body: { reason: reason.trim() },
  })
  return data ?? problemCode(error)
}

/** Message keys of an invalid close form. */
export function validateClose(input: CloseInput): { reason?: string; externalRef?: string } {
  const out: { reason?: string; externalRef?: string } = {}
  const reason = input.reason.trim()
  if (reason === '') out.reason = 'findings.close.reasonRequired'
  else if ([...reason].length > maxFindingReason) out.reason = 'findings.close.reasonTooLong'
  if ([...input.externalRef.trim()].length > maxFindingExternalRef) out.externalRef = 'findings.close.externalRefTooLong'
  return out
}
