import { api, listPage, problemCode, type SoftwareRequest, type SoftwareRequestSort, type SoftwareRequestState } from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'
import type { StatusView } from './status'

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** Every state of a request (plan M13c §3.7): requested waits for a decision, the others are final. */
export const softwareRequestStates: SoftwareRequestState[] = ['requested', 'approved', 'denied', 'expired', 'withdrawn']

/** Longest decision reason the server stores. */
export const decisionReasonMax = 500

/** Filters of the request list. */
export const softwareRequestFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'state', label: 'softwareRequests.state',
    options: softwareRequestStates.map((value) => ({ value, title: 'softwareRequests.states.' + value })),
  },
]

/** The chip of a request state: an open request waits for someone, a denial is a decision and no alarm. */
export function softwareRequestStatus(state: SoftwareRequestState): StatusView {
  const label = 'softwareRequests.states.' + state
  switch (state) {
    case 'requested':
      return { status: 'warn', label }
    case 'approved':
      return { status: 'ok', label }
    default:
      return { status: 'neutral', label }
  }
}

/** Whether the viewer may decide the request: an organization administrator, and only while it is open. */
export function canDecide(r: Pick<SoftwareRequest, 'state'>, orgAdmin: boolean): boolean {
  return orgAdmin && r.state === 'requested'
}

/** One page of requests for DataList. */
export async function listSoftwareRequests(p: ListParams): Promise<Page<SoftwareRequest>> {
  return listPage(
    await api.GET('/api/v1/software-requests', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as SoftwareRequestSort, q: p.q,
          state: p.state as SoftwareRequestState[] | undefined,
        },
      },
    }),
  )
}

/**
 * Approves (reason optional) or denies (reason required, the user sees it) an open request; null or the problem code.
 * A decision needs no step-up of its own (plan M13c decision Q15).
 */
export async function decideSoftwareRequest(id: string, verb: 'approve' | 'deny', reason: string): Promise<string | null> {
  const trimmed = reason.trim()
  const { error } = verb === 'approve'
    ? await api.POST('/api/v1/software-requests/{id}/approve', {
      params: { path: { id }, header: csrf }, body: trimmed === '' ? {} : { reason: trimmed },
    })
    : await api.POST('/api/v1/software-requests/{id}/deny', { params: { path: { id }, header: csrf }, body: { reason: trimmed } })
  return error ? problemCode(error) : null
}
