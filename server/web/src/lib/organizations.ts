import {
  api, listPage, problemCode, type Organization, type OrganizationSort, type OrganizationStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

const statuses: OrganizationStatus[] = ['provisioning', 'active', 'provisioning_failed', 'suspended', 'deleting', 'deleted']

/** Filters of the organization list. */
export const organizationFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'status', label: 'organizations.status',
    options: statuses.map((value) => ({ value, title: 'organizations.statuses.' + value })),
  },
]

/** One page of organizations for DataList. */
export async function listOrganizations(p: ListParams): Promise<Page<Organization>> {
  return listPage(
    await api.GET('/api/platform/v1/organizations', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as OrganizationSort, q: p.q,
          status: p.status as OrganizationStatus[],
        },
      },
    }),
  )
}

/** Creates an organization; returns the created organization, otherwise the problem code. */
export async function createOrganization(slug: string, name: string): Promise<Organization | string> {
  const { data, error } = await api.POST('/api/platform/v1/organizations', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: { slug: slug.trim(), name: name.trim() },
  })
  return data ?? problemCode(error)
}

/** Replaces the domains of an organization; returns null on success, otherwise the problem code. */
export async function updateOrganizationDomains(id: string, domains: string[]): Promise<string | null> {
  const { error } = await api.PATCH('/api/platform/v1/organizations/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { domains },
  })
  return error ? problemCode(error) : null
}

/** The grace period of a deletion in days (plan M17 decision 2); a development stack also accepts 0, the server decides. */
export const graceDays = { min: 7, max: 90, default: 30 }

/** The request the platform administrator confirms; confirm_slug is typed by them. */
export interface OrganizationDeletionInput {
  id: string
  slug: string
  reason: string
  graceDays: number
}

/** Requests the deletion of an organization; returns null on success, otherwise the problem code (step_up_required included). */
export async function requestOrganizationDeletion(input: OrganizationDeletionInput): Promise<string | null> {
  const { error } = await api.POST('/api/platform/v1/organizations/{id}/delete', {
    params: { path: { id: input.id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { confirm_slug: input.slug, reason: input.reason, grace_days: input.graceDays },
  })
  return error ? problemCode(error) : null
}

/** Cancels the pending deletion; returns null on success, otherwise the problem code. */
export async function cancelOrganizationDeletion(id: string): Promise<string | null> {
  const { error } = await api.POST('/api/platform/v1/organizations/{id}/cancel-deletion', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return error ? problemCode(error) : null
}

/** A deletion that is requested but whose data is not deleted yet: the organization is still usable and the request can be cancelled. */
export function deletionPending(org: Organization): boolean {
  return org.deletion !== null && org.status !== 'deleting' && org.status !== 'deleted'
}

/** Whether a deletion can be requested. */
export function canRequestDeletion(org: Organization): boolean {
  return org.deletion === null && (org.status === 'active' || org.status === 'provisioning_failed')
}
