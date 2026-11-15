import {
  api, listPage, problemCode, type AuditEvent, type AuditEventSort, type AuditExport, type AuditExportCreate, type AuditExportSort,
  type AuditExportStatus, type AuditOutcome, type AuditActorType, type Organization, type OrganizationSort, type OrganizationStatus,
} from '../api/client'
import { firstDate } from './audit'
import { dateInputToRFC3339 } from './format'
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

/** The grace period of a deletion in days (plan M17 decision 2); the portal offers 7 to 90 only, a development stack may accept 0 through the API. */
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

/** The organization with its deletion object, or the problem code. */
export async function getOrganization(id: string): Promise<Organization | string> {
  const { data, error } = await api.GET('/api/platform/v1/organizations/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** The retained audit log of a deleted organization for DataList (filters as the audit log of an organization). */
export function listDeletedOrganizationAuditEvents(id: string): (p: ListParams) => Promise<Page<AuditEvent>> {
  return async (p) =>
    listPage(
      await api.GET('/api/platform/v1/organizations/{id}/audit-events', {
        params: {
          path: { id },
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as AuditEventSort, q: p.q,
            from: dateInputToRFC3339(firstDate(p.from), false), to: dateInputToRFC3339(firstDate(p.to), true),
            code: p.code as string[], outcome: p.outcome as AuditOutcome[], actor_type: p.actor_type as AuditActorType[],
          },
        },
      }),
    )
}

/** The evidence exports of a deleted organization for DataList. */
export function listDeletedOrganizationAuditExports(id: string): (p: ListParams) => Promise<Page<AuditExport>> {
  return async (p) =>
    listPage(
      await api.GET('/api/platform/v1/organizations/{id}/audit-exports', {
        params: {
          path: { id },
          query: { page: p.page, page_size: p.page_size, sort: p.sort as AuditExportSort, q: p.q, status: p.status as AuditExportStatus[] },
        },
      }),
    )
}

/** Requests an evidence export of a deleted organization; the pending export, or the problem code (step_up_required included). */
export async function createDeletedOrganizationAuditExport(id: string, body: AuditExportCreate): Promise<AuditExport | string> {
  const { data, error } = await api.POST('/api/platform/v1/organizations/{id}/audit-exports', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body,
  })
  return data ?? problemCode(error)
}

/** The URL of the package of a ready export; the browser fetches it with the session cookie. */
export function deletedOrganizationExportUrl(id: string, exportId: string): string {
  return '/api/platform/v1/organizations/' + encodeURIComponent(id) + '/audit-exports/' + encodeURIComponent(exportId) + '/download'
}
