import {
  api, listPage, problemCode, type Organization, type OrganizationSort, type OrganizationStatus,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

const statuses: OrganizationStatus[] = ['provisioning', 'active', 'provisioning_failed', 'suspended']

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
