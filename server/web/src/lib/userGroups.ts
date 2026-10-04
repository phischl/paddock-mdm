import {
  api, listPage, problemCode, type IdentitySource, type UpstreamGroup, type UpstreamGroupSort, type UserGroup,
  type UserGroupSort,
} from '../api/client'
import { maxListDepth, type ListFilter, type ListParams, type Page } from './listQuery'
import { identitySources } from './users'

/** The source filter of the group list. */
export const groupSourceFilter: ListFilter = {
  kind: 'enum', key: 'source', label: 'users.source',
  options: identitySources.map((value) => ({ value, title: 'userGroups.sources.' + value })),
}

/** One page of user groups for DataList. */
export async function listUserGroups(p: ListParams): Promise<Page<UserGroup>> {
  return listPage(
    await api.GET('/api/v1/user-groups', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as UserGroupSort, q: p.q, source: p.source as IdentitySource[] } },
    }),
  )
}

/** One page of the upstream groups that can be imported. */
export async function listUpstreamGroups(p: ListParams): Promise<Page<UpstreamGroup>> {
  return listPage(
    await api.GET('/api/v1/upstream-groups', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as UpstreamGroupSort, q: p.q } },
    }),
  )
}

/** All user groups by name (selection lists). */
export async function allUserGroups(): Promise<UserGroup[]> {
  const out: UserGroup[] = []
  for (let page = 1; page * 100 <= maxListDepth; page++) {
    const { data } = await api.GET('/api/v1/user-groups', { params: { query: { page, page_size: 100, sort: 'name' } } })
    out.push(...(data?.items ?? []))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

/** Group slugs (the part of the Authentik name), mirroring the API rule. */
export const groupSlugPattern = /^[a-z0-9][a-z0-9-]{0,40}[a-z0-9]$/

/** A slug suggestion from a name ("Engineering: Linux" → "engineering-linux"). */
export function slugFrom(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 42).replace(/-+$/, '')
}

/** Creates a local group or imports an upstream group; the group or the problem code. */
export async function createUserGroup(slug: string, name: string, upstreamID: string | null): Promise<UserGroup | string> {
  const { data, error } = await api.POST('/api/v1/user-groups', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: { slug: slug.trim(), name: name.trim(), ...(upstreamID ? { upstream_group_id: upstreamID } : {}) },
  })
  return data ?? problemCode(error)
}

/** Loads a user group; the problem code on failure. */
export async function getUserGroup(id: string): Promise<UserGroup | string> {
  const { data, error } = await api.GET('/api/v1/user-groups/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Renames a group; null on success, otherwise the problem code. */
export async function renameUserGroup(id: string, name: string): Promise<string | null> {
  const { error } = await api.PATCH('/api/v1/user-groups/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { name: name.trim() },
  })
  return error ? problemCode(error) : null
}

/** Deletes a group; null on success, otherwise the problem code. */
export async function deleteUserGroup(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/user-groups/{id}', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** Adds a member to a local group; null on success, otherwise the problem code. */
export async function addMember(groupID: string, userID: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/user-groups/{id}/members', {
    params: { path: { id: groupID }, header: { 'X-Paddock-CSRF': '1' } },
    body: { user_id: userID },
  })
  return error ? problemCode(error) : null
}

/** Removes a member from a local group; null on success, otherwise the problem code. */
export async function removeMember(groupID: string, userID: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/user-groups/{id}/members/{user_id}', {
    params: { path: { id: groupID, user_id: userID }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return error ? problemCode(error) : null
}
