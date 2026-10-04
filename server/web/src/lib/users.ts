import {
  api, listPage, problemCode, type IdentitySource, type User, type UserCreated, type UserDetail,
  type UserEffectiveProfile, type UserSort,
} from '../api/client'
import { maxListDepth, type ListFilter, type ListParams, type Page } from './listQuery'

export const identitySources: IdentitySource[] = ['local', 'synced']

/** Filters of user lists: source and lock state. */
export const userFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'source', label: 'users.source',
    options: identitySources.map((value) => ({ value, title: 'users.sources.' + value })),
  },
  {
    kind: 'enum', key: 'locked', label: 'users.lockState',
    options: [{ value: 'true', title: 'users.locked' }, { value: 'false', title: 'users.notLocked' }],
  },
]

/** The locked filter takes one value; both or none mean no filter. */
function lockedParam(p: ListParams): boolean | undefined {
  const v = (p.locked as string[] | undefined) ?? []
  return v.length === 1 ? v[0] === 'true' : undefined
}

/** One page of users for DataList. */
export async function listUsers(p: ListParams): Promise<Page<User>> {
  return listPage(
    await api.GET('/api/v1/users', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as UserSort, q: p.q, source: p.source as IdentitySource[],
          locked: lockedParam(p),
        },
      },
    }),
  )
}

/** One page of the members of a user group for DataList. */
export function listGroupMembers(groupID: string): (p: ListParams) => Promise<Page<User>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/user-groups/{id}/members', {
        params: {
          path: { id: groupID },
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as UserSort, q: p.q, source: p.source as IdentitySource[],
            locked: lockedParam(p),
          },
        },
      }),
    )
}

/** All users by username (selection lists), paged through the list contract (at most its depth limit). */
export async function allUsers(): Promise<User[]> {
  const out: User[] = []
  for (let page = 1; page * 100 <= maxListDepth; page++) {
    const { data } = await api.GET('/api/v1/users', { params: { query: { page, page_size: 100, sort: 'username' } } })
    out.push(...(data?.items ?? []))
    if (!data || page * data.page_size >= data.total) break
  }
  return out
}

export interface UserInput {
  username: string
  displayName: string
  email: string
}

/** Creates a local user; returns the one-time answer with the recovery link or the problem code. */
export async function createUser(input: UserInput): Promise<UserCreated | string> {
  const { data, error } = await api.POST('/api/v1/users', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: {
      username: input.username.trim(), display_name: input.displayName.trim(),
      ...(input.email.trim() ? { email: input.email.trim() } : {}),
    },
  })
  return data ?? problemCode(error)
}

/** Loads a user with its groups; the problem code on failure. */
export async function getUser(id: string): Promise<UserDetail | string> {
  const { data, error } = await api.GET('/api/v1/users/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Changes display name and email of a local user; null on success, otherwise the problem code. */
export async function updateUser(id: string, displayName: string, email: string): Promise<string | null> {
  const { error } = await api.PATCH('/api/v1/users/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
    body: { display_name: displayName.trim(), email: email.trim() },
  })
  return error ? problemCode(error) : null
}

/** Deletes a local user; null on success, otherwise the problem code. */
export async function deleteUser(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/users/{id}', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** Locks or unlocks a user; null on success, otherwise the problem code. */
export async function setLocked(id: string, locked: boolean): Promise<string | null> {
  const path = locked ? '/api/v1/users/{id}/lock' : '/api/v1/users/{id}/unlock'
  const { error } = await api.POST(path, { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** The effective profile of a user on a device (or on a device in no group); the problem code on failure. */
export async function getEffectiveProfile(id: string, deviceID: string | null): Promise<UserEffectiveProfile | string> {
  const { data, error } = await api.GET('/api/v1/users/{id}/effective-profile', {
    params: { path: { id }, query: deviceID ? { device_id: deviceID } : {} },
  })
  return data ?? problemCode(error)
}
