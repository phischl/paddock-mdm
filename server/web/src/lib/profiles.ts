import {
  api, listPage, problemCode, type EffectiveSudo, type Lecture, type PermissionProfile, type PermissionProfileSort,
  type PrivilegeClass, type ProfileAssignment, type ProfileAssignmentSort, type SubjectType,
} from '../api/client'
import type { ListFilter, ListParams, Page } from './listQuery'

export const privilegeClasses: PrivilegeClass[] = ['none', 'restricted', 'full']
export const lectures: Lecture[] = ['always', 'once', 'never']
export const subjectTypes: SubjectType[] = ['global', 'group', 'user']

/** The class filter of the profile list. */
export const classFilter: ListFilter = {
  kind: 'enum', key: 'class', label: 'profiles.class',
  options: privilegeClasses.map((value) => ({ value, title: 'profiles.classes.' + value })),
}

/** One page of permission profiles for DataList. */
export async function listProfiles(p: ListParams): Promise<Page<PermissionProfile>> {
  return listPage(
    await api.GET('/api/v1/permission-profiles', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as PermissionProfileSort, q: p.q, class: p.class as PrivilegeClass[] } },
    }),
  )
}

/** One page of the assignments of a profile for DataList. */
export function listAssignments(profileID: string): (p: ListParams) => Promise<Page<ProfileAssignment>> {
  return async (p) =>
    listPage(
      await api.GET('/api/v1/profile-assignments', {
        params: {
          query: {
            page: p.page, page_size: p.page_size, sort: p.sort as ProfileAssignmentSort, q: p.q, profile_id: profileID,
            subject_type: p.subject_type as SubjectType[],
          },
        },
      }),
    )
}

/** The subject type filter of the assignment list. */
export const subjectTypeFilter: ListFilter = {
  kind: 'enum', key: 'subject_type', label: 'profiles.subjectType',
  options: subjectTypes.map((value) => ({ value, title: 'profiles.subjectTypes.' + value })),
}

export interface ProfileInput {
  name: string
  class: PrivilegeClass
  commands: string[]
  requirePassword: boolean
  timestampTimeoutMin: number
  lecture: Lecture
}

/** Commands from a text area: one per line, blank lines ignored. */
export function commandLines(text: string): string[] {
  return text.split('\n').map((l) => l.trim()).filter((l) => l !== '')
}

function body(input: ProfileInput) {
  return {
    name: input.name.trim(), class: input.class, commands: input.class === 'restricted' ? input.commands : [],
    require_password: input.requirePassword, timestamp_timeout_min: input.timestampTimeoutMin, lecture: input.lecture,
  }
}

/** Creates a profile; the profile or the problem code. */
export async function createProfile(input: ProfileInput): Promise<PermissionProfile | string> {
  const { data, error } = await api.POST('/api/v1/permission-profiles', {
    params: { header: { 'X-Paddock-CSRF': '1' } }, body: body(input),
  })
  return data ?? problemCode(error)
}

/** Replaces a profile's settings; null on success, otherwise the problem code. */
export async function updateProfile(id: string, input: ProfileInput): Promise<string | null> {
  const { error } = await api.PATCH('/api/v1/permission-profiles/{id}', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } }, body: body(input),
  })
  return error ? problemCode(error) : null
}

/** Loads a profile; the problem code on failure. */
export async function getProfile(id: string): Promise<PermissionProfile | string> {
  const { data, error } = await api.GET('/api/v1/permission-profiles/{id}', { params: { path: { id } } })
  return data ?? problemCode(error)
}

/** Deletes a profile; null on success, otherwise the problem code. */
export async function deleteProfile(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/permission-profiles/{id}', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

export interface AssignmentInput {
  subjectType: SubjectType
  subjectID: string | null
  deviceGroupID: string | null
}

/** Assigns a profile; null on success, otherwise the problem code. */
export async function createAssignment(profileID: string, input: AssignmentInput): Promise<string | null> {
  const { error } = await api.POST('/api/v1/profile-assignments', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: {
      profile_id: profileID, subject_type: input.subjectType,
      ...(input.subjectType !== 'global' && input.subjectID ? { subject_id: input.subjectID } : {}),
      ...(input.deviceGroupID ? { device_group_id: input.deviceGroupID } : {}),
    },
  })
  return error ? problemCode(error) : null
}

/** Removes an assignment; null on success, otherwise the problem code. */
export async function deleteAssignment(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/profile-assignments/{id}', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** The effective sudo profiles of a device; the problem code on failure. */
export async function getEffectiveSudo(deviceID: string): Promise<EffectiveSudo | string> {
  const { data, error } = await api.GET('/api/v1/devices/{id}/effective-sudo', { params: { path: { id: deviceID } } })
  return data ?? problemCode(error)
}
