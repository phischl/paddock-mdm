import {
  api, listPage, problemCode, type ManagedFile, type ManagedFileSort, type ManagedUnit, type ManagedUnitSort,
} from '../api/client'
import type { ListParams, Page } from './listQuery'

function groupParam(p: ListParams): string | undefined {
  return ((p.device_group_id as string[] | undefined) ?? [])[0]
}

/** One page of managed files for DataList. */
export async function listManagedFiles(p: ListParams): Promise<Page<ManagedFile>> {
  return listPage(
    await api.GET('/api/v1/managed-files', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as ManagedFileSort, q: p.q, device_group_id: groupParam(p) } },
    }),
  )
}

/** One page of managed units for DataList. */
export async function listManagedUnits(p: ListParams): Promise<Page<ManagedUnit>> {
  return listPage(
    await api.GET('/api/v1/managed-units', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as ManagedUnitSort, q: p.q, device_group_id: groupParam(p) } },
    }),
  )
}

export interface FileInput {
  groupID: string | null
  path: string
  mode: string
  owner: string
  group: string
  content: string
}

/** Creates (no id) or updates a managed file; null on success, otherwise the problem code. */
export async function saveManagedFile(id: string | null, f: FileInput): Promise<string | null> {
  const fields = { path: f.path.trim(), mode: f.mode.trim(), owner: f.owner.trim(), group: f.group.trim(), content: f.content }
  const header = { 'X-Paddock-CSRF': '1' as const }
  const { error } = id
    ? await api.PATCH('/api/v1/managed-files/{id}', { params: { path: { id }, header }, body: fields })
    : await api.POST('/api/v1/managed-files', { params: { header }, body: { ...fields, ...(f.groupID ? { device_group_id: f.groupID } : {}) } })
  return error ? problemCode(error) : null
}

export async function deleteManagedFile(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/managed-files/{id}', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

export interface UnitInput {
  groupID: string | null
  unit: string
  enabled: boolean
  active: boolean
}

/** Creates (no id) or updates a managed unit; null on success, otherwise the problem code. */
export async function saveManagedUnit(id: string | null, u: UnitInput): Promise<string | null> {
  const fields = { unit: u.unit.trim(), enabled: u.enabled, active: u.active }
  const header = { 'X-Paddock-CSRF': '1' as const }
  const { error } = id
    ? await api.PATCH('/api/v1/managed-units/{id}', { params: { path: { id }, header }, body: fields })
    : await api.POST('/api/v1/managed-units', { params: { header }, body: { ...fields, ...(u.groupID ? { device_group_id: u.groupID } : {}) } })
  return error ? problemCode(error) : null
}

export async function deleteManagedUnit(id: string): Promise<string | null> {
  const { error } = await api.DELETE('/api/v1/managed-units/{id}', { params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } } })
  return error ? problemCode(error) : null
}

/** Client-side checks mirroring the API (plan M2a decision 8); the server enforces the full path policy. */
export interface FileErrors {
  path?: 'validation.pathInvalid'
  mode?: 'validation.modeInvalid'
  owner?: 'validation.ownerInvalid'
  content?: 'validation.contentTooLarge'
}

const modePattern = /^0[0-7]{3}$/
const ownerPattern = /^[a-z_][a-z0-9_-]{0,31}$/
const unitPattern = /^[a-zA-Z0-9@._-]+\.(service|timer|socket|path)$/

export function validateFile(f: FileInput): FileErrors {
  const errors: FileErrors = {}
  const path = f.path.trim()
  if (!/^\/(etc|usr\/local\/etc|opt)\/./.test(path) || path.includes('..')) errors.path = 'validation.pathInvalid'
  if (!modePattern.test(f.mode.trim())) errors.mode = 'validation.modeInvalid'
  if (!ownerPattern.test(f.owner.trim()) || !ownerPattern.test(f.group.trim())) errors.owner = 'validation.ownerInvalid'
  if (new TextEncoder().encode(f.content).length > 64 * 1024) errors.content = 'validation.contentTooLarge'
  return errors
}

export function validateUnit(u: UnitInput): { unit?: 'validation.unitInvalid' } {
  return unitPattern.test(u.unit.trim()) ? {} : { unit: 'validation.unitInvalid' }
}
