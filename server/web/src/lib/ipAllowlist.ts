import {
  api, listPage, problemCode, type IpAllowlistConfirm, type IpAllowlistEntry, type IpAllowlistSort,
} from '../api/client'
import { parseCIDR } from './cidr'
import type { ListParams, Page } from './listQuery'

/** The problem codes of a change that needs the caller's confirmation (plan M7a decision 12). */
export const lockoutConfirmationRequired = 'lockout_confirmation_required'
export const disableConfirmationRequired = 'disable_confirmation_required'

/** The confirmation a problem code asks for; null for any other code. */
export function confirmationOf(code: string | null): IpAllowlistConfirm | null {
  switch (code) {
    case lockoutConfirmationRequired:
      return 'lockout'
    case disableConfirmationRequired:
      return 'disable'
  }
  return null
}

export interface IpAllowlistInput {
  cidr: string
  label: string
}

export const maxLabelLength = 64

/** Validates an input like the server; returns message keys by field. */
export function validateIpAllowlistEntry(input: IpAllowlistInput): Partial<Record<keyof IpAllowlistInput, string>> {
  const errors: Partial<Record<keyof IpAllowlistInput, string>> = {}
  const cidr = parseCIDR(input.cidr)
  if (!cidr.ok) errors.cidr = cidr.message
  const label = input.label.trim()
  if (label.length === 0 || [...label].length > maxLabelLength || [...label].some((c) => c < ' ' || c === '\u007f')) {
    errors.label = 'ipAllowlist.labelInvalid'
  }
  return errors
}

/** One page of entries for DataList. */
export async function listIpAllowlist(p: ListParams): Promise<Page<IpAllowlistEntry>> {
  return listPage(
    await api.GET('/api/platform/v1/ip-allowlist', {
      params: { query: { page: p.page, page_size: p.page_size, sort: p.sort as IpAllowlistSort, q: p.q } },
    }),
  )
}

/** The status card's facts: every entry (the list is small) and the ones covering the caller. */
export interface IpAllowlistStatus {
  entries: number
  covering: string[]
}

/** Reads the whole list (up to 100 entries) for the status card. */
export async function loadIpAllowlistStatus(): Promise<IpAllowlistStatus | string> {
  const { data, error } = await api.GET('/api/platform/v1/ip-allowlist', {
    params: { query: { page: 1, page_size: 100, sort: 'cidr' } },
  })
  if (!data) return problemCode(error)
  return { entries: data.total, covering: data.items.filter((e) => e.covers_caller).map((e) => e.cidr) }
}

const csrf = { 'X-Paddock-CSRF': '1' } as const

/** Adds an entry; the entry on success, otherwise the problem code. */
export async function createIpAllowlistEntry(input: IpAllowlistInput, confirm?: IpAllowlistConfirm): Promise<IpAllowlistEntry | string> {
  const { data, error } = await api.POST('/api/platform/v1/ip-allowlist', {
    params: { header: csrf, query: { confirm } },
    body: { cidr: input.cidr.trim(), label: input.label.trim() },
  })
  return data ?? problemCode(error)
}

/** Changes an entry; the entry on success, otherwise the problem code. */
export async function updateIpAllowlistEntry(id: string, input: IpAllowlistInput, confirm?: IpAllowlistConfirm): Promise<IpAllowlistEntry | string> {
  const { data, error } = await api.PATCH('/api/platform/v1/ip-allowlist/{id}', {
    params: { path: { id }, header: csrf, query: { confirm } },
    body: { cidr: input.cidr.trim(), label: input.label.trim() },
  })
  return data ?? problemCode(error)
}

/** Removes an entry; null on success, otherwise the problem code. */
export async function deleteIpAllowlistEntry(id: string, confirm?: IpAllowlistConfirm): Promise<string | null> {
  const { error } = await api.DELETE('/api/platform/v1/ip-allowlist/{id}', {
    params: { path: { id }, header: csrf, query: { confirm } },
  })
  return error ? problemCode(error) : null
}
