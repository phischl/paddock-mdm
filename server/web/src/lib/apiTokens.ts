import {
  api, listPage, problemCode, type ApiToken, type ApiTokenCreated, type ApiTokenRole, type ApiTokenSort, type ApiTokenStatus,
} from '../api/client'
import { toDateInput } from './format'
import type { ListFilter, ListParams, Page } from './listQuery'

const statuses: ApiTokenStatus[] = ['active', 'expired', 'revoked']

/** Filters of the API token list. */
export const apiTokenFilters: ListFilter[] = [
  {
    kind: 'enum', key: 'status', label: 'apiTokens.status',
    options: statuses.map((value) => ({ value, title: 'apiTokens.statuses.' + value })),
  },
]

/** One page of API tokens for DataList. */
export async function listApiTokens(p: ListParams): Promise<Page<ApiToken>> {
  return listPage(
    await api.GET('/api/v1/api-tokens', {
      params: {
        query: {
          page: p.page, page_size: p.page_size, sort: p.sort as ApiTokenSort, q: p.q, status: p.status as ApiTokenStatus[],
        },
      },
    }),
  )
}

/**
 * The roles an administrator may give a token (plan M6c decision 3): an organization administrator any organization
 * role, an operator operator and auditor tokens, everyone else none.
 */
export function rolesFor(creator: string | null | undefined): ApiTokenRole[] {
  switch (creator) {
    case 'org_admin':
      return ['org_admin', 'org_operator', 'org_auditor']
    case 'org_operator':
      return ['org_operator', 'org_auditor']
  }
  return []
}

/** Token names as the server accepts them. */
const namePattern = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/

/** Expiry window of a token (plan M6c decision 6). */
const hourMs = 60 * 60 * 1000
const dayMs = 24 * hourMs
export const defaultValidityDays = 90
export const maxValidityDays = 365

export interface ApiTokenInput {
  name: string
  role: ApiTokenRole
  /** Expiry day (YYYY-MM-DD, local); the token expires on that day at the time of creation. */
  expires: string
}

/** The expiry instant of an input: the expiry day at the current time of day. */
export function expiresAt(day: string, now: Date): Date {
  const [y, m, d] = day.split('-').map(Number)
  return new Date(y, m - 1, d, now.getHours(), now.getMinutes(), now.getSeconds())
}

/** The default expiry day (now + 90 days) and the last allowed one (now + 365 days). */
export function expiryBounds(now: Date): { defaultDay: string; minDay: string; maxDay: string } {
  return {
    defaultDay: toDateInput(new Date(now.getTime() + defaultValidityDays * dayMs)),
    minDay: toDateInput(new Date(now.getTime() + dayMs)),
    maxDay: toDateInput(new Date(now.getTime() + maxValidityDays * dayMs)),
  }
}

/** Validates an input like the server; returns message keys by field. */
export function validateApiToken(input: ApiTokenInput, creator: string | null | undefined, now: Date): Partial<Record<keyof ApiTokenInput, string>> {
  const errors: Partial<Record<keyof ApiTokenInput, string>> = {}
  if (!namePattern.test(input.name)) errors.name = 'apiTokens.nameInvalid'
  if (!rolesFor(creator).includes(input.role)) errors.role = 'apiTokens.roleAboveCeiling'
  if (!/^\d{4}-\d{2}-\d{2}$/.test(input.expires)) {
    errors.expires = 'apiTokens.expiryTooSoon'
  } else {
    const at = expiresAt(input.expires, now).getTime()
    if (at < now.getTime() + hourMs) errors.expires = 'apiTokens.expiryTooSoon'
    else if (at > now.getTime() + maxValidityDays * dayMs) errors.expires = 'apiTokens.expiryTooLate'
  }
  return errors
}

/** Creates a token; returns the one-time answer or the problem code. */
export async function createApiToken(input: ApiTokenInput, now = new Date()): Promise<ApiTokenCreated | string> {
  const { data, error } = await api.POST('/api/v1/api-tokens', {
    params: { header: { 'X-Paddock-CSRF': '1' } },
    body: { name: input.name, role: input.role, expires_at: expiresAt(input.expires, now).toISOString() },
  })
  return data ?? problemCode(error)
}

/** Revokes a token; null on success, otherwise the problem code. */
export async function revokeApiToken(id: string): Promise<string | null> {
  const { error } = await api.POST('/api/v1/api-tokens/{id}/revoke', {
    params: { path: { id }, header: { 'X-Paddock-CSRF': '1' } },
  })
  return error ? problemCode(error) : null
}
